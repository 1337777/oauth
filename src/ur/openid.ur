val discoveryExpiry = 3600
val nonceExpiry = 3600

task initialize = fn () => OpenidFfi.init

table discoveries : { Identifier : string, Endpoint : string, Expires : time }
  PRIMARY KEY Identifier

fun discover s =
    endpoint <- oneOrNoRowsE1 (SELECT (discoveries.Endpoint)
                               FROM discoveries
                               WHERE discoveries.Identifier = {[s]});
    case endpoint of
        Some ep => return (Some ep)
      | None =>
        r <- OpenidFfi.discover s;
        case r of
            None => return None
          | Some r =>
            tm <- now;
            dml (INSERT INTO discoveries (Identifier, Endpoint, Expires)
                 VALUES ({[s]}, {[OpenidFfi.endpoint r]}, {[addSeconds tm discoveryExpiry]}));
            return (Some (OpenidFfi.endpoint r))

val createInputs =
    is <- OpenidFfi.createInputs;
    OpenidFfi.addInput is "openid.ns" "http://specs.openid.net/auth/2.0";
    return is

table associations : { Endpoint : string, Handle : string, Key : string, Expires : time }
  PRIMARY KEY Endpoint

datatype association = Association of {Handle : string, Key : string} | AssError of string

fun association url =
    secret <- oneOrNoRows1 (SELECT associations.Handle, associations.Key
                            FROM associations
                            WHERE associations.Endpoint = {[url]});
    case secret of
        Some r => return (Association r)
      | None =>
        is <- createInputs;
        OpenidFfi.addInput is "openid.mode" "associate";
        OpenidFfi.addInput is "openid.assoc_type" "HMAC-SHA256";
        OpenidFfi.addInput is "openid.session_type" "no-encryption";

        debug ("Contacting " ^ url);

        os <- OpenidFfi.direct url is;
        case OpenidFfi.getOutput os "error" of
            Some v => return (AssError v)
          | None =>
            case (OpenidFfi.getOutput os "assoc_handle", OpenidFfi.getOutput os "mac_key", OpenidFfi.getOutput os "expires_in") of
                (Some handle, Some key, Some expires) =>
                (case read expires of
                     None => return (AssError "Invalid 'expires_in' field")
                   | Some expires =>
                     tm <- now;
                     dml (INSERT INTO associations (Endpoint, Handle, Key, Expires)
                          VALUES ({[url]}, {[handle]}, {[key]}, {[addSeconds tm expires]}));
                     return (Association {Handle = handle, Key = key}))
              | (None, _, _) => return (AssError "Missing assoc_handle")
              | (_, None, _) => return (AssError "Missing mac_key")
              | _ => return (AssError "Missing fields in response from OP")

fun eatFragment s =
    case String.split s #"#" of
        Some (_, s') => s'
      | _ => s

datatype handle_result = HandleOk of {Endpoint : string, Key : string} | HandleError of string

fun verifyHandle os id =
    ep <- discover (eatFragment id);
    case ep of
        None => return (HandleError "Discovery failed on returned endpoint")
      | Some ep =>
        case OpenidFfi.getOutput os "openid.assoc_handle" of
            None => return (HandleError "Missing association handle in response")
          | Some handle =>
            assoc <- association ep;
            case assoc of
                AssError s => return (HandleError s)
              | Association assoc =>
                if assoc.Handle <> handle then
                    return (HandleError "Association handles don't match")
                else
                    return (HandleOk {Endpoint = ep, Key = assoc.Key})

table nonces : { Endpoint : string, Nonce : string, Expires : time }
  PRIMARY KEY (Endpoint, Nonce)

fun timeOfNonce s =
    case String.split s #"T" of
        None => None
      | Some (date, s) =>
        case String.split s #"Z" of
            None => None
          | Some (time, _) => readUtc (date ^ " " ^ time)

fun verifyNonce os ep =
    case OpenidFfi.getOutput os "openid.response_nonce" of
        None => return (Some "Missing nonce in OP response")
      | Some nonce =>
        case timeOfNonce nonce of
            None => return (Some "Invalid timestamp in nonce")
          | Some tm =>
            now <- now;
            exp <- return (addSeconds now nonceExpiry);
            if tm < exp then
                return (Some "Nonce timestamp is too old")
            else
                b <- oneRowE1 (SELECT COUNT( * ) > 0
                               FROM nonces
                               WHERE nonces.Endpoint = {[ep]}
                                 AND nonces.Nonce = {[nonce]});

                if b then
                    return (Some "Duplicate nonce")
                else
                    debug ("Nonce expires: " ^ show exp);
                    dml (INSERT INTO nonces (Endpoint, Nonce, Expires)
                         VALUES ({[ep]}, {[nonce]}, {[exp]}));
                    return None

fun verifySig os key =
    case OpenidFfi.getOutput os "openid.signed" of
        None => return (Some "Missing openid.signed in OP response")
      | Some signed =>
        case OpenidFfi.getOutput os "openid.sig" of
            None => return (Some "Missing openid.sig in OP response")
          | Some sign => let
                fun gatherNvps signed acc =
                    let
                        val (this, next) =
                            case String.split signed #"," of
                                None => (signed, None)
                              | Some (this, next) => (this, Some next)
                    in
                        case OpenidFfi.getOutput os ("openid." ^ this) of
                            None => None
                          | Some value =>
                            let
                                val acc = acc ^ this ^ ":" ^ value ^ "\n"
                            in
                                case next of
                                    None => Some acc
                                  | Some next => gatherNvps next acc
                            end
                    end
            in    
                case gatherNvps signed "" of
                    None => return (Some "openid.signed mentions missing field")
                  | Some nvps =>
                    let
                        val sign' = OpenidFfi.sha256 key nvps
                    in
                        debug ("Fields: " ^ signed);
                        debug ("Nvps: " ^ nvps);
                        debug ("Key: " ^ key);
                        debug ("His: " ^ sign);
                        debug ("Mine: " ^ sign');
                        if sign' = sign then
                            return None
                        else
                            return (Some "Signatures don't match")
                    end
            end

fun returnTo (qs : option queryString) =
    case qs of
        None => error <xml>Empty query string for OpenID callback</xml>
      | Some qs =>
        os <- OpenidFfi.indirect qs;
        case OpenidFfi.getOutput os "openid.error" of
            Some v => error <xml>Authentication failed: {[v]}</xml>
          | None =>
            case OpenidFfi.getOutput os "openid.mode" of
                None => error <xml>No <tt>openid.mode</tt> in response ({[qs]})</xml>
              | Some mode =>
                case mode of
                    "cancel" => error <xml>You canceled the authentication!</xml>
                  | "id_res" =>
                    (case OpenidFfi.getOutput os "openid.identity" of
                         None => error <xml>Missing identity in OP response</xml>
                       | Some id =>
                         errO <- verifyHandle os id;
                         case errO of
                             HandleError s => error <xml>{[s]}</xml>
                           | HandleOk {Endpoint = ep, Key = key} =>
                             errO <- verifyReturnTo os;
                             case errO of
                                 Some s => error <xml>{[s]}</xml>
                               | None =>
                                 errO <- verifyNonce os ep;
                                 case errO of
                                     Some s => error <xml>{[s]}</xml>
                                   | None =>
                                     errO <- verifySig os key;
                                     case errO of
                                         Some s => error <xml>{[s]}</xml>
                                       | None => return <xml>Identity: {[id]}</xml>)
                  | _ => error <xml>Unexpected <tt>openid.mode</tt>: <tt>{[mode]}</tt></xml>

and verifyReturnTo os =
    case OpenidFfi.getOutput os "openid.return_to" of
        None => return (Some "Missing return_to in OP response")
      | Some rt =>
        if rt <> show (effectfulUrl returnTo) then
            return (Some "Wrong return_to in OP response")
        else
            return None

fun authenticate id =
    dy <- discover id;
    case dy of
        None => return "Discovery failed"
      | Some dy =>
        assoc <- association dy;
        case assoc of
            AssError msg => return msg
          | Association assoc =>
            redirect (bless (dy ^ "?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id="
                             ^ id ^ "&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.assoc_handle="
                             ^ assoc.Handle ^ "&openid.return_to=" ^ show (effectfulUrl returnTo)))

task periodic 1 = fn () =>
                     dml (DELETE FROM discoveries WHERE Expires < CURRENT_TIMESTAMP);
                     dml (DELETE FROM associations WHERE Expires < CURRENT_TIMESTAMP);
                     dml (DELETE FROM nonces WHERE Expires < CURRENT_TIMESTAMP)
