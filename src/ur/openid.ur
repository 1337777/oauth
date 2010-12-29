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

datatype association_type = HMAC_SHA1 | HMAC_SHA256
datatype association_session_type = NoEncryption | DH_SHA1 | DH_SHA256

table associations : { Endpoint : string, Handle : string, Typ : serialized association_type, Key : string, Expires : time }
  PRIMARY KEY Endpoint

datatype association = Association of {Handle : string, Typ : association_type, Key : string}
                     | AssError of string
                     | AssAlternate of {Atype : association_type, Stype : association_session_type}

fun atype_show v =
    case v of
        HMAC_SHA1 => "HMAC-SHA1"
      | HMAC_SHA256 => "HMAC-SHA256"

val show_atype = mkShow atype_show

fun stype_show v =
    case v of
        NoEncryption => "no-encryption"
      | DH_SHA1 => "DH-SHA1"
      | DH_SHA256 => "DH-SHA256"

val show_stype = mkShow stype_show

fun atype_read s =
    case s of
        "HMAC-SHA1" => Some HMAC_SHA1
      | "HMAC-SHA256" => Some HMAC_SHA256
      | _ => None

val read_atype = mkRead' atype_read "association type"

fun stype_read s =
    case s of
        "no-encryption" => Some NoEncryption
      | "DH-SHA1" => Some DH_SHA1
      | "DH-SHA256" => Some DH_SHA256
      | _ => None

val read_stype = mkRead' stype_read "association session type"

fun atype_eq v1 v2 =
    case (v1, v2) of
        (HMAC_SHA1, HMAC_SHA1) => True
      | (HMAC_SHA256, HMAC_SHA256) => True
      | _ => False

val eq_atype = mkEq atype_eq

fun stype_eq v1 v2 =
    case (v1, v2) of
        (NoEncryption, NoEncryption) => True
      | (DH_SHA1, DH_SHA1) => True
      | (DH_SHA256, DH_SHA256) => True
      | _ => False

val eq_stype = mkEq stype_eq

fun errorResult atype stype os =
    case OpenidFfi.getOutput os "error" of
        Some v =>
        (case (OpenidFfi.getOutput os "error_code", OpenidFfi.getOutput os "assoc_type", OpenidFfi.getOutput os "session_type") of
             (Some "unsupported-type", at, st) => Some (AssAlternate {Atype = Option.get atype (Option.bind read at),
                                                                      Stype = Option.get stype (Option.bind read st)})
           | _ => Some (AssError ("OP error during association: " ^ v)))
      | None => None

fun associateNoEncryption url atype =
    is <- createInputs;
    OpenidFfi.addInput is "openid.mode" "associate";
    OpenidFfi.addInput is "openid.assoc_type" (show atype);
    OpenidFfi.addInput is "openid.session_type" (show NoEncryption);

    os <- OpenidFfi.direct url is;
    case errorResult atype NoEncryption os of
        Some v => return v
      | None =>
        case (OpenidFfi.getOutput os "assoc_handle", OpenidFfi.getOutput os "mac_key", OpenidFfi.getOutput os "expires_in") of
            (Some handle, Some key, Some expires) =>
            (case read expires of
                 None => return (AssError "Invalid 'expires_in' field")
               | Some expires =>
                 tm <- now;
                 dml (INSERT INTO associations (Endpoint, Handle, Typ, Key, Expires)
                      VALUES ({[url]}, {[handle]}, {[serialize atype]}, {[key]}, {[addSeconds tm expires]}));
                 return (Association {Handle = handle, Typ = atype, Key = key}))
          | (None, _, _) => return (AssError "Missing assoc_handle")
          | (_, None, _) => return (AssError "Missing mac_key")
          | _ => return (AssError "Missing expires_in")

fun associateDh url atype stype =
    dh <- OpenidFfi.generate;

    is <- createInputs;
    OpenidFfi.addInput is "openid.mode" "associate";
    OpenidFfi.addInput is "openid.assoc_type" (show atype);
    OpenidFfi.addInput is "openid.session_type" (show stype);
    OpenidFfi.addInput is "openid.dh_modulus" (OpenidFfi.modulus dh);
    OpenidFfi.addInput is "openid.dh_gen" (OpenidFfi.generator dh);
    OpenidFfi.addInput is "openid.dh_consumer_public" (OpenidFfi.public dh);

    os <- OpenidFfi.direct url is;
    case errorResult atype stype os of
        Some v => return v
      | None =>
        case (OpenidFfi.getOutput os "assoc_handle", OpenidFfi.getOutput os "dh_server_public",
              OpenidFfi.getOutput os "enc_mac_key", OpenidFfi.getOutput os "expires_in") of
                (Some handle, Some pub, Some mac, Some expires) =>
                (case read expires of
                     None => return (AssError "Invalid 'expires_in' field")
                   | Some expires =>
                     key <- OpenidFfi.compute dh pub;
                     tm <- now;
                     dml (INSERT INTO associations (Endpoint, Handle, Typ, Key, Expires)
                          VALUES ({[url]}, {[handle]}, {[serialize atype]}, {[key]}, {[addSeconds tm expires]}));
                     return (Association {Handle = handle, Typ = atype, Key = key}))
              | (None, _, _, _) => return (AssError "Missing assoc_handle")
              | (_, None, _, _) => return (AssError "Missing dh_server_public")
              | (_, _, None, _) => return (AssError "Missing enc_mac_key")
              | _ => return (AssError "Missing expires_in")

fun oldAssociation url =
    secret <- oneOrNoRows1 (SELECT associations.Handle, associations.Typ, associations.Key
                            FROM associations
                            WHERE associations.Endpoint = {[url]});
    case secret of
        Some r => return (Some (r -- #Typ ++ {Typ = deserialize r.Typ}))
      | None => return None

fun newAssociation url atype stype =
    case stype of
        NoEncryption => associateNoEncryption url atype
      | _ => associateDh url atype stype

fun association atype stype url =
    secret <- oldAssociation url;
    case secret of
        Some r => return (Association r)
      | None =>
        stype <- return (case (stype, String.isPrefix {Full = url, Prefix = "https://"}) of
                             (NoEncryption, False) => DH_SHA256
                           | _ => stype);
        r <- newAssociation url atype stype;
        case r of
            AssAlternate alt =>
            if alt.Atype = atype && alt.Stype = stype then
                return (AssError "Suggested new modes match old ones!")
            else
                newAssociation url alt.Atype alt.Stype
          | v => return v

fun eatFragment s =
    case String.split s #"#" of
        Some (_, s') => s'
      | _ => s

datatype handle_result = HandleOk of {Endpoint : string, Typ : association_type, Key : string} | HandleError of string

fun verifyHandle os id =
    ep <- discover (eatFragment id);
    case ep of
        None => return (HandleError "Discovery failed on returned endpoint")
      | Some ep =>
        case OpenidFfi.getOutput os "openid.assoc_handle" of
            None => return (HandleError "Missing association handle in response")
          | Some handle =>
            assoc <- oldAssociation ep;
            case assoc of
                None => return (HandleError "Couldn't find association handle")
              | Some assoc =>
                if assoc.Handle <> handle then
                    return (HandleError "Association handles don't match")
                else
                    return (HandleOk {Endpoint = ep, Typ = assoc.Typ, Key = assoc.Key})

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

fun verifySig os atype key =
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
                        val sign' = case atype of
                                        HMAC_SHA256 => OpenidFfi.sha256 key nvps
                                      | HMAC_SHA1 => OpenidFfi.sha1 key nvps
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
                           | HandleOk {Endpoint = ep, Typ = atype, Key = key} =>
                             errO <- verifyReturnTo os;
                             case errO of
                                 Some s => error <xml>{[s]}</xml>
                               | None =>
                                 errO <- verifyNonce os ep;
                                 case errO of
                                     Some s => error <xml>{[s]}</xml>
                                   | None =>
                                     errO <- verifySig os atype key;
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

fun authenticate atype stype id =
    dy <- discover id;
    case dy of
        None => return "Discovery failed"
      | Some dy =>
        assoc <- association atype stype dy;
        case assoc of
            AssError msg => return ("Association failure: " ^ msg)
          | AssAlternate _ => return "Association failure: server didn't accept its own alternate association modes"
          | Association assoc =>
            redirect (bless (dy ^ "?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id="
                             ^ id ^ "&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.assoc_handle="
                             ^ assoc.Handle ^ "&openid.return_to=" ^ show (effectfulUrl returnTo)))

task periodic 1 = fn () =>
                     dml (DELETE FROM discoveries WHERE Expires < CURRENT_TIMESTAMP);
                     dml (DELETE FROM associations WHERE Expires < CURRENT_TIMESTAMP);
                     dml (DELETE FROM nonces WHERE Expires < CURRENT_TIMESTAMP)
