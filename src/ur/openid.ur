task initialize = fn () => OpenidFfi.init

fun discover s =
    r <- OpenidFfi.discover s;
    return (Option.mp (fn r => {Endpoint = OpenidFfi.endpoint r,
                                LocalId = OpenidFfi.localId r}) r)

val createInputs =
    is <- OpenidFfi.createInputs;
    OpenidFfi.addInput is "openid.ns" "http://specs.openid.net/auth/2.0";
    return is

table associations : { Endpoint : string, Handle : string, Key : string, Expires : time }
  PRIMARY KEY Endpoint

task periodic 1 = fn () => dml (DELETE FROM associations WHERE Expires < CURRENT_TIMESTAMP)

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
              | _ => return (AssError "Missing fields in response from OP")

fun returnTo (qs : option queryString) =
    case qs of
        None => error <xml>Empty query string for OpenID callback</xml>
      | Some qs =>
        os <- OpenidFfi.indirect qs;
        case OpenidFfi.getOutput os "openid.error" of
            Some v => error <xml>Authentication failed: {[v]}</xml>
          | None =>
            case OpenidFfi.getOutput os "openid.mode" of
                None => error <xml>No <tt>openid.mode</tt> in response</xml>
              | Some mode =>
                case mode of
                    "cancel" => error <xml>You canceled the authentication!</xml>
                  | "id_res" =>
                    (case OpenidFfi.getOutput os "openid.identity" of
                         None => error <xml>Missing identity in OP response</xml>
                       | Some v => return <xml>Identity: {[v]}</xml>)
                  | _ => error <xml>Unexpected <tt>openid.mode</tt>: <tt>{[mode]}</tt></xml>

fun authenticate id =
    dy <- discover id;
    case dy of
        None => return "Discovery failed"
      | Some dy =>
        assoc <- association dy.Endpoint;
        case assoc of
            AssError msg => return msg
          | Association assoc =>
            redirect (bless (dy.Endpoint ^ "?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id="
                             ^ id ^ "&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.assoc_handle="
                             ^ assoc.Handle ^ "&openid.return_to=" ^ show (effectfulUrl returnTo)))
