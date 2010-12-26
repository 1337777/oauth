task initialize = fn () => OpenidFfi.init

fun discover s =
    r <- OpenidFfi.discover s;
    return (Option.mp (fn r => {Endpoint = OpenidFfi.endpoint r,
                                LocalId = OpenidFfi.localId r}) r)

val createInputs =
    is <- OpenidFfi.createInputs;
    OpenidFfi.addInput is "openid.ns" "http://specs.openid.net/auth/2.0";
    return is

table associations : { Endpoint : string, Secret : string, Expires : time }
  PRIMARY KEY Endpoint

task periodic 0 = fn () => dml (DELETE FROM associations WHERE Expires < CURRENT_TIMESTAMP)

datatype association = Handle of string | Error of string

fun association url =
    secret <- oneOrNoRowsE1 (SELECT (associations.Secret)
                             FROM associations
                             WHERE associations.Endpoint = {[url]});
    case secret of
        Some v => return (Handle v)
      | None =>
        is <- createInputs;
        OpenidFfi.addInput is "openid.mode" "associate";
        OpenidFfi.addInput is "openid.assoc_type" "HMAC-SHA256";
        OpenidFfi.addInput is "openid.session_type" "no-encryption";
        os <- OpenidFfi.indirect url is;
        case OpenidFfi.getOutput os "error" of
            Some v => return (Error v)
          | None =>
            case (OpenidFfi.getOutput os "assoc_handle", OpenidFfi.getOutput os "expires_in") of
                (Some handle, Some expires) =>
                (case read expires of
                     None => return (Error "Invalid 'expires_in' field")
                   | Some expires =>
                     tm <- now;
                     dml (INSERT INTO associations (Endpoint, Secret, Expires)
                          VALUES ({[url]}, {[handle]}, {[addSeconds tm expires]}));
                     return (Handle handle))
              | _ => return (Error "Missing fields in response from OP")
