datatype association_type = HMAC_SHA1 | HMAC_SHA256
datatype association_session_type = NoEncryption | DH_SHA1 | DH_SHA256

val authenticate : association_type -> association_session_type -> string -> transaction string
(* Doesn't return normally if everything goes as planned.
 * Instead, the user is redirected to his OP to authenticate there. *)
