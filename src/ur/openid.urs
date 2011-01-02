datatype association_type = HMAC_SHA1 | HMAC_SHA256
datatype association_session_type = NoEncryption | DH_SHA1 | DH_SHA256
datatype association_mode =
         Stateless
       | Stateful of {AssociationType : association_type,
                      AssociationSessionType : association_session_type}

datatype authentication = AuthenticatedAs of string | Canceled | Failure of string

val authenticate : (authentication -> transaction page)
                   -> {Association : association_mode,
                       Identifier : string}
                   -> transaction string
(* Doesn't return normally if everything goes as planned.
 * Instead, the user is redirected to his OP to authenticate there.
 * Later, the function passed as the first argument should be called with the result. *)
