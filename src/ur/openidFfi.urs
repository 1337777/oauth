val init : transaction {}

type discovery
val discover : string -> transaction (option discovery)
val endpoint : discovery -> string
val localId : discovery -> option string

type inputs
val createInputs : transaction inputs
val addInput : inputs -> string -> string -> transaction {}

type outputs
val getOutput : outputs -> string -> option string

val direct : string -> inputs -> transaction outputs
val indirect : queryString -> transaction outputs

val sha1 : string -> string
val sha256 : string -> string

val hmac_sha1 : string -> string -> string
val hmac_sha256 : string -> string -> string

type dh
val modulus : dh -> string
val generator: dh -> string
val public : dh -> string

val generate : transaction dh
val compute : dh -> string -> transaction string
val xor : string -> string -> string

val remode : outputs -> string -> inputs
