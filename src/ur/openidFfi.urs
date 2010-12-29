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

val sha256 : string -> string -> string
