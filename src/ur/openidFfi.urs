val init : transaction {}

type discovery
val discover : string -> transaction (option discovery)
val endpoint : discovery -> string
val localId : discovery -> option string
