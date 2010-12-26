val discover : string -> transaction (option {Endpoint : string, LocalId : option string})

datatype association = Handle of string | Error of string
val association : string -> transaction association
