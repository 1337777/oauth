task initialize = fn () => OpenidFfi.init

fun discover s =
    r <- OpenidFfi.discover s;
    return (Option.mp (fn r => {Endpoint = OpenidFfi.endpoint r,
                                LocalId = OpenidFfi.localId r}) r)
