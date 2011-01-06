functor Make(M: sig
                 con cols :: {Type}
                 constraint [Id] ~ cols
                 val folder : folder cols
                 val inj : $(map sql_injectable cols)
                 (* Extra columns to add to the user database table *)

                 type creationState
                 type creationData
                 val creationState : transaction creationState
                 val render : creationState -> xtable
                 val tabulate : creationState -> signal creationData
                 val choose : sql_table ([Id = string] ++ cols) [Pkey = [Id]] -> creationData -> transaction $cols

                 val sessionLifetime : int
                 (* Number of seconds a session may live *)

                 val afterLogout : url
                 (* Where to send the user after he logs out *)

                 val secureCookies : bool
                 (* Should authentication cookies be restricted to SSL connections? *)

                 val association : Openid.association_mode
                 (* OpenID cryptography preferences *)

                 val realm : option string
                 (* See end of [Openid] module's documentation for the meaning of realms *)

                 val formClass : css_class
             end) : sig

    type user
    val show_user : show user
    val inj_user : sql_injectable_prim user

    table user : ([Id = user] ++ M.cols)
      PRIMARY KEY Id

    val current : transaction (option user)

    val main : (string -> xbody -> transaction page) -> transaction xbody
    (* Pass in your generic page template; get out the HTML snippet for user management *)

end
