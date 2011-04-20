(* This module provides generic user authentication functionality, backed by
 * OpenID authentication.  Each account (named with a short alphanumeric string)
 * is associated with one or more OpenID identifiers, any of which may be used
 * to log in as that user.  This module provides all the code you need to sign
 * users up, log them in, and check which user is logged in.
 *
 * Module author: Adam Chlipala
 *)

datatype choose_result a = Success of a | Failure of string

(* Formatting options for the gui elements and controls. *)
signature CTLDISPLAY = sig

    val formatUser : xbody -> xbody
    (* Format the display of the logged on user *)
                              
    val formatLogout : url -> xbody
    (* Format the logout link *)

    val formatSignup : url -> xbody
    (* Format the signup link *)

    val formatLogon : ({User : string} -> transaction page) -> xbody
   (* Format the login form *)
end

(* Some reasonable default gui control formats for programmers in a hurry. *)
structure DefaultDisplay : CTLDISPLAY


(* Instantiate this functor to create your customized authentication scheme. *)
functor Make(M: sig
                 con cols :: {Type}
                 constraint [Id] ~ cols
                 val folder : folder cols
                 val inj : $(map sql_injectable cols)
                 (* Extra columns of profile information to include in the user
                  * database table *)

                 type creationState
                 (* The type of client-side state used while soliciting sign-up
                  * input *)
                 type creationData
                 (* A functional representation of the latest client-side state *)

                 val creationState : transaction creationState
                 (* Create some fresh client-side state. *)

                 val render : creationState -> xtable
                 (* Display widgets. *)

                 val ready : creationState -> signal bool
                 (* Is the data ready to send? *)

                 val tabulate : creationState -> signal creationData
                 (* Functionalize current state. *)

                 val choose : sql_table ([Id = string] ++ cols) [Pkey = [Id]]
                              -> creationData -> transaction (choose_result $cols)
                 (* Use functionalized state to choose initial column values,
                  * given a handle to the users table. *)

                 val sessionLifetime : int
                 (* Number of seconds a session may live *)

                 val afterLogout : url
                 (* Where to send the user after he logs out *)

                 val secureCookies : bool
                 (* Should authentication cookies be restricted to SSL
                  * connections? *)

                 val association : Openid.association_mode
                 (* OpenID cryptography preferences *)

                 val realm : option string
                 (* See end of [Openid] module's documentation for the meaning
                  * of realms. *)

                 val formClass : css_class
                 (* CSS class for <table>, <th>, and <td> elements used in
                  * sign-up form *)

                 val fakeId : option string
                 (* If set, this string is always accepted as a verified
                  * identifier, which can be useful during development (say,
                  * when you're off-network). *)

                 structure CtlDisplay : CTLDISPLAY
                 (* Tells how to format the GUI elements. *)
             end) : sig

    type user
    val eq_user : eq user
    val show_user : show user
    val read_user : read user
    val inj_user : sql_injectable_prim user
    (* The abstract type of user IDs.  It's really [string], but this is only
     * exposed via some standard type class instances. *)

    table user : ([Id = user] ++ M.cols)
      PRIMARY KEY Id

    val current : transaction (option user)
    (* Figure out which, if any, user is logged in on this connection. *)


    val main : (string -> xbody -> transaction page) -> transaction {Status : xbody,
                                                                     Other : {Url : url, Xml : xbody}}

    (* Pass in your generic page template; get out the HTML snippet for user
     * management, suitable for, e.g., inclusion in your standard page
     * header.  The output gives a "status" chunk, which will either be a login
     * form or a message about which user is logged in; and an "other" chunk,
     * which will be a log out or sign up link. *)
                             
end

(* Functor outputs will contain buttons specialized to particular well-known
 * OpenID providers.  Use these CSS classes to style those buttons. *)
style aol
style google
style myspace
style yahoo

(* This style is used by forms containing the above buttons. *)
style provider
