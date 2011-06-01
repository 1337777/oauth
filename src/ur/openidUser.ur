style provider

style aol
style google
style myspace
style yahoo

datatype choose_result a = Success of a | Failure of string

signature CTLDISPLAY = sig
    val formatUser : xbody -> xbody
    val formatLogout : url -> xbody
    val formatSignup : url -> xbody
    val formatLogon : ({User : string} -> transaction page) -> xbody
end

structure DefaultDisplay : CTLDISPLAY = struct
    fun formatUser user =
        <xml>You are logged in as {user}.</xml>

    fun formatLogout url =
        <xml><a href={url}>Log Out</a></xml>

    fun formatSignup url =
        <xml><a href={url}>Sign Up</a></xml>

    fun formatLogon handler =
        <xml>
          <form><textbox{#User}/><submit value="Log In" action={handler}/></form>
        </xml>
end


functor Make(M: sig
                 con cols :: {Type}
                 constraint [Id] ~ cols
                 val folder : folder cols
                 val inj : $(map sql_injectable cols)

                 type creationState
                 type creationData
                 val creationState : transaction creationState
                 val render : creationState -> xtable
                 val ready : creationState -> signal bool
                 val tabulate : creationState -> signal creationData
                 val choose : sql_table ([Id = string] ++ cols) [Pkey = [Id]] -> creationData -> transaction (choose_result $cols)

                 val sessionLifetime : int
                 val afterLogout : url
                 val secureCookies : bool
                 val association : Openid.association_mode
                 val realm : option string
                 val formClass : css_class
                 val fakeId : option string

                 structure CtlDisplay : CTLDISPLAY
             end) = struct

    type user = string
    val eq_user = _
    val read_user = _
    val show_user = _
    val inj_user = _

    table user : ([Id = user] ++ M.cols)
      PRIMARY KEY Id

    table identity : {User : user, Identifier : string}
      PRIMARY KEY (User, Identifier)

    sequence sessionIds

    table session : {Id : int, Key : int, Identifier : option string, Expires : time}
      PRIMARY KEY Id

    datatype authMode =
             SigningUp of {Session : int, Key : int}
           | LoggedIn of {User : user, Session : int, Key : int}

    cookie auth : authMode

    val currentUrl =
        b <- currentUrlHasPost;
        if b then
            return M.afterLogout
        else
            currentUrl

    val current =
        login <- getCookie auth;
        case login of
            Some (LoggedIn login) =>
            (ident <- oneOrNoRowsE1 (SELECT (session.Identifier)
                                     FROM session
                                     WHERE session.Id = {[login.Session]}
                                       AND session.Key = {[login.Key]});
             case ident of
                 None => return None
               | Some None => return None
               | Some (Some ident) =>
                 valid <- oneRowE1 (SELECT COUNT( * ) > 0
                                    FROM identity
                                    WHERE identity.User = {[login.User]}
                                      AND identity.Identifier = {[ident]});
                 if valid then
                     return (Some login.User)
                 else
                     error <xml>Session not authorized to act as user</xml>)
          | _ => return None

    fun validUser s = String.length s > 0 && String.length s < 20
                      && String.all Char.isAlnum s

    fun main wrap =
        let
            fun logout () =
                clearCookie auth;
                redirect M.afterLogout

            fun signupDetails after =
                let
                    fun finishSignup uid data =
                        if not (validUser uid) then
                            return (Some "That username is not valid.  It must be between 1 and 19 characters long, containing only letters and numbers.")
                        else
                            used <- oneRowE1 (SELECT COUNT( * ) > 0
                                              FROM user
                                              WHERE user.Id = {[uid]});
                            if used then
                                return (Some "That username is taken.  Please choose another.")
                            else
                                ses <- getCookie auth;
                                case ses of
                                    None => return (Some "Missing session cookie")
                                  | Some (LoggedIn _) => return (Some "Session cookie is for already logged-in user")
                                  | Some (SigningUp ses) =>
                                    ident <- oneOrNoRowsE1 (SELECT (session.Identifier)
                                                            FROM session
                                                            WHERE session.Id = {[ses.Session]}
                                                              AND session.Key = {[ses.Key]});
                                    case ident of
                                        None => return (Some "Invalid session data")
                                      | Some None => return (Some "Session has no associated identifier")
                                      | Some (Some ident) =>
                                        cols <- M.choose user data;
                                        case cols of
                                            Failure s => return (Some s)
                                          | Success cols =>
                                            setCookie auth {Value = LoggedIn ({User = uid} ++ ses),
                                                            Expires = None,
                                                            Secure = M.secureCookies};

                                            dml (insert user ({Id = (SQL {[uid]})} ++ @Sql.sqexps M.folder M.inj cols));
                                            dml (INSERT INTO identity (User, Identifier)
                                                 VALUES ({[uid]}, {[ident]}));
                                            return None
                in
                    uid <- source "";
                    cs <- M.creationState;

                    wrap "Your User Details" <xml>
                      <table class={M.formClass}>
                        <tr> <th class={M.formClass}>Username:</th> <td><ctextbox source={uid}/></td> </tr>
                        {M.render cs}
                        <tr> <td><dyn signal={b <- M.ready cs;
                                              return (if b then
                                                          <xml><button value="Create Account"
                                                                       onclick={uid <- get uid;
                                                                                data <- Basis.current (M.tabulate cs);
                                                                                res <- rpc (finishSignup uid data);
                                                                                case res of
                                                                                    None => redirect (bless after)
                                                                                  | Some msg => alert msg}/></xml>
                                                      else
                                                          <xml/>)}/></td> </tr>
                      </table>
                    </xml>
                end

            fun opCallback after ses res =
                case res of
                    Openid.Canceled => error <xml>You canceled the login process.</xml>
                  | Openid.Failure s => error <xml>Login failed: {[s]}</xml>
                  | Openid.AuthenticatedAs ident =>
                    av <- getCookie auth;
                    case av of
                        Some (SigningUp signup) =>
                        if signup.Session <> ses then
                            error <xml>Session has changed suspiciously</xml>
                        else
                            invalid <- oneRowE1 (SELECT COUNT( * ) = 0
                                                 FROM session
                                                 WHERE session.Id = {[signup.Session]}
                                                   AND session.Key = {[signup.Key]});
                            if invalid then
                                error <xml>Invalid or expired session</xml>
                            else
                                dml (UPDATE session
                                     SET Identifier = {[Some ident]}
                                     WHERE Id = {[signup.Session]});
                                signupDetails after
                      | Some (LoggedIn login) =>
                        if login.Session <> ses then
                            error <xml>Session has changed suspiciously</xml>
                        else
                            invalid <- oneRowE1 (SELECT COUNT( * ) = 0
                                                 FROM session
                                                 WHERE session.Id = {[login.Session]}
                                                   AND session.Key = {[login.Key]});
                            if invalid then
                                error <xml>Invalid or expired session</xml>
                            else
                                dml (UPDATE session
                                     SET Identifier = {[Some ident]}
                                     WHERE Id = {[login.Session]});
                                redirect (bless after)
                      | None => error <xml>Missing session cookie</xml>

            fun fakeCallback ident after ses =
                av <- getCookie auth;
                case av of
                    Some (SigningUp signup) =>
                    invalid <- oneRowE1 (SELECT COUNT( * ) = 0
                                         FROM session
                                         WHERE session.Id = {[signup.Session]}
                                           AND session.Key = {[signup.Key]});
                    if invalid then
                        error <xml>Invalid or expired session</xml>
                    else
                        dml (UPDATE session
                             SET Identifier = {[Some ident]}
                             WHERE Id = {[signup.Session]});
                        signupDetails after
                  | Some (LoggedIn login) =>
                    invalid <- oneRowE1 (SELECT COUNT( * ) = 0
                                         FROM session
                                         WHERE session.Id = {[login.Session]}
                                           AND session.Key = {[login.Key]});
                    if invalid then
                        error <xml>Invalid or expired session</xml>
                    else
                        dml (UPDATE session
                             SET Identifier = {[Some ident]}
                             WHERE Id = {[login.Session]});
                        redirect (bless after)
                  | None => error <xml>Missing session cookie</xml>

            fun newSession () =
                ses <- nextval sessionIds;
                now <- now;
                key <- rand;
                dml (INSERT INTO session (Id, Key, Identifier, Expires)
                     VALUES ({[ses]}, {[key]}, NULL, {[addSeconds now M.sessionLifetime]}));
                return {Session = ses, Key = key}

            fun logon after r =
                ident <- oneOrNoRowsE1 (SELECT (identity.Identifier)
                                        FROM identity
                                        WHERE identity.User = {[r.User]}
                                        LIMIT 1);
                case ident of
                    None => error <xml>Username not found</xml>
                  | Some ident =>
                    ses <- newSession ();
                    setCookie auth {Value = LoggedIn (r ++ ses),
                                    Expires = None,
                                    Secure = M.secureCookies};
                    ses <- return ses.Session;
                    if M.fakeId = Some ident then
                        fakeCallback ident after ses
                    else
                        msg <- Openid.authenticate (opCallback after ses)
                                                   {Association = M.association,
                                                    Realm = M.realm,
                                                    Identifier = Openid.KnownIdentifier ident};
                        error <xml>Login with your identity provider failed: {[msg]}</xml>

            fun doSignup after r =
                ses <- newSession ();
                setCookie auth {Value = SigningUp ses,
                                Expires = None,
                                Secure = M.secureCookies};
                ses <- return ses.Session;
                if M.fakeId = Some r.Identifier then
                    fakeCallback r.Identifier after ses
                else
                    msg <- Openid.authenticate (opCallback after ses)
                                               {Association = M.association,
                                                Realm = M.realm,
                                                Identifier = Openid.ChooseIdentifier r.Identifier};
                    error <xml>Login with your identity provider failed: {[msg]}</xml>

            fun signup after =
                let
                    fun fixed cls url =
                        let
                            fun doFixedButton () =
                                doSignup after {Identifier = url}
                        in
                            <xml><form class={provider}>
                              <submit class={cls} value="" action={doFixedButton}/>
                            </form></xml>
                        end
                in
                    wrap "Account Signup" <xml>
                      <p>This web site uses the <b><a href="http://openid.net/">OpenID</a></b> standard, which lets you log in using your account from one of several popular web sites, without revealing your password to us.</p>

                      <p>You may click one of these buttons to choose to use your account from that site:</p>
                      {fixed aol "https://openid.aol.com/"}
                      {fixed google "https://www.google.com/accounts/o8/id"}
                      {fixed myspace "https://www.myspace.com/openid"}
                      {fixed yahoo "https://me.yahoo.com/"}

                      <p>Visitors familiar with the details of OpenID may also enter their own identifiers:</p>
                      <form>
                        OpenID Identifier: <textbox{#Identifier}/><br/>
                        <submit value="Sign Up" action={doSignup after}/>
                      </form>
                    </xml>
                end
        in
            cur <- current;
            here <- currentUrl;

            case cur of
                Some cur => return {Status = (M.CtlDisplay.formatUser <xml>{[cur]}</xml>),
                                    Other = {Url = (url (logout ())), 
                                             Xml = (M.CtlDisplay.formatLogout (url (logout ())))}}
              | None => return {Status = (M.CtlDisplay.formatLogon (logon (show here))),
                                Other = {Url = (url (signup (show here))),
                                         Xml = (M.CtlDisplay.formatSignup (url (signup (show here))))}}
        end

    task periodic 60 = fn () => dml (DELETE FROM session
                                     WHERE Expires < CURRENT_TIMESTAMP)

end
