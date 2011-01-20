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
                 val choose : sql_table ([Id = string] ++ cols) [Pkey = [Id]] -> creationData -> transaction $cols

                 val sessionLifetime : int
                 val afterLogout : url
                 val secureCookies : bool
                 val association : Openid.association_mode
                 val realm : option string
                 val formClass : css_class
                 val fakeId : option string
             end) = struct

    type user = string
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
                                        setCookie auth {Value = LoggedIn ({User = uid} ++ ses),
                                                        Expires = None,
                                                        Secure = M.secureCookies};

                                        cols <- M.choose user data;
                                        dml (insert user ({Id = (SQL {[uid]})} ++ @Sql.sqexps M.folder M.inj cols));
                                        dml (INSERT INTO identity (User, Identifier)
                                             VALUES ({[uid]}, {[ident]}));
                                        redirect (bless after)
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
                                                    Identifier = ident};
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
                                                Identifier = r.Identifier};
                    error <xml>Login with your identity provider failed: {[msg]}</xml>

            fun signup after =
                wrap "Account Signup" <xml>
                  <form>
                    OpenID Identifier: <textbox{#Identifier}/><br/>
                    <submit value="Sign Up" action={doSignup after}/>
                  </form>
                </xml>
        in
            cur <- current;
            here <- currentUrl;
            case cur of
                Some cur => return {Status = <xml>Logged in as {[cur]}.</xml>,
                                    Other = <xml><a link={logout ()}>Log out</a></xml>}
              | None => return {Status = <xml><form><textbox{#User}/> <submit value="Log In" action={logon (show here)}/></form></xml>,
                                Other = <xml><a link={signup (show here)}>Sign up</a></xml>}
        end

    task periodic 60 = fn () => dml (DELETE FROM session
                                     WHERE Expires < CURRENT_TIMESTAMP)

end
