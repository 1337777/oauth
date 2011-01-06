functor Make(M: sig
                 con cols :: {Type}
                 constraint [Id] ~ cols

                 val sessionLifetime : int
                 val afterLogout : url
                 val secureCookies : bool
                 val association : Openid.association_mode
                 val realm : option string
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

    cookie signingUp : {Session : int, Key : int}
    cookie login : {User : user, Session : int, Key : int}

    val current =
        login <- getCookie login;
        case login of
            None => return None
          | Some login =>
            ident <- oneOrNoRowsE1 (SELECT (session.Identifier)
                                    FROM session
                                    WHERE session.Id = {[login.Session]}
                                      AND session.Key = {[login.Key]});
            case ident of
                None => error <xml>Invalid or expired session</xml>
              | Some None => return None
              | Some (Some ident) =>
                valid <- oneRowE1 (SELECT COUNT( * ) > 0
                                   FROM identity
                                   WHERE identity.User = {[login.User]}
                                     AND identity.Identifier = {[ident]});
                if valid then
                    return (Some login.User)
                else
                    error <xml>Session not authorized to act as user</xml>

    fun main wrap =
        let
            fun logout () =
                clearCookie login;
                redirect M.afterLogout

            fun opCallback after ses res =
                case res of
                    Openid.Canceled => error <xml>You canceled the login process.</xml>
                  | Openid.Failure s => error <xml>Login failed: {[s]}</xml>
                  | Openid.AuthenticatedAs ident =>
                    signup <- getCookie signingUp;
                    case signup of
                        Some signup =>
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
                                return <xml>I now believe that you are {[ident]}.</xml>
                      | None =>
                        login <- getCookie login;
                        case login of
                            None => error <xml>Missing session cookie</xml>
                          | Some login =>
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
                                         WHERE Key = {[login.Key]});
                                    redirect (bless after)

            fun newSession () =
                ses <- nextval sessionIds;
                now <- now;
                key <- rand;
                dml (INSERT INTO session (Id, Key, Identifier, Expires)
                     VALUES ({[ses]}, {[key]}, NULL, {[addSeconds now M.sessionLifetime]}));
                return {Session = ses, Key = key}

            fun logon r =
                ident <- oneOrNoRowsE1 (SELECT (identity.Identifier)
                                        FROM identity
                                        WHERE identity.User = {[r.User]}
                                        LIMIT 1);
                case ident of
                    None => error <xml>Username not found</xml>
                  | Some ident =>
                    ses <- newSession ();
                    setCookie login {Value = r ++ ses,
                                     Expires = None,
                                     Secure = M.secureCookies};
                    after <- currentUrl;
                    after <- return (show after);
                    ses <- return ses.Session;
                    msg <- Openid.authenticate (opCallback after ses)
                           {Association = M.association,
                            Realm = M.realm,
                            Identifier = ident};
                    error <xml>Login with your identity provider failed: {[msg]}</xml>

            fun doSignup after r =
                ses <- newSession ();
                setCookie signingUp {Value = ses,
                                     Expires = None,
                                     Secure = M.secureCookies};
                ses <- return ses.Session;
                msg <- Openid.authenticate (opCallback after ses)
                                           {Association = M.association,
                                            Realm = M.realm,
                                            Identifier = r.Identifier};
                error <xml>Login with your identity provider failed: {[msg]}</xml>

            fun signup () =
                after <- currentUrl;
                wrap "Account Signup" <xml>
                  <form>
                    OpenID Identifier: <textbox{#Identifier}/><br/>
                    <submit value="Sign Up" action={doSignup (show after)}/>
                  </form>
                </xml>
        in
            cur <- current;
            case cur of
                Some cur => return <xml>Logged in as {[cur]}. <a link={logout ()}>[Log out]</a></xml>
              | None => return <xml>
                <form><textbox{#User}/> <submit value="Log In" action={logon}/></form>
                <a link={signup ()}>Sign up</a>
              </xml>
        end

    task periodic 60 = fn () => dml (DELETE FROM session
                                     WHERE Expires >= CURRENT_TIMESTAMP)

end
