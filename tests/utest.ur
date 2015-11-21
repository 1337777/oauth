style inputs

structure U = OpenidUser.Make(struct
                                  con cols = [Nam = string]

                                  val sessionLifetime = 3600
                                  val afterLogout = bless "/main"
                                  val secureCookies = False
                                  val association = Openid.Stateful {AssociationType = Openid.HMAC_SHA256,
                                                                     AssociationSessionType = Openid.NoEncryption}
                                  val realm = Some "http://localhost:8080/"

                                  val creationState =
                                      n <- source "";
                                      return {Nam = n}
                                      
                                  fun render r = <xml>
                                    <tr> <th class={inputs}>Name:</th> <td><ctextbox source={r.Nam}/></td> </tr>
                                  </xml>

                                  fun ready _ = return True

                                  fun tabulate r =
                                      n <- signal r.Nam;
                                      return {Nam = n}

                                  fun choose _ r = return (OpenidUser.Success r)

                                  val formClass = inputs

                                  val fakeId = Some "localh#melocal" (*None*)

                                  structure CtlDisplay = OpenidUser.DefaultDisplay
                              end)

fun wrap titl bod =
    userStuff <- U.main wrap;
    return <xml><head>
      <title>{[titl]}</title>
    </head><body>
      {userStuff.Status}<br/>
      {userStuff.Other.Xml}

      <h1>{[titl]}</h1>

      {bod}
    </body></xml>

fun main () =
    whoami <- U.current;
    wrap "Main page" (case whoami of
                          None => <xml>I don't think you're logged in.</xml>
                        | Some whoami => <xml>Apparently you are <b>{[whoami]}</b>!</xml>)

structure OAuthInst = Openid.OAuth (struct
					val endpointAuth = "https://github.com/login/oauth/authorize"
					val endpointToken = "https://github.com/login/oauth/access_token"
					val clientId = "eff6bdf9d28da17b0f2c"
					val clientSecret = "7700323c365d3c5b12096cddb94deb28f0d9a937"
					val sessionLifetime = 3600
				    end)

fun index () =
    let
	fun after id key =
	    user <- OAuthInst.directApi id key "https://api.github.com/user";
	    return <xml><body> YOYO ses.Id {[id]}, GOGO ses.Key {[key]} <br/>
	      USER INFO: {case user of
			      Some s => txt s
			    | None => txt "[ERROR]"}
		</body></xml>

	fun opCallback after res =
            case res of
                OAuthInst.CanceledAuth => error <xml>You canceled the login process.</xml>
              | OAuthInst.FailureAuth s => error <xml>Login failed: {[s]}</xml>
              | OAuthInst.AuthorizedAs ses => redirect (url (after ses.Id ses.Key))

	fun authorize () =
	    msg <- OAuthInst.authorize (opCallback after)
				       {Scope = "user"};
            error <xml>Login with your identity provider failed: {[msg]}</xml>
    in
	return <xml><body>
          <form><submit value="Authorize" action={authorize}/></form></body>
        </xml>
    end
