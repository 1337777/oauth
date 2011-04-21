style inputs

structure U = OpenidUser.Make(struct
                                  con cols = [Nam = string]

                                  val sessionLifetime = 3600
                                  val afterLogout = bless "/main"
                                  val secureCookies = False
                                  val association = Openid.Stateful {AssociationType = Openid.HMAC_SHA256,
                                                                     AssociationSessionType = Openid.NoEncryption}
                                  val realm = None

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

                                  val fakeId = None

                                  val ctlDisplay = {User = {Status = <xml>Status</xml>, Logout = <xml>Log Out</xml>},
                                                    Guest = {Status = <xml>Status</xml>, Signup = <xml>Sign Up</xml>}}
                              end)

fun wrap title body =
    userStuff <- U.main wrap;
    return <xml><head>
      <title>{[title]}</title>
    </head><body>
      {userStuff.Status}<br/>
      {userStuff.Other}

      <h1>{[title]}</h1>

      {body}
    </body></xml>

fun main () =
    whoami <- U.current;
    wrap "Main page" (case whoami of
                          None => <xml>I don't think you're logged in.</xml>
                        | Some whoami => <xml>Apparently you are <b>{[whoami]}</b>!</xml>)
