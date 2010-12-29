fun afterward r = return <xml><body>
  {case r of
       Openid.Canceled => <xml>You canceled that sucker.</xml>
     | Openid.Failure s => error <xml>OpenID failure: {[s]}</xml>
     | Openid.AuthenticatedAs id => <xml>I now know you as <tt>{[id]}</tt>.</xml>}
</body></xml>

fun auth r =
    msg <- Openid.authenticate afterward
                               {AssociationType = Openid.HMAC_SHA256,
                                AssociationSessionType = Openid.NoEncryption,
                                Identifier = r.Id};
    error <xml>{[msg]}</xml>

fun main () = return <xml><body>
  <form>
    <textbox{#Id}/>
    <submit action={auth}/>
  </form>
</body></xml>
