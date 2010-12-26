fun discover r =
    dy <- Openid.discover r.Id;
    case dy of
        None => return <xml>No dice</xml>
      | Some dy => return <xml><body>
        Endpoint: {[dy.Endpoint]}<br/>
        Local ID: {[dy.LocalId]}<br/>
      </body></xml>

fun main () = return <xml><body>
  <form>
    <textbox{#Id}/>
    <submit action={discover}/>
  </form>
</body></xml>
