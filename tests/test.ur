fun discover r =
    dy <- Openid.discover r.Id;
    case dy of
        None => return <xml>No dice</xml>
      | Some dy =>
        os <- Openid.association dy.Endpoint;
        case os of
            Openid.Error s => error <xml>{[s]}</xml>
          | Openid.Handle s => return <xml>{[s]}</xml>

fun main () = return <xml><body>
  <form>
    <textbox{#Id}/>
    <submit action={discover}/>
  </form>
</body></xml>
