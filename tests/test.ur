fun auth r =
    msg <- Openid.authenticate r.Id;
    error <xml>{[msg]}</xml>

fun main () = return <xml><body>
  <form>
    <textbox{#Id}/>
    <submit action={auth}/>
  </form>
</body></xml>
