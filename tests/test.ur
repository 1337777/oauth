fun discover r =
    code <- Openid.discover r.Id;
    return <xml><body>
      Code: {[code]}
    </body></xml>

fun main () = return <xml><body>
  <form>
    <textbox{#Id}/>
    <submit action={discover}/>
  </form>
</body></xml>
