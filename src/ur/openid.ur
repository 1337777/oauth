val discoveryExpiry = 3600
val nonceExpiry = 600
val nonceSkew = 600

task initialize = fn () => OpenidFfi.init

table discoveries : { Identifier : string, Endpoint : string, Expires : time }
  PRIMARY KEY Identifier

fun eatFragment s =
    case String.split s #"#" of
        Some (s', _) => s'
      | _ => s

fun discover s =
    s <- return (eatFragment s);
    endpoint <- oneOrNoRowsE1 (SELECT (discoveries.Endpoint)
                               FROM discoveries
                               WHERE discoveries.Identifier = {[s]});
    case endpoint of
        Some ep => return (Some ep)
      | None =>
        r <- OpenidFfi.discover s;
        case r of
            None => return None
          | Some r =>
            tm <- now;
            dml (INSERT INTO discoveries (Identifier, Endpoint, Expires)
                 VALUES ({[s]}, {[OpenidFfi.endpoint r]}, {[addSeconds tm discoveryExpiry]}));
            return (Some (OpenidFfi.endpoint r))

val createInputs =
    is <- OpenidFfi.createInputs;
    OpenidFfi.addInput is "openid.ns" "http://specs.openid.net/auth/2.0";
    return is

datatype association_type = HMAC_SHA1 | HMAC_SHA256
datatype association_session_type = NoEncryption | DH_SHA1 | DH_SHA256
datatype association_mode =
         Stateless
       | Stateful of {AssociationType : association_type,
                      AssociationSessionType : association_session_type}

datatype authentication_mode =
         ChooseIdentifier of string
       | KnownIdentifier of string

table associations : { Endpoint : string, Handle : string, Typ : serialized association_type, Key : string, Expires : time }
  PRIMARY KEY Endpoint

datatype association = Association of {Handle : string, Typ : association_type, Key : string}
                     | AssError of string
                     | AssAlternate of {Atype : association_type, Stype : association_session_type}

fun atype_show v =
    case v of
        HMAC_SHA1 => "HMAC-SHA1"
      | HMAC_SHA256 => "HMAC-SHA256"

val show_atype = mkShow atype_show

fun stype_show v =
    case v of
        NoEncryption => "no-encryption"
      | DH_SHA1 => "DH-SHA1"
      | DH_SHA256 => "DH-SHA256"

val show_stype = mkShow stype_show

fun atype_read s =
    case s of
        "HMAC-SHA1" => Some HMAC_SHA1
      | "HMAC-SHA256" => Some HMAC_SHA256
      | _ => None

val read_atype = mkRead' atype_read "association type"

fun stype_read s =
    case s of
        "no-encryption" => Some NoEncryption
      | "DH-SHA1" => Some DH_SHA1
      | "DH-SHA256" => Some DH_SHA256
      | _ => None

val read_stype = mkRead' stype_read "association session type"

fun atype_eq v1 v2 =
    case (v1, v2) of
        (HMAC_SHA1, HMAC_SHA1) => True
      | (HMAC_SHA256, HMAC_SHA256) => True
      | _ => False

val eq_atype = mkEq atype_eq

fun stype_eq v1 v2 =
    case (v1, v2) of
        (NoEncryption, NoEncryption) => True
      | (DH_SHA1, DH_SHA1) => True
      | (DH_SHA256, DH_SHA256) => True
      | _ => False

val eq_stype = mkEq stype_eq

fun errorResult atype stype os =
    case OpenidFfi.getOutput os "error" of
        Some v =>
        (case (OpenidFfi.getOutput os "error_code", OpenidFfi.getOutput os "assoc_type", OpenidFfi.getOutput os "session_type") of
             (Some "unsupported-type", at, st) => Some (AssAlternate {Atype = Option.get atype (Option.bind read at),
                                                                      Stype = Option.get stype (Option.bind read st)})
           | _ => Some (AssError ("OP error during association: " ^ v)))
      | None => None

fun eatQstring s =
    case String.split s #"?" of
        Some (s', _) => s'
      | _ => s

fun associateNoEncryption url atype =
    url <- return (eatQstring url);
    is <- createInputs;
    OpenidFfi.addInput is "openid.mode" "associate";
    OpenidFfi.addInput is "openid.assoc_type" (show atype);
    OpenidFfi.addInput is "openid.session_type" (show NoEncryption);

    os <- OpenidFfi.direct url is;
    case errorResult atype NoEncryption os of
        Some v => return v
      | None =>
        case (OpenidFfi.getOutput os "assoc_handle", OpenidFfi.getOutput os "mac_key", OpenidFfi.getOutput os "expires_in") of
            (Some handle, Some key, Some expires) =>
            (case read expires of
                 None => return (AssError "Invalid 'expires_in' field")
               | Some expires =>
                 tm <- now;
                 dml (INSERT INTO associations (Endpoint, Handle, Typ, Key, Expires)
                      VALUES ({[url]}, {[handle]}, {[serialize atype]}, {[key]}, {[addSeconds tm expires]}));
                 return (Association {Handle = handle, Typ = atype, Key = key}))
          | (None, _, _) => return (AssError "Missing assoc_handle")
          | (_, None, _) => return (AssError "Missing mac_key")
          | _ => return (AssError "Missing expires_in")

fun associateDh url atype stype =
    url <- return (eatQstring url);
    dh <- OpenidFfi.generate;

    is <- createInputs;
    OpenidFfi.addInput is "openid.mode" "associate";
    OpenidFfi.addInput is "openid.assoc_type" (show atype);
    OpenidFfi.addInput is "openid.session_type" (show stype);
    OpenidFfi.addInput is "openid.dh_modulus" (OpenidFfi.modulus dh);
    OpenidFfi.addInput is "openid.dh_gen" (OpenidFfi.generator dh);
    OpenidFfi.addInput is "openid.dh_consumer_public" (OpenidFfi.public dh);

    os <- OpenidFfi.direct url is;
    case errorResult atype stype os of
        Some v => return v
      | None =>
        case (OpenidFfi.getOutput os "assoc_handle", OpenidFfi.getOutput os "dh_server_public",
              OpenidFfi.getOutput os "enc_mac_key", OpenidFfi.getOutput os "expires_in") of
                (Some handle, Some pub, Some mac, Some expires) =>
                (case read expires of
                     None => return (AssError "Invalid 'expires_in' field")
                   | Some expires =>
                     secret <- OpenidFfi.compute dh pub;
                     digest <- return (case stype of
                                           DH_SHA1 => OpenidFfi.sha1 secret
                                         | DH_SHA256 => OpenidFfi.sha256 secret
                                         | _ => error <xml>Non-DH stype in associateDh</xml>);
                     key <- return (OpenidFfi.xor mac digest);
                     tm <- now;
                     dml (INSERT INTO associations (Endpoint, Handle, Typ, Key, Expires)
                          VALUES ({[url]}, {[handle]}, {[serialize atype]}, {[key]}, {[addSeconds tm expires]}));
                     return (Association {Handle = handle, Typ = atype, Key = key}))
              | (None, _, _, _) => return (AssError "Missing assoc_handle")
              | (_, None, _, _) => return (AssError "Missing dh_server_public")
              | (_, _, None, _) => return (AssError "Missing enc_mac_key")
              | _ => return (AssError "Missing expires_in")

fun oldAssociation url =
    url <- return (eatQstring url);
    secret <- oneOrNoRows1 (SELECT associations.Handle, associations.Typ, associations.Key
                            FROM associations
                            WHERE associations.Endpoint = {[url]});
    case secret of
        Some r => return (Some (r -- #Typ ++ {Typ = deserialize r.Typ}))
      | None => return None

fun newAssociation url atype stype =
    case stype of
        NoEncryption => associateNoEncryption url atype
      | _ => associateDh url atype stype

fun association atype stype url =
    secret <- oldAssociation url;
    case secret of
        Some r => return (Association r)
      | None =>
        stype <- return (case (stype, String.isPrefix {Full = url, Prefix = "https://"}) of
                             (NoEncryption, False) => DH_SHA256
                           | _ => stype);
        r <- newAssociation url atype stype;
        case r of
            AssAlternate alt =>
            if alt.Atype = atype && alt.Stype = stype then
                return (AssError "Suggested new modes match old ones!")
            else
                debug "Renegotiating protocol";
                newAssociation url alt.Atype alt.Stype
          | v => return v

datatype handle_result = HandleOk of {Endpoint : string, Typ : association_type, Key : string} | NoAssociation of string | HandleError of string

datatype authentication = AuthenticatedAs of string | Canceled | Failure of string

fun verifyHandle os id =
    id' <- return (eatFragment id);
    ep <- discover id';
    case ep of
        None => return (HandleError ("Discovery failed on returned identifier: " ^ id'))
      | Some ep =>
        case OpenidFfi.getOutput os "openid.assoc_handle" of
            None => return (HandleError "Missing association handle in response")
          | Some handle =>
            assoc <- oldAssociation ep;
            case assoc of
                None => return (NoAssociation ep)
              | Some assoc =>
                if assoc.Handle <> handle then
                    return (HandleError "Association handles don't match")
                else
                    return (HandleOk {Endpoint = ep, Typ = assoc.Typ, Key = assoc.Key})

fun verifyStateless os ep id expectInvalidation =
    os' <- OpenidFfi.direct ep (OpenidFfi.remode os "check_authentication");
    case OpenidFfi.getOutput os' "error" of
        Some msg => return (Failure ("Failure confirming message contents with OP: " ^ msg))
      | None =>
        let
            fun finish () = case OpenidFfi.getOutput os' "is_valid" of
                                Some "true" => return (AuthenticatedAs id)
                              | _ => return (Failure "OP does not confirm message contents")
        in
            case OpenidFfi.getOutput os' "invalidate_handle" of
                None =>
                if expectInvalidation then
                    return (Failure "Claimed invalidate_handle is not confirmed")
                else
                    finish ()
              | Some handle =>
                dml (DELETE FROM associations
                     WHERE Endpoint = {[ep]} AND Handle = {[handle]});
                finish ()
        end

table nonces : { Endpoint : string, Nonce : string, Expires : time }
  PRIMARY KEY (Endpoint, Nonce)

fun timeOfNonce s =
    case String.split s #"T" of
        None => None
      | Some (date, s) =>
        case String.split s #"Z" of
            None => None
          | Some (time, _) => readUtc (date ^ " " ^ time)

fun verifyNonce os ep =
    case OpenidFfi.getOutput os "openid.response_nonce" of
        None => return (Some "Missing nonce in OP response")
      | Some nonce =>
        case timeOfNonce nonce of
            None => return (Some "Invalid timestamp in nonce")
          | Some tm =>
            now <- now;
            if tm < addSeconds now (-nonceExpiry) then
                return (Some "Nonce timestamp is too old")
            else if tm > addSeconds now nonceSkew then
                return (Some "Nonce timestamp is too far in the future")
            else
                b <- oneRowE1 (SELECT COUNT( * ) > 0
                               FROM nonces
                               WHERE nonces.Endpoint = {[ep]}
                                 AND nonces.Nonce = {[nonce]});

                if b then
                    return (Some "Duplicate nonce")
                else
                    dml (INSERT INTO nonces (Endpoint, Nonce, Expires)
                         VALUES ({[ep]}, {[nonce]}, {[addSeconds now nonceExpiry]}));
                    return None

fun verifySig os atype key =
    case OpenidFfi.getOutput os "openid.signed" of
        None => return (Some "Missing openid.signed in OP response")
      | Some signed =>
        case OpenidFfi.getOutput os "openid.sig" of
            None => return (Some "Missing openid.sig in OP response")
          | Some sign => let
                fun gatherNvps signed required acc =
                    let
                        val (this, next) =
                            case String.split signed #"," of
                                None => (signed, None)
                              | Some (this, next) => (this, Some next)
                    in
                        case OpenidFfi.getOutput os ("openid." ^ this) of
                            None => None
                          | Some value =>
                            let
                                val required = List.filter (fn other => other <> this) required
                                val acc = acc ^ this ^ ":" ^ value ^ "\n"
                            in
                                case next of
                                    None => Some (required, acc)
                                  | Some next => gatherNvps next required acc
                            end
                    end
            in    
                case gatherNvps signed ("op_endpoint" :: "return_to" :: "response_nonce" :: "assoc_handle" :: "claimed_id" :: "identity" :: []) "" of
                    None => return (Some "openid.signed mentions missing field")
                  | Some ([], nvps) =>
                    let
                        val sign' = case atype of
                                        HMAC_SHA256 => OpenidFfi.hmac_sha256 key nvps
                                      | HMAC_SHA1 => OpenidFfi.hmac_sha1 key nvps
                    in
                        if OpenidFfi.secCmp sign' sign then
                            return None
                        else
                            return (Some "Signatures don't match")
                    end
                  | Some (left, _) => return (Some ("openid.signed is missing required fields: " ^ show left))
            end


		    
functor OAuth (M: sig
		   val endpointAuth : string (*https://github.com/login/oauth/authorize*)
		   val endpointToken : string (*https://github.com/login/oauth/access_token*)
		   val clientId : string
		   val clientSecret : string
		   val sessionLifetime : int
	       end) = struct

    sequence sessionIds
	     
    table session : {Id : int, Key : int, Identifier : option string, Expires : time, Token : option string}
			PRIMARY KEY Id
		    
    datatype authorization =
             AuthorizedAs of {Id : int, Key : int}
	   | CanceledAuth
	   | FailureAuth of string
			    
    fun authorize after r =
	let
	fun newSession identO =
            ses <- nextval sessionIds;
            now <- now;
            key <- rand;
            dml (INSERT INTO session (Id, Key, Identifier, Expires, Token)
                 VALUES ({[ses]}, {[key]}, {[identO]}, {[addSeconds now M.sessionLifetime]}, {[None]}));
            return {Id = ses, Key = key}

	fun exchangeCode code =
	    is <- createInputs;
	    OpenidFfi.addInput is "code" code;
	    OpenidFfi.addInput is "client_id" M.clientId;
	    OpenidFfi.addInput is "client_secret" M.clientSecret;
	    OpenidFfi.directToken M.endpointToken is
	    
       fun returnToAuth (qs : option queryString) =
            case qs of
                None => after (FailureAuth "Empty query string for OAuth callback")
              | Some qs =>
                os <- OpenidFfi.indirect qs;
                case OpenidFfi.getOutput os "error" of
                    Some v => after (FailureAuth ("Authorization failed: no sucessful grant: " ^ v))
                  | None =>
                    case OpenidFfi.getOutput os "state" of
                        None => after (FailureAuth "No state in response")
                      | Some state =>
			case String.split state #"@" of
			    None => after (FailureAuth "Invalid 'stateFull' field")
			  | Some (stateIndex, state) =>
			    case read stateIndex of
				None => after (FailureAuth "Invalid 'stateIndex' field")
			      | Some stateIndex =>
				case read state of
				    None => after (FailureAuth "Invalid 'statePass' field")
				  | Some state =>
				    case OpenidFfi.getOutput os "code" of
					None => after (FailureAuth "Missing code in response")
				      | Some code =>
					errO <- verifyStateAuth os stateIndex state;
					case errO of
					    Some s => after (FailureAuth s)
					  | None => os2 <- exchangeCode code;
					    os2 <- (case OpenidFfi.getOutput os2 "error" of
							Some v => exchangeCode code (*github bug? retry*)
						      | None => return os2); 
					    case OpenidFfi.getOutput os2 "error" of
						Some v => after (FailureAuth ("Authorization failed: directToken error for code " ^ code ^ " - Description:" ^ v))
					      | None => case (OpenidFfi.getOutput os2 "access_token", OpenidFfi.getOutput os2 "scope", OpenidFfi.getOutput os2 "token_type") of
							    (Some token, Some token_scope, Some token_type) =>
							    dml (UPDATE session
								 SET Identifier = {[Some code]},
								   Token = {[Some token]}
								 WHERE Id = {[stateIndex]});
							    after (AuthorizedAs {Id = stateIndex, Key = state})
							  | (None, _, _) => after (FailureAuth ("Authorization failed: no token in response "))
							  | (_, None, _) => after (FailureAuth ("Authorization failed: no token_scope in response"))
							  | _ => after (FailureAuth ("Authorization failed: no token_type in response"))
								 
       and verifyStateAuth os stateIndex state =
	   valid <- oneRowE1 (SELECT COUNT( * ) > 0
                              FROM session
                              WHERE session.Id = {[stateIndex]}
                                AND session.Key = {[state]});
           if valid then
               return None
           else
	       return (Some "That state is invalid or expired.")
	       
	val begin = case String.index M.endpointAuth #"?" of
                        None => "?"
                      | Some _ => "&"

    in
	ses <- newSession None;
        redirect (bless (M.endpointAuth
			 ^ begin ^ "client_id=" ^ M.clientId
                         ^ "&redirect_uri=" ^ show (effectfulUrl returnToAuth)
			 ^ "&scope=" ^ r.Scope
			 ^ "&state=" ^ (show ses.Id) ^ "@" ^ (show ses.Key)))
    end

    fun directApi id key ep =
	access_token <- oneOrNoRowsE1 (SELECT (session.Token)
				       FROM session
				       WHERE session.Id = {[id]} AND session.Key = {[key]});
	case access_token of
            Some (Some access_token) => 
	    res <- OpenidFfi.directApi (ep (*"https://api.github.com/user"*)
				     ^ "?access_token=" ^ access_token);
	    (case res of
		Some res => return (Some res)
	      | None => return None)
	  | _ => return None
					      
end

fun authenticate after r =
    let
        fun returnTo (qs : option queryString) =
            case qs of
                None => after (Failure "Empty query string for OpenID callback")
              | Some qs =>
                os <- OpenidFfi.indirect qs;
                case OpenidFfi.getOutput os "openid.error" of
                    Some v => after (Failure ("Authentication failed: " ^ v))
                  | None =>
                    case OpenidFfi.getOutput os "openid.mode" of
                        None => after (Failure "No openid.mode in response")
                      | Some mode =>
                        case mode of
                            "cancel" => after Canceled
                          | "id_res" =>
                            (case OpenidFfi.getOutput os "openid.claimed_id" of
                                 None => after (Failure "Missing identity in OP response")
                               | Some id =>
                                 errO <- verifyReturnTo os;
                                 case errO of
                                     Some s => after (Failure s)
                                   | None =>
                                     errO <- verifyHandle os id;
                                     case errO of
                                         HandleError s => after (Failure s)
                                       | NoAssociation ep =>
                                         r <- verifyStateless os ep id False;
                                         after r
                                       | HandleOk {Endpoint = ep, Typ = atype, Key = key} =>
                                         case OpenidFfi.getOutput os "openid.invalidate_handle" of
                                             Some _ =>
                                             r <- verifyStateless os ep id True;
                                             after r
                                           | None =>
                                             errO <- verifyNonce os ep;
                                             case errO of
                                                 Some s => after (Failure s)
                                               | None =>
                                                 errO <- verifySig os atype key;
                                                 case errO of
                                                     Some s => after (Failure s)
                                                   | None => after (AuthenticatedAs id))
                          | _ => after (Failure ("Unexpected openid.mode: " ^ mode))

        and verifyReturnTo os =
            case OpenidFfi.getOutput os "openid.return_to" of
                None => return (Some "Missing return_to in OP response")
              | Some rt =>
                if rt <> show (effectfulUrl returnTo) then
                    return (Some "Wrong return_to in OP response")
                else
                    return None

        val realmString = case r.Realm of
                              None => ""
                            | Some realm => "&openid.realm=" ^ realm

        val (ident, claimed) =
            case r.Identifier of
                ChooseIdentifier s => (eatFragment s, "http://specs.openid.net/auth/2.0/identifier_select")
              | KnownIdentifier s =>
                let
                    val s = eatFragment s
                in
                    (s, s)
                end
    in
        dy <- discover ident;
        case dy of
            None => return "Discovery failed"
          | Some dy =>
            let
                val begin = case String.index dy #"?" of
                                None => "?"
                              | Some _ => "&"
            in
                case r.Association of
                    Stateless =>
                    redirect (bless (dy ^ begin ^ "openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup"
                                     ^ "&openid.claimed_id=" ^ claimed
                                     ^ "&openid.identity=" ^ claimed ^ "&openid.assoc_handle="
                                     ^ "&openid.return_to=" ^ show (effectfulUrl returnTo) ^ realmString))
                  | Stateful ar =>
                    assoc <- association ar.AssociationType ar.AssociationSessionType dy;
                    case assoc of
                        AssError msg => return ("Association failure: " ^ msg)
                      | AssAlternate _ => return "Association failure: server didn't accept its own alternate association modes"
                      | Association assoc =>
                        redirect (bless (dy ^ begin ^ "openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup"
                                         ^ "&openid.claimed_id=" ^ claimed
                                         ^ "&openid.identity=" ^ claimed ^ "&openid.assoc_handle="
                                         ^ assoc.Handle ^ "&openid.return_to=" ^ show (effectfulUrl returnTo) ^ realmString))
            end
    end

task periodic 60 = fn () =>
                      dml (DELETE FROM discoveries WHERE Expires < CURRENT_TIMESTAMP);
                      dml (DELETE FROM associations WHERE Expires < CURRENT_TIMESTAMP);
                      dml (DELETE FROM nonces WHERE Expires < CURRENT_TIMESTAMP)
