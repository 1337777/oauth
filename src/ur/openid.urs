(* This module implements the key primitive of the OpenID 2.0 authentication
 * protocol, as specified in:
 *   http://specs.openid.net/auth/2.0
 *
 * Module author: Adam Chlipala
 *
 * Known missing features:
 * - Compatibility with prior OpenID protocols
 * - Endpoint discovery via XRIs or Yadis
 * - Immediate requests (authentication with no opportunity for user
 *   interaction)
 * - Publishing information for relying party discovery
 * - Extensions (in the protocol specification's terminology)
 *
 * Support for every other aspect of relying party functionality should be
 * present, including appropriate security measures.
 *)

(* == Quick summary of OpenID ==
 * There are lots of protocol details, but my take on it comes down to one
 * simple idea.  OpenID exports a primitive that allows a web site that verify
 * that a particular _user_ wishes to provide his identity to a particular
 * _URL_.  There is use of cryptography and other fanciness to implement this
 * primitive securely and efficiently, but application builders shouldn't need
 * to think about the implementation details.  Indeed, that simple interface is
 * what this module exports.  Thanks to Ur/Web's usual encapsulation guarantees,
 * client code need not worry about accidentally disturbing state used by the
 * protocol.
 *
 * The last key aspect is that URLs are used to identify users.  Each URL should
 * point to an HTML page containing a special tag which points to another URL
 * that is assigned responsibility for answering queries about what the user
 * has authorized.  To use the library, you only need to think about the
 * initial, user-identifying URLs, which form a kind of universal username
 * namespace.
 *)

(* The protocol provides some options for how particular security requirements
 * can be satisfied.  This module defines a few datatypes for the different
 * dimensions of choice. *)

(* First, we have association types, which are methods of guaranteeing message
 * integrity.  The only options in OpenID 2.0 are two different hash-based
 * message authentication codes (HMACs).  [HMAC_SHA256] is the stronger
 * scheme. *)

datatype association_type = HMAC_SHA1 | HMAC_SHA256

(* Next, there are association session types, which are approaches to
 * establishing shared secrets that can be used to provide integrity.  There are
 * two versions of the Diffie-Hellman key exchange protocol, based on pairing
 * with different MAC algorithms.  The [NoEncryption] option is only
 * appropriate for communication via SSL, which already provides secrecy.  If
 * [NoEncryption] is requested over an unencrypted HTTP connection, the library
 * will automatically switch to [DH_SHA256]. *)

datatype association_session_type = NoEncryption | DH_SHA1 | DH_SHA256

(* Finally, you have the option to skip all this crypto stuff in your
 * application, at some expense.  Use of cryptography with shared secrets allows
 * you to authenticate a user with one fewer round-trip to the remote web server
 * that is placed in charge of that user's identity.  This benefit is traded for
 * greater space requirements in your application, with several kinds of data
 * stored in local SQL tables, with the number of rows roughly proportional to
 * the number of authentications, over short time periods.  A stateless approach
 * uses local state only as a cache for predictable HTTP request results, with
 * storage use proportional to the number of users.  (The stateful approach uses
 * that same state and more.) *)

datatype association_mode =
         Stateless
       | Stateful of {AssociationType : association_type,
                      AssociationSessionType : association_session_type}

(* An authentication attempt terminates in one of four ways.
 * First, the user might get bored and surf away, never finishing the process.
 * If so, your application will never be told explicitly.
 * The other possibilities are captured by this datatype: *)

datatype authentication =
         AuthenticatedAs of string
         (* Successful authentication, with the user's verified identifying
          * URL *)
       | Canceled
         (* The user explicitly canceled the authentication process. *)
       | Failure of string
         (* Something went wrong, and here's some text that hopefully diagnoses
          * the problem. *)

(* Finally, here's the function to call to verify that a user wants to
 * authenticate to your particular web application.  Note that this will only
 * work properly if your project .urp file includes a 'prefix' directive that
 * gives the full protocol, hostname, and port part of your URLs.
 *
 * If authentication proceeds successfully, the function will never return.
 * Instead, the user is redirected to his identity provider, to authenticate with
 * whatever method they have agreed on.  When that process finishes, the user is
 * redirected back to your app, at which time the function that you pass as the
 * first argument below is called with the result, to generate the page to show
 * to the user.
 *
 * If authentication fails before the user is redirected away, the original
 * function returns an error message suitable for display to technically-savvy
 * users. *)

val authenticate : (authentication -> transaction page)
                   -> {Association : association_mode,
                       (* Your preferences for statefulness and cryptography.
                        * If the remote server doesn't support some kind of
                        * crypto that you ask for, the library automatically
                        * switches to a mode that the server advertises as
                        * supported. *)
                       Identifier : string,
                       (* The URL that the user claims identifies him.
                        * It may also point to a generic authentication service
                        * that will take care of deciding the proper
                        * username. *)
                       Realm : option string
                       (* A URL prefix that we are asking the user to authorize.
                        * If provided, it must be a genuine prefix of every
                        * application URL.  If omitted, we authorize for just one
                        * specific URL, which is the authentication-specific URL
                        * that the library always chooses automatically. *)}
                   -> transaction string
