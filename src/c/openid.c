#include <openssl/sha.h>
#include <curl/curl.h>

#include <urweb/urweb.h>

uw_unit uw_OpenidFfi_init(uw_context ctx) {
  curl_global_init(CURL_GLOBAL_ALL);

  return uw_unit_v;
}
