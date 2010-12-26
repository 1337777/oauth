#include <string.h>

#include <openssl/sha.h>
#include <curl/curl.h>
#include <expat.h>

#include <openid.h>

struct uw_OpenidFfi_discovery {
  uw_Basis_string endpoint, localId;
};

uw_Basis_string uw_OpenidFfi_endpoint(uw_context ctx, uw_OpenidFfi_discovery d) {
  return d->endpoint;
}

uw_Basis_string uw_OpenidFfi_localId(uw_context ctx, uw_OpenidFfi_discovery d) {
  return d->localId;
}

uw_unit uw_OpenidFfi_init(uw_context ctx) {
  curl_global_init(CURL_GLOBAL_ALL);

  return uw_unit_v;
}

static CURL *curl(uw_context ctx) {
  CURL *r;

  if (!(r = uw_get_global(ctx, "curl"))) {
    r = curl_easy_init();
    if (r)
      uw_set_global(ctx, "curl", r, curl_easy_cleanup);
  }

  return r;
}

typedef struct {
  uw_context ctx;
  uw_OpenidFfi_discovery d;
} endpoint;

static void XMLCALL startElement(void *userData, const XML_Char *name, const XML_Char **atts) {
  endpoint *ep = userData;

  if (!strcmp(name, "link")) {
    const XML_Char **attp;
    int found = 0;

    for (attp = atts; *attp; attp += 2) {
      if (!strcmp(attp[0], "rel") && !strcmp(attp[1], "openid2.provider")) {
        found = 1;
        break;
      }
    }

    if (found) {
      for (attp = atts; *attp; attp += 2) {
        if (!strcmp(attp[0], "href")) {
          ep->d->endpoint = uw_strdup(ep->ctx, attp[1]);
          return;
        }
      }
    }
  }
}

static void XMLCALL endElement(void *userData, const XML_Char *name) {
}

typedef struct {
  XML_Parser parser;
  int any_errors;
} curl_data;

static size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
  curl_data *d = userp;

  if (!XML_Parse(d->parser, buffer, size * nmemb, 0))
    d->any_errors = 1;

  return size * nmemb;
}

uw_OpenidFfi_discovery *uw_OpenidFfi_discover(uw_context ctx, uw_Basis_string id) {
  char *s;
  CURL *c = curl(ctx);
  curl_data cd = {};
  uw_OpenidFfi_discovery dy = uw_malloc(ctx, sizeof(struct uw_OpenidFfi_discovery));
  endpoint ep = {ctx, dy};
  CURLcode code;

  dy->endpoint = dy->localId = NULL;

  if (!strchr(id, ':')) {
    id = uw_Basis_strcat(ctx, "http://", id);
    if ((s = strchr(id, '#')) != NULL)
      *s = 0;
  } else if ((s = strchr(id, '#')) != NULL) {
    char *id2 = uw_malloc(ctx, s - id + 1);
    memcpy(id2, s, s - id);
    id2[s - id] = 0;
    id = id2;
  }

  cd.parser = XML_ParserCreate(NULL);
  XML_SetUserData(cd.parser, &ep);
  uw_push_cleanup(ctx, (void (*)(void *))XML_ParserFree, cd.parser);
  XML_SetElementHandler(cd.parser, startElement, endElement);

  curl_easy_setopt(c, CURLOPT_URL, id);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_data);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &cd);

  code = curl_easy_perform(c);
  uw_pop_cleanup(ctx);

  if (code || !ep.d->endpoint)
    return NULL;
  else {
    uw_OpenidFfi_discovery *dyp = malloc(sizeof(uw_OpenidFfi_discovery));
    *dyp = ep.d;
    return dyp;
  }
}
