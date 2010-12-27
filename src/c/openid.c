#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <expat.h>

#include <openid.h>

#define BUF_MAX 10240
#define BUF_INIT 1024

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
} curl_discovery_data;

static size_t write_discovery_data(void *buffer, size_t size, size_t nmemb, void *userp) {
  curl_discovery_data *d = userp;

  if (!XML_Parse(d->parser, buffer, size * nmemb, 0))
    d->any_errors = 1;

  return size * nmemb;
}

uw_OpenidFfi_discovery *uw_OpenidFfi_discover(uw_context ctx, uw_Basis_string id) {
  char *s;
  CURL *c = curl(ctx);
  curl_discovery_data cd = {};
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
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_discovery_data);
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

uw_OpenidFfi_inputs uw_OpenidFfi_createInputs(uw_context ctx) {
  uw_buffer *r = uw_malloc(ctx, sizeof(uw_buffer));
  uw_buffer_init(BUF_MAX, r, BUF_INIT);
  return r;
}

static int okForPost(const char *s) {
  for (; *s; ++s)
    if (*s == '=' || *s == '&')
      return 0;
  return 1;
}

uw_unit uw_OpenidFfi_addInput(uw_context ctx, uw_OpenidFfi_inputs buf, uw_Basis_string key, uw_Basis_string value) {
  if (!okForPost(key))
    uw_error(ctx, FATAL, "Invalid key for OpenID inputs");
  if (!okForPost(value))
    uw_error(ctx, FATAL, "Invalid value for OpenID inputs");

  if (uw_buffer_used(buf) > 0)
    uw_buffer_append(buf, "&", 1);

  uw_buffer_append(buf, key, strlen(key));
  uw_buffer_append(buf, "=", 1);
  uw_buffer_append(buf, value, strlen(value));

  return uw_unit_v;
}

uw_Basis_string uw_OpenidFfi_getOutput(uw_context ctx, uw_OpenidFfi_outputs buf, uw_Basis_string key) {
  char *s = buf->start;

  for (; *s; s = strchr(strchr(s, 0)+1, 0)+1)
    if (!strcmp(key, s))
      return strchr(s, 0)+1;

  return NULL;
}

static size_t write_buffer_data(void *buffer, size_t size, size_t nmemb, void *userp) {
  uw_buffer *buf = userp;

  uw_buffer_append(buf, buffer, size * nmemb);

  return size * nmemb;
}

const char curl_failure[] = "error\0Error fetching URL";

uw_OpenidFfi_outputs uw_OpenidFfi_direct(uw_context ctx, uw_Basis_string url, uw_OpenidFfi_inputs inps) {
  uw_buffer *buf = uw_malloc(ctx, sizeof(uw_buffer));
  CURL *c = curl(ctx);
  CURLcode code;

  uw_buffer_init(BUF_MAX, buf, BUF_INIT);

  uw_buffer_append(inps, "", 1);

  curl_easy_setopt(c, CURLOPT_URL, url);
  curl_easy_setopt(c, CURLOPT_POSTFIELDS, inps->start);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_buffer_data);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, buf);

  code = curl_easy_perform(c);

  uw_buffer_append(buf, "", 1);

  if (code) {
    uw_buffer_reset(buf);
    uw_buffer_append(buf, curl_failure, sizeof curl_failure);
  } else {
    char *s;

    s = buf->start;
    while (*s) {
      char *colon = strchr(s, ':'), *newline;

      if (!colon) {
        *s = 0;
        break;
      }

      newline = strchr(colon+1, '\n');

      if (!newline) {
        *s = 0;
        break;
      }

      *colon = 0;
      *newline = 0;
      s = newline+1;
    }
  }

  return buf;
}

static uw_Basis_string deurl(uw_context ctx, uw_Basis_string s) {
  uw_Basis_string r = uw_malloc(ctx, strlen(s)), s2 = r;

  for (; *s; ++s) {
    if (s[0] == '%' && s[1] && s[2]) {
      unsigned u;

      sscanf(s+1, "%02x", &u);
      *s2++ = u;
      s += 2;
    } else
      *s2++ = *s;
  }

  *s2 = 0;
  return r;
}

uw_OpenidFfi_outputs uw_OpenidFfi_indirect(uw_context ctx, uw_Basis_string fields) {
  uw_OpenidFfi_outputs b = malloc(sizeof(uw_buffer));

  uw_buffer_init(BUF_MAX, b, BUF_INIT);

  fields = uw_strdup(ctx, fields);

  while (*fields) {
    char *equal = strchr(fields, '='), *and, *s;

    if (!equal)
      break;

    *equal = 0;
    s = deurl(ctx, fields);
    uw_buffer_append(b, s, strlen(s));
    uw_buffer_append(b, "", 1);

    and = strchr(equal+1, '&');
    if (and) {
      *and = 0;
      fields = and+1;
    } else
      fields = and = strchr(equal+1, 0);
    s = deurl(ctx, equal+1);
    uw_buffer_append(b, s, strlen(s));
    uw_buffer_append(b, "", 1);
  }

  uw_buffer_append(b, "", 1);
  return b;
}

static uw_Basis_string base64(uw_context ctx, unsigned char *input, int length) {
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  (void)BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buff = uw_malloc(ctx, bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;

  BIO_free_all(b64);

  return buff;
}

uw_Basis_string uw_OpenidFfi_sha256(uw_context ctx, uw_Basis_string s) {
  unsigned char out[SHA256_DIGEST_LENGTH];

  SHA256((unsigned char *)s, strlen(s), out);

  return base64(ctx, out, sizeof out);
}
