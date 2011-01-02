#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/dh.h>
#include <curl/curl.h>
#include <expat.h>

#include <openid.h>

#define BUF_MAX 10240
#define BUF_INIT 1024

#define PRIME_LEN 64
#define GENERATOR DH_GENERATOR_5

uw_Basis_string uw_OpenidFfi_endpoint(uw_context ctx, uw_OpenidFfi_discovery d) {
  return d.endpoint;
}

uw_Basis_string uw_OpenidFfi_localId(uw_context ctx, uw_OpenidFfi_discovery d) {
  return d.localId;
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
  uw_OpenidFfi_discovery *d;
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
  uw_OpenidFfi_discovery *dy = uw_malloc(ctx, sizeof(uw_OpenidFfi_discovery));
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
  XML_SetStartElementHandler(cd.parser, startElement);

  curl_easy_setopt(c, CURLOPT_URL, id);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_discovery_data);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &cd);

  code = curl_easy_perform(c);
  uw_pop_cleanup(ctx);

  if (code || !dy->endpoint)
    return NULL;
  else
    return dy;
}

uw_OpenidFfi_inputs uw_OpenidFfi_createInputs(uw_context ctx) {
  uw_buffer *r = uw_malloc(ctx, sizeof(uw_buffer));
  uw_buffer_init(BUF_MAX, r, BUF_INIT);
  return r;
}

static void postify(uw_OpenidFfi_inputs buf, uw_Basis_string s) {
  for (; *s; ++s) {
    switch (*s) {
    case '=':
      uw_buffer_append(buf, "%3D", 3);
      break;
    case '&':
      uw_buffer_append(buf, "%26", 3);
      break;
    default:
      uw_buffer_append(buf, s, 1);
    }
  }
}

uw_unit uw_OpenidFfi_addInput(uw_context ctx, uw_OpenidFfi_inputs buf, uw_Basis_string key, uw_Basis_string value) {
  if (uw_buffer_used(buf) > 0)
    uw_buffer_append(buf, "&", 1);

  postify(buf, key);
  uw_buffer_append(buf, "=", 1);
  postify(buf, value);

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

      *colon = 0;

      newline = strchr(colon+1, '\n');

      if (!newline)
        break;

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

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new(BIO_s_mem());
  BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  (void)BIO_flush(b64);

  int len = BIO_ctrl_pending(bmem);
  char *buff = uw_malloc(ctx, len+1);
  BIO_read(bmem, buff, len);
  buff[len] = 0;

  BIO_free_all(b64);

  return buff;
}

static int unbase64(unsigned char *input, int length, unsigned char *buffer, int bufferLength)
{
  BIO *b64, *bmem;
  int n;

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(input, length);
  BIO_push(b64, bmem);
  n = BIO_read(b64, buffer, bufferLength);

  BIO_free_all(bmem);

  return n;
}

uw_Basis_string uw_OpenidFfi_hmac_sha1(uw_context ctx, uw_Basis_string key, uw_Basis_string data) {
  unsigned char keyBin[SHA_DIGEST_LENGTH], out[EVP_MAX_MD_SIZE];
  unsigned outLen;

  unbase64((unsigned char *)key, strlen(key), keyBin, sizeof keyBin);

  HMAC(EVP_sha1(), keyBin, sizeof keyBin, (unsigned char *)data, strlen(data), out, &outLen);
  return base64(ctx, out, outLen);
}

uw_Basis_string uw_OpenidFfi_hmac_sha256(uw_context ctx, uw_Basis_string key, uw_Basis_string data) {
  unsigned char keyBin[SHA256_DIGEST_LENGTH], out[EVP_MAX_MD_SIZE];
  unsigned outLen;

  unbase64((unsigned char *)key, strlen(key), keyBin, sizeof keyBin);

  HMAC(EVP_sha256(), keyBin, sizeof keyBin, (unsigned char *)data, strlen(data), out, &outLen);
  return base64(ctx, out, outLen);
}

static uw_Basis_string btwoc(uw_context ctx, const BIGNUM *n) {
  int len = BN_num_bytes(n), i;
  unsigned char bytes[len+1];

  bytes[0] = 0;
  BN_bn2bin(n, bytes+1);

  for (i = 1; i <= len; ++i)
    if (bytes[i]) {
      if (bytes[i] & 0x80)
        --i;
      break;
    }

  if (i > len)
    i = len;

  return base64(ctx, bytes+i, len+1-i);
}

static BIGNUM *unbtwoc(uw_context ctx, uw_Basis_string s) {
  unsigned char bytes[1024];
  int len;

  len = unbase64((unsigned char *)s, strlen(s), bytes, sizeof bytes);
  return BN_bin2bn(bytes, len, NULL);
}

uw_Basis_string uw_OpenidFfi_modulus(uw_context ctx, uw_OpenidFfi_dh dh) {
  return btwoc(ctx, dh->p);
}

uw_Basis_string uw_OpenidFfi_generator(uw_context ctx, uw_OpenidFfi_dh dh) {
  return btwoc(ctx, dh->g);
}

uw_Basis_string uw_OpenidFfi_public(uw_context ctx, uw_OpenidFfi_dh dh) {
  return btwoc(ctx, dh->pub_key);
}

static void free_DH(void *data, int will_retry) {
  DH *dh = data;
  DH_free(dh);
}

uw_OpenidFfi_dh uw_OpenidFfi_generate(uw_context ctx) {
  DH *dh = DH_new();

  uw_register_transactional(ctx, dh, NULL, NULL, free_DH);

  DH_generate_parameters_ex(dh, PRIME_LEN, GENERATOR, NULL);

  if (DH_generate_key(dh) != 1)
    uw_error(ctx, FATAL, "Diffie-Hellman key generation failed");

  return dh;
}

uw_Basis_string uw_OpenidFfi_compute(uw_context ctx, uw_OpenidFfi_dh dh, uw_Basis_string server_pub) {
  BIGNUM *bn = unbtwoc(ctx, server_pub);
  unsigned char secret[DH_size(dh)+1], *secretP;
  int size;

  uw_push_cleanup(ctx, (void (*)(void *))BN_free, bn);

  size = DH_compute_key(secret+1, bn, dh);
  if (size == -1)
    uw_error(ctx, FATAL, "Diffie-Hellman key computation failed");

  uw_pop_cleanup(ctx);

  if (size > 0 && (secret[1] & 0x80)) {
    secret[0] = 0;
    secretP = secret;
    ++size;
  } else
    secretP = secret+1;

  return base64(ctx, secretP, size);
}

uw_Basis_string uw_OpenidFfi_sha1(uw_context ctx, uw_Basis_string data) {
  unsigned char dataBin[128], out[EVP_MAX_MD_SIZE];
  int len;

  len = unbase64((unsigned char *)data, strlen(data), dataBin, sizeof dataBin);

  SHA1(dataBin, len, out);
  return base64(ctx, out, SHA_DIGEST_LENGTH);
}

uw_Basis_string uw_OpenidFfi_sha256(uw_context ctx, uw_Basis_string data) {
  unsigned char dataBin[128], out[EVP_MAX_MD_SIZE];
  int len;

  len = unbase64((unsigned char *)data, strlen(data), dataBin, sizeof dataBin);
  
  SHA256(dataBin, len, out);
  return base64(ctx, out, SHA256_DIGEST_LENGTH);
}

uw_Basis_string uw_OpenidFfi_xor(uw_context ctx, uw_Basis_string s1, uw_Basis_string s2) {
  unsigned char buf1[128], buf2[128], bufO[128];
  int len1, len2, i;

  len1 = unbase64((unsigned char *)s1, strlen(s1), buf1, sizeof buf1);
  len2 = unbase64((unsigned char *)s2, strlen(s2), buf2, sizeof buf2);

  for (i = 0; i < len1; ++i)
    bufO[i] = buf1[i] ^ buf2[i % len2];

  return base64(ctx, bufO, len1);
}

uw_OpenidFfi_inputs uw_OpenidFfi_remode(uw_context ctx, uw_OpenidFfi_outputs out, uw_Basis_string mode) {
  uw_OpenidFfi_inputs in = uw_OpenidFfi_createInputs(ctx);
  char *s;

  for (s = out->start; *s; s = strchr(strchr(s, 0)+1, 0)+1)
    if (!strcmp("openid.mode", s))
      uw_OpenidFfi_addInput(ctx, in, "openid.mode", mode);
    else
      uw_OpenidFfi_addInput(ctx, in, s, strchr(s, 0)+1);

  return in;
}
