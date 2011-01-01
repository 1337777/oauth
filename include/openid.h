#include <urweb/urweb.h>

#include <openssl/dh.h>

uw_unit uw_OpenidFfi_init(uw_context);

typedef struct {
  uw_Basis_string endpoint, localId;
} uw_OpenidFfi_discovery;

uw_Basis_string uw_OpenidFfi_endpoint(uw_context, uw_OpenidFfi_discovery);
uw_Basis_string uw_OpenidFfi_localId(uw_context, uw_OpenidFfi_discovery);

uw_OpenidFfi_discovery *uw_OpenidFfi_discover(uw_context, uw_Basis_string id);

typedef uw_buffer *uw_OpenidFfi_inputs;
typedef uw_buffer *uw_OpenidFfi_outputs;

uw_OpenidFfi_inputs uw_OpenidFfi_createInputs(uw_context);
uw_unit uw_OpenidFfi_addInput(uw_context, uw_OpenidFfi_inputs, uw_Basis_string key, uw_Basis_string value);

uw_Basis_string uw_OpenidFfi_getOutput(uw_context, uw_OpenidFfi_outputs, uw_Basis_string key);

uw_OpenidFfi_outputs uw_OpenidFfi_direct(uw_context, uw_Basis_string url, uw_OpenidFfi_inputs);
uw_OpenidFfi_outputs uw_OpenidFfi_indirect(uw_context, uw_Basis_string fields);

uw_Basis_string uw_OpenidFfi_sha1(uw_context ctx, uw_Basis_string data);
uw_Basis_string uw_OpenidFfi_sha256(uw_context ctx, uw_Basis_string data);

uw_Basis_string uw_OpenidFfi_hmac_sha1(uw_context, uw_Basis_string key, uw_Basis_string data);
uw_Basis_string uw_OpenidFfi_hmac_sha256(uw_context, uw_Basis_string key, uw_Basis_string data);

typedef DH *uw_OpenidFfi_dh;

uw_Basis_string uw_OpenidFfi_modulus(uw_context, uw_OpenidFfi_dh);
uw_Basis_string uw_OpenidFfi_generator(uw_context, uw_OpenidFfi_dh);
uw_Basis_string uw_OpenidFfi_public(uw_context, uw_OpenidFfi_dh);

uw_OpenidFfi_dh uw_OpenidFfi_generate(uw_context);
uw_Basis_string uw_OpenidFfi_compute(uw_context, uw_OpenidFfi_dh, uw_Basis_string server_pub);
uw_Basis_string uw_OpenidFfi_xor(uw_context, uw_Basis_string, uw_Basis_string);
