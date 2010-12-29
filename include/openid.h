#include <urweb/urweb.h>

uw_unit uw_OpenidFfi_init(uw_context);

typedef struct uw_OpenidFfi_discovery *uw_OpenidFfi_discovery;

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

uw_Basis_string uw_OpenidFfi_sha256(uw_context, uw_Basis_string key, uw_Basis_string data);
