#include <urweb/urweb.h>

typedef struct uw_OpenidFfi_discovery *uw_OpenidFfi_discovery;

uw_Basis_string uw_OpenidFfi_endpoint(uw_context, uw_OpenidFfi_discovery);
uw_Basis_string uw_OpenidFfi_localId(uw_context, uw_OpenidFfi_discovery);

uw_unit uw_OpenidFfi_init(uw_context);
uw_OpenidFfi_discovery *uw_OpenidFfi_discover(uw_context, uw_Basis_string id);
