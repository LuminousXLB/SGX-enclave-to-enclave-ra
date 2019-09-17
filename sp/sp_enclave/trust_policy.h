#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_TRUST_POLICY_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_TRUST_POLICY_H

#include <sgx_tkey_exchange.h>

typedef struct _ra_trust_policy {
    int allow_debug;
    int allow_configuration_needed;
    sgx_prod_id_t isv_product_id;
    sgx_isv_svn_t isv_min_svn;
    sgx_measurement_t mrsigner;
} ra_trust_policy;

#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_TRUST_POLICY_H
