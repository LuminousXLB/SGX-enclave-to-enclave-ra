#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_SP_ROUTINES_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_SP_ROUTINES_H

#include <tlibc/mbusafecrt.h>
#include <sgx_key_exchange.h>
#include "protocol.h"
#include "crypto_utils.h"

typedef struct ra_secret_struct {
    sgx_ec256_private_t private_b;
    sgx_ec256_public_t public_b;
    sgx_ec256_dh_shared_t shared_secret;
    sgx_cmac_128bit_key_t smk;
    sgx_ec256_public_t public_a;
    sgx_epid_group_id_t client_gid;
} ra_secret_t;

#define check_sgx_status(status) if(status != SGX_SUCCESS) return status;

sgx_status_t private_proc_msg0(ra_secret_t *secret, uint32_t msg0_extended_epid_group_id, attestation_error_t *error);

sgx_status_t private_proc_msg1(ra_secret_t *secret, sgx_ra_msg1_t *msg1, attestation_error_t *error);

#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_SP_ROUTINES_H
