//
// Created by ncl on 16/9/19.
//

#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_DO_ATTESTATION_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_DO_ATTESTATION_H

#include <sgx_urts.h>
#include "config.h"

int do_attestation(sgx_enclave_id_t eid, config_t *config);


#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_DO_ATTESTATION_H
