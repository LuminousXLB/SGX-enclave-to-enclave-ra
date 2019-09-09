//
// Created by ncl on 9/9/19.
//

#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_LOOP_ROUTINE_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_LOOP_ROUTINE_H

#include <msgio.h>
#include <ias_request.h>
#include "tmp_config.h"

void do_attestation(sgx_enclave_id_t enclave_id, MsgIO *msgio, IAS_Connection *ias, const config_t &config);

#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_LOOP_ROUTINE_H
