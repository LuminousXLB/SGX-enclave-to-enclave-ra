//
// Created by ncl on 3/9/19.
//

#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_SP_OCALLS_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_SP_OCALLS_H

#include <sgx_key_exchange.h>

//    [ocall]get  SigRL, spid, quote_type
void ocall_pre_get_sigrl(sgx_epid_group_id_t gid, sgx_spid_t *spid, uint16_t *quote_type, uint32_t *sigrl_length);

void ocall_get_sigrl(uint32_t sigrl_size, uint8_t *sigrl);

#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_SP_OCALLS_H
