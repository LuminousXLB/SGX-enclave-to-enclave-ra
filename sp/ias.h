//
// Created by ncl on 3/9/19.
//

#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_IAS_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_IAS_H

#include "ias_request.h"
#include "sgx_key_exchange.h"
#include "protocol.h"

int get_sigrl(IAS_Connection *ias, int version, const sgx_epid_group_id_t gid, char **sig_rl, uint32_t *sig_rl_size);

int get_attestation_report(IAS_Connection *ias, int version, const char *b64quote, sgx_ps_sec_prop_desc_t sec_prop,
                           ra_msg4_t *msg4, int strict_trust);


#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_IAS_H
