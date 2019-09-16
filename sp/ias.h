#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_IAS_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_IAS_H

#include "ias_request.h"
#include "sgx_key_exchange.h"
#include "protocol.h"

ias_error_t get_sigrl(IAS_Connection *ias, int version, const sgx_epid_group_id_t &gid, string &sig_rl);

ias_error_t get_attestation_report(IAS_Connection *ias, int version, const vector<uint8_t> &quote, string &response);


#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_IAS_H
