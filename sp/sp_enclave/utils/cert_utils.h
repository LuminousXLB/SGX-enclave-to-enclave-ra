#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_X509_UTILS_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_X509_UTILS_H

#include <cstdlib>
#include <openssl/x509.h>
#include <string>
#include <sgx_key_exchange.h>
#include "../httpparser/response.h"
#include "protocol.h"

sgx_status_t verify_certificate(const httpparser::Response &response, attestation_error_t &att_error);

#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_X509_UTILS_H
