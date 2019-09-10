#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_X509_VFY_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_X509_VFY_H

#include <openssl/x509.h>

int hook_X509_verify_cert_hook(X509_STORE_CTX *ctx);

#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_X509_VFY_H
