#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_CRYPTO_UTILS_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_CRYPTO_UTILS_H

#include <sgx_tcrypto.h>
#include <string>
#include "string.h"

sgx_status_t key_verify(const sgx_ec256_public_t *pubkey, int *result);

sgx_status_t key_generate(sgx_ec256_private_t *k_b, sgx_ec256_public_t *g_b);

sgx_status_t ecdh_shared_secret(sgx_ec256_private_t *k_b, sgx_ec256_public_t *g_a, sgx_ec256_dh_shared_t *shared);

sgx_status_t ecdsa(sgx_ec256_private_t *priv_sp, const uint8_t *data, uint32_t data_size,
                   sgx_ec256_signature_t *signature);

sgx_status_t derive_key(const sgx_ec256_dh_shared_t *ss, const std::string label, sgx_cmac_128bit_key_t *derived_key);


#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_CRYPTO_UTILS_H
