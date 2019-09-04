#include "crypto_utils.h"

using namespace std;


sgx_status_t key_verify(const sgx_ec256_public_t &pubkey, bool &valid) {
    sgx_status_t status;
    sgx_ecc_state_handle_t ecc_handle = nullptr;

    status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) {
        valid = false;
        goto cleanup;
    }

    int result;
    status = sgx_ecc256_check_point(&pubkey, ecc_handle, &result);
    if (status != SGX_SUCCESS) {
        valid = false;
        goto cleanup;
    }

    valid = (result != 0);

    cleanup:
    sgx_ecc256_close_context(ecc_handle);
    return status;
}

sgx_status_t key_generate(sgx_ec256_private_t &privkey, sgx_ec256_public_t &pubkey) {
    sgx_status_t status;
    sgx_ecc_state_handle_t ecc_handle = nullptr;

    status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup;
    }

    status = sgx_ecc256_create_key_pair(&privkey, &pubkey, ecc_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup;
    }

    cleanup:
    sgx_ecc256_close_context(ecc_handle);
    return status;
}


sgx_status_t ecdh_shared_secret(sgx_ec256_private_t &privkey, sgx_ec256_public_t &pubkey,
                                sgx_ec256_dh_shared_t &shared) {
    sgx_status_t status;
    sgx_ecc_state_handle_t ecc_handle = nullptr;

    status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup;
    }

    status = sgx_ecc256_compute_shared_dhkey(&privkey, &pubkey, &shared, ecc_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup;
    }

    cleanup:
    sgx_ecc256_close_context(ecc_handle);
    return status;
}

sgx_status_t ecdsa(sgx_ec256_private_t &privkey, const uint8_t *data, uint32_t size, sgx_ec256_signature_t &signature) {
    sgx_status_t status;
    sgx_ecc_state_handle_t ecc_handle = nullptr;

    status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup;
    }

    status = sgx_ecdsa_sign(data, size, &privkey, &signature, ecc_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup;
    }

    cleanup:
    sgx_ecc256_close_context(ecc_handle);
    return status;
}


sgx_status_t derive_key(
        const sgx_ec256_dh_shared_t *ss,
        const string &label,
        sgx_cmac_128bit_key_t *derived_key) {

#define EC_DERIVATION_BUFFER_SIZE(label_length) ((label_length) +4)

    sgx_status_t status;

    sgx_cmac_128bit_key_t cmac_key;
    sgx_cmac_128bit_key_t key_derive_key;

    if (!ss || !derived_key || label.empty()) {
        return SGX_ERROR_INVALID_PARAMETER;
    }


    /*check integer overflow */
    if (label.length() > EC_DERIVATION_BUFFER_SIZE(label.length())) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    memset(cmac_key, 0, SGX_CMAC_KEY_SIZE);
    status = sgx_rijndael128_cmac_msg(&cmac_key,
                                      (uint8_t *) ss,
                                      sizeof(sgx_ec256_dh_shared_t),
                                      (sgx_cmac_128bit_tag_t *) &key_derive_key);
    if (SGX_SUCCESS != status) {
        return status;
    }

    /* derivation_buffer = counter(0x01) || label || 0x00 || output_key_len(0x0080) */
    uint32_t derivation_buffer_length = EC_DERIVATION_BUFFER_SIZE(label.length());
    uint8_t *p_derivation_buffer = (uint8_t *) malloc(derivation_buffer_length);
    if (p_derivation_buffer == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    memset(p_derivation_buffer, 0, derivation_buffer_length);

    /*counter = 0x01 */
    p_derivation_buffer[0] = 0x01;
    /*label*/
    memcpy(&p_derivation_buffer[1], label.c_str(), label.length());
    /*output_key_len=0x0080*/
    uint16_t *key_len = (uint16_t *) &p_derivation_buffer[derivation_buffer_length - 2];
    *key_len = 0x0080;

    status = sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t *) &key_derive_key,
                                      p_derivation_buffer,
                                      derivation_buffer_length,
                                      (sgx_cmac_128bit_tag_t *) derived_key);

    free(p_derivation_buffer);
#undef EC_DERIVATION_BUFFER_SIZE
    return status;
}