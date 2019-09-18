//
// Created by ncl on 18/9/19.
//

#include <tlibc/mbusafecrt.h>
#include "p2p_enclave_t.h"
#include "sp_routines.h"
#include "utils/crypto_utils.h"

#define COUNTER_LENGTH_IN_BYTES 16

extern ra_secret_t secret;
sgx_ra_key_128_t final_key[2];

sgx_status_t ecall_init_share_key(sgx_ra_context_t ctx, sgx_sha256_hash_t *hash) {
    sgx_status_t status = SGX_SUCCESS;

    sgx_ra_key_128_t key_arr1[2];

    status = sgx_ra_get_keys(ctx, SGX_RA_KEY_MK, &key_arr1[0]);
    check_sgx_status(status);

    status = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &key_arr1[1]);
    check_sgx_status(status);

    sgx_ra_key_128_t key_arr2[2];

    status = derive_key(DERIVE_KEY_MK, secret.shared_secret, key_arr2[0]);
    check_sgx_status(status);

    status = derive_key(DERIVE_KEY_SK, secret.shared_secret, key_arr2[1]);
    check_sgx_status(status);


    /* Now generate a SHA hash */
    sgx_sha256_hash_t hash1;
    status = sgx_sha256_msg((uint8_t *) key_arr1, sizeof(sgx_ra_key_128_t) * 2, &hash1);
    check_sgx_status(status);

    sgx_sha256_hash_t hash2;
    status = sgx_sha256_msg((uint8_t *) key_arr2, sizeof(sgx_ra_key_128_t) * 2, &hash2);
    check_sgx_status(status);


    /* Let's be thorough */
    auto *ptr0 = reinterpret_cast<uint8_t *>(&final_key[0]);
    for (size_t i = 0; i < SGX_SHA256_HASH_SIZE; i++) {
        ptr0[i] = hash1[i] ^ hash2[i];
    }

    status = sgx_sha256_msg((uint8_t *) final_key, sizeof(sgx_ra_key_128_t) * 2, hash);
    check_sgx_status(status);

    return status;
}

/*
 * Encrypt & Decrypt using AES-CTR-128
 */
sgx_status_t aes_ctr_128_encrypt(uint8_t *buffer, uint32_t length, uint8_t nonce[COUNTER_LENGTH_IN_BYTES]) {
    uint8_t counter[COUNTER_LENGTH_IN_BYTES];

    sgx_status_t status = sgx_read_rand(counter, COUNTER_LENGTH_IN_BYTES);
    if (status != SGX_SUCCESS) {
        return status;
    }

    memcpy_s((void *) nonce, COUNTER_LENGTH_IN_BYTES, counter, COUNTER_LENGTH_IN_BYTES);
    uint8_t *ciphertext = (uint8_t *) malloc(length);

    status = sgx_aes_ctr_encrypt(final_key, buffer, length, counter, COUNTER_LENGTH_IN_BYTES * 8, ciphertext);
    if (status != SGX_SUCCESS) {
        return status;
    }

    memcpy_s((void *) buffer, length, ciphertext, length);
    memset((void *) ciphertext, 0, length);

    return status;
}

sgx_status_t aes_ctr_128_decrypt(uint8_t *buffer, uint32_t length, uint8_t nonce[COUNTER_LENGTH_IN_BYTES]) {
    uint8_t counter[COUNTER_LENGTH_IN_BYTES];
    memcpy_s(counter, COUNTER_LENGTH_IN_BYTES, (void *) nonce, COUNTER_LENGTH_IN_BYTES);

    uint8_t *plaintext = (uint8_t *) malloc(length);

    sgx_status_t status = sgx_aes_ctr_decrypt(final_key, buffer, length, counter, COUNTER_LENGTH_IN_BYTES * 8,
                                              plaintext);
    if (status != SGX_SUCCESS) {
        return status;
    }

    memcpy_s((void *) buffer, length, plaintext, length);
    memset((void *) plaintext, 0, length);

    return status;
}