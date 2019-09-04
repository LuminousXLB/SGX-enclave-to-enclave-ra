#include "sp_routines.h"
#include "crypto_utils.h"

using namespace std;

sgx_status_t private_proc_msg0(uint32_t msg0_extended_epid_group_id, attestation_status_t *att_status) {
    if (msg0_extended_epid_group_id == 0) {
        return SGX_SUCCESS;
    } else {
        att_status->error = attestation_status_t::MSG0_ExtendedEpidGroupIdIsNotZero;
        return SGX_ERROR_UNEXPECTED;
    }
}


sgx_status_t private_proc_msg1(ra_secret_t &secret, sgx_ra_msg1_t *msg1, attestation_status_t *att_status) {
    /* All components of msg1 are in little-endian byte order. */

    sgx_status_t status;

    /* Verify A's EC key */
    bool valid;
    status = key_verify(msg1->g_a, valid);

    check_sgx_status(status);
    if (!valid) {
        att_status->error = attestation_status_t::MSG1_ClientEnclaveSessionKeyIsInvalid;
        return SGX_ERROR_UNEXPECTED;
    }

    memcpy(&secret.public_a, msg1, sizeof(sgx_ra_msg1_t));

    /* Generate a random EC key using the P-256 curve. This key will become Gb. */
    status = key_generate(secret.private_b, secret.public_b);
    check_sgx_status(status);

    /* Derive the key derivation key (KDK) from Ga and Gb: */
    status = ecdh_shared_secret(secret.private_b, secret.public_a, secret.shared_secret);
    check_sgx_status(status);

    /* Derive SMK */
    status = derive_key(&secret.shared_secret, "SMK", &secret.smk);
    check_sgx_status(status);

    return status;
}

sgx_status_t private_build_msg2(ra_secret_t &secret, const sgx_spid_t &spid, const sgx_quote_sign_type_t &quote_type,
                                const vector<uint8_t> &sigrl, sgx_ra_msg2_t &msg2) {
    sgx_status_t status;

    /* Gb */
    memcpy(&msg2.g_b, &secret.public_b, sizeof(sgx_ec256_public_t));

    /* SPID */
    memcpy(&msg2.spid, &spid, sizeof(sgx_spid_t));

    /* Quote Type */
    msg2.quote_type = (quote_type == SGX_UNLINKABLE_SIGNATURE) ? 0 : 1;

    /* KDF-ID */
    msg2.kdf_id = 1;

    /* SigSP */
    vector<uint8_t> Gb_Ga(SGX_ECP256_KEY_SIZE * 2, 0);
    memcpy(&Gb_Ga[0], &secret.public_b, SGX_ECP256_KEY_SIZE);
    memcpy(&Gb_Ga[SGX_ECP256_KEY_SIZE], &secret.public_b, SGX_ECP256_KEY_SIZE);

    sgx_ec256_signature_t sig_sp;
    status = ecdsa(secret.private_b, Gb_Ga, sig_sp);
    check_sgx_status(status);

    /* CMACsmk */
    sgx_rijndael128_cmac_msg(&secret.smk, (uint8_t *) &msg2, 148, &msg2.mac);

    /* SigRL */
    msg2.sig_rl_size = sigrl.size();
    memcpy(&msg2.sig_rl, sigrl.data(), sigrl.size());
}