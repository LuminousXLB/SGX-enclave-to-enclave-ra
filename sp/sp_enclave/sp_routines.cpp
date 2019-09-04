#include "sp_routines.h"
#include "crypto_utils.h"
#include <array>

using namespace std;

sgx_status_t private_proc_msg0(uint32_t msg0_extended_epid_group_id, attestation_status_t *att_status) {
    if (msg0_extended_epid_group_id == 0) {
        return SGX_SUCCESS;
    } else {
        att_status->error = attestation_status_t::MSG0_ExtendedEpidGroupIdIsNotZero;
        return SGX_ERROR_UNEXPECTED;
    }
}


sgx_status_t private_proc_msg1(ra_secret_t &secret, const sgx_ra_msg1_t &msg1, attestation_status_t *att_status) {
    /* All components of msg1 are in little-endian byte order. */

    sgx_status_t status;

    /* Verify A's EC key */
    bool valid;
    status = key_verify(msg1.g_a, valid);

    check_sgx_status(status);
    if (!valid) {
        att_status->error = attestation_status_t::MSG1_ClientEnclaveSessionKeyIsInvalid;
        return SGX_ERROR_UNEXPECTED;
    }

    memcpy(&secret.public_a, &msg1, sizeof(sgx_ra_msg1_t));

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
    sgx_ec256_signature_t sig_sp;
    array<sgx_ec256_public_t, 2> Gb_Ga{secret.public_b, secret.public_b};
    status = ecdsa(secret.private_b, (uint8_t *) &Gb_Ga[0], 2 * sizeof(sgx_ec256_public_t), sig_sp);
    check_sgx_status(status);

    /* CMACsmk */
    status = sgx_rijndael128_cmac_msg(&secret.smk, (uint8_t *) &msg2, 148, &msg2.mac);
    check_sgx_status(status);

    /* SigRL */
    msg2.sig_rl_size = sigrl.size();
//    memcpy(&msg2.sig_rl, sigrl.data(), sigrl.size());

    return status;
}

sgx_status_t private_proc_msg3(ra_secret_t &secret, const sgx_ra_msg3_t &msg3, attestation_status_t *att_status) {
    sgx_status_t status;

    if (memcmp(&secret.public_a, &msg3.g_a, sizeof(sgx_ec256_public_t)) != 0) {
        att_status->error = attestation_status_t::MSG3_ClientEnclaveSessingKeyMismatch;
        return SGX_ERROR_UNEXPECTED;
    }

#if 0

    /*
     * The quote size will be the total msg3 size - sizeof(sgx_ra_msg3_t)
     * since msg3.quote is a flexible array member.
     *
     * Total message size is sz/2 since the income message is in base16.
     */
    quote_sz = (uint32_t) ((sz / 2) - sizeof(sgx_ra_msg3_t));
    if (debug) {
        eprintf("+++ quote_sz= %lu bytes\n", quote_sz);
    }

    /* Make sure Ga matches msg1 */

    if (debug) {
        eprintf("+++ Verifying msg3.g_a matches msg1.g_a\n");
        eprintf("msg1.g_a.gx = %s\n", hexstring(msg3->g_a.gx, sizeof(msg1->g_a.gx)));
        eprintf("msg1.g_a.gy = %s\n", hexstring(&msg3->g_a.gy, sizeof(msg1->g_a.gy)));
        eprintf("msg3.g_a.gx = %s\n", hexstring(msg3->g_a.gx, sizeof(msg3->g_a.gx)));
        eprintf("msg3.g_a.gy = %s\n", hexstring(&msg3->g_a.gy, sizeof(msg3->g_a.gy)));
    }
    if (CRYPTO_memcmp(&msg3->g_a, &msg1->g_a, sizeof(sgx_ec256_public_t))) {
        eprintf("msg1.g_a and mgs3.g_a keys don't match\n");
        free(msg3);
        return 0;
    }

    /* Validate the MAC of M */

    cmac128(session->smk, (unsigned char *) &msg3->g_a, sizeof(sgx_ra_msg3_t) - sizeof(sgx_mac_t) + quote_sz,
            (unsigned char *) vrfymac);
    if (debug) {
        eprintf("+++ Validating MACsmk(M)\n");
        eprintf("msg3.mac   = %s\n", hexstring(msg3->mac, sizeof(sgx_mac_t)));
        eprintf("calculated = %s\n", hexstring(vrfymac, sizeof(sgx_mac_t)));
    }
    if (CRYPTO_memcmp(msg3->mac, vrfymac, sizeof(sgx_mac_t))) {
        eprintf("Failed to verify msg3 MAC\n");
        free(msg3);
        return 0;
    }

    /* Encode the report body as base64 */

    b64quote = base64_encode((char *) &msg3->quote, quote_sz);
    if (b64quote == NULL) {
        eprintf("Could not base64 encode the quote\n");
        free(msg3);
        return 0;
    }
    q = (sgx_quote_t *) msg3->quote;

    if (verbose) {

        edividerWithText("Msg3 Details (from Client)");
        eprintf("msg3.mac                 = %s\n", hexstring(&msg3->mac, sizeof(msg3->mac)));
        eprintf("msg3.g_a.gx              = %s\n", hexstring(msg3->g_a.gx, sizeof(msg3->g_a.gx)));
        eprintf("msg3.g_a.gy              = %s\n", hexstring(&msg3->g_a.gy, sizeof(msg3->g_a.gy)));
        eprintf("msg3.ps_sec_prop         = %s\n", hexstring(&msg3->ps_sec_prop, sizeof(msg3->ps_sec_prop)));
        eprintf("msg3.quote.version       = %s\n", hexstring(&q->version, sizeof(uint16_t)));
        eprintf("msg3.quote.sign_type     = %s\n", hexstring(&q->sign_type, sizeof(uint16_t)));
        eprintf("msg3.quote.epid_group_id = %s\n", hexstring(&q->epid_group_id, sizeof(sgx_epid_group_id_t)));
        eprintf("msg3.quote.qe_svn        = %s\n", hexstring(&q->qe_svn, sizeof(sgx_isv_svn_t)));
        eprintf("msg3.quote.pce_svn       = %s\n", hexstring(&q->pce_svn, sizeof(sgx_isv_svn_t)));
        eprintf("msg3.quote.xeid          = %s\n", hexstring(&q->xeid, sizeof(uint32_t)));
        eprintf("msg3.quote.basename      = %s\n", hexstring(&q->basename, sizeof(sgx_basename_t)));
        eprintf("msg3.quote.report_body   = %s\n", hexstring(&q->report_body, sizeof(sgx_report_body_t)));
        eprintf("msg3.quote.signature_len = %s\n", hexstring(&q->signature_len, sizeof(uint32_t)));
        eprintf("msg3.quote.signature     = %s\n", hexstring(&q->signature, q->signature_len));

        edividerWithText("isv_enclave Quote (base64) ==> Send to IAS");

        eputs(b64quote);

        eprintf("\n");
        edivider();
    }

    /* Verify that the EPID group ID in the quote matches the one from msg1 */

    if (debug) {
        eprintf("+++ Validating quote's epid_group_id against msg1\n");
        eprintf("msg1.egid = %s\n", hexstring(msg1->gid, sizeof(sgx_epid_group_id_t)));
        eprintf("msg3.quote.epid_group_id = %s\n", hexstring(&q->epid_group_id, sizeof(sgx_epid_group_id_t)));
    }

    if (memcmp(msg1->gid, &q->epid_group_id, sizeof(sgx_epid_group_id_t))) {
        eprintf("EPID GID mismatch. Attestation failed.\n");
        free(b64quote);
        free(msg3);
        return 0;
    }

#endif
}
