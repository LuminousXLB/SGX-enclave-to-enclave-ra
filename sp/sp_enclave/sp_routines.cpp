#include "sp_routines.h"
#include "crypto_utils.h"
#include <array>
#include "sp_enclave_t.h"
#include <mbusafecrt.h>

using namespace std;

void print_256_msg(const char *header, const uint32_t *data) {
    char buffer[256];

    sprintf_s(buffer, 256, "%s = %08x %08x %08x %08x %08x %08x %08x %08x", header,
              data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);

    ocall_eputs(__FILE__, __FUNCTION__, __LINE__, buffer);
}


sgx_status_t private_proc_msg0(uint32_t msg0_extended_epid_group_id, attestation_xstatus_t *att_status) {
#ifdef VERBOSE
    char buffer[256];
    sprintf_s(buffer, 256, "msg0_extended_epid_group_id=%08x", msg0_extended_epid_group_id);
    ocall_eputs(__FILE__, __FUNCTION__, __LINE__, buffer);
#endif

    if (msg0_extended_epid_group_id == 0) {
        return SGX_SUCCESS;
    } else {
        att_status->error = MSG0_ExtendedEpidGroupIdIsNotZero;
        return SGX_ERROR_UNEXPECTED;
    }
}


sgx_status_t private_proc_msg1(ra_secret_t &secret, const sgx_ra_msg1_t &msg1, attestation_xstatus_t *att_status) {
    /* All components of msg1 are in little-endian byte order. */

    sgx_status_t status;

    /* Verify A's EC key */
    bool valid;
    status = key_verify(msg1.g_a, valid);

    check_sgx_status(status);
    if (!valid) {
        att_status->error = MSG1_ClientEnclaveSessionKeyIsInvalid;
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
    status = derive_key(DERIVE_KEY_SMK, secret.shared_secret, secret.smk);
    check_sgx_status(status);

    return status;
}

sgx_status_t private_build_msg2(ra_secret_t &secret, const sgx_ec256_private_t &service_provider_privkey,
                                const sgx_spid_t &spid, const sgx_quote_sign_type_t &quote_type,
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
    array<sgx_ec256_public_t, 2> Gb_Ga{secret.public_b, secret.public_a};
    status = ecdsa(service_provider_privkey, (uint8_t *) &Gb_Ga[0], 2 * sizeof(sgx_ec256_public_t), msg2.sign_gb_ga);
    check_sgx_status(status);

    /* CMACsmk */
    status = sgx_rijndael128_cmac_msg(&secret.smk, (uint8_t *) &msg2, 148, &msg2.mac);
    check_sgx_status(status);

    /* SigRL */
    msg2.sig_rl_size = sigrl.size();
//    memcpy(&msg2.sig_rl, sigrl.data(), sigrl.size());

    return status;
}

sgx_status_t private_proc_msg3(ra_secret_t &secret, const sgx_ra_msg3_t &msg3, attestation_xstatus_t *att_status) {
    sgx_status_t status;
    sgx_quote_t &quote = *(sgx_quote_t *) msg3.quote;

    /* Verify that Ga in msg3 matches Ga in msg1 */
    if (memcmp(&secret.public_a, &msg3.g_a, sizeof(sgx_ec256_public_t)) != 0) {
        att_status->error = MSG3_ClientEnclaveSessingKeyMismatch;
        return SGX_ERROR_UNEXPECTED;
    }


    /* Verify that the EPID group ID in the quote matches the one from msg1 */
    if (memcmp(secret.client_gid, quote.epid_group_id, sizeof(sgx_epid_group_id_t)) != 0) {
        att_status->error = MSG3_EpidGroupIdMismatch;
        return SGX_ERROR_UNEXPECTED;
    }

    /* Verify CMACsmk of M */
    uint32_t quote_size = 436 + quote.signature_len;
    uint32_t M_length = sizeof(sgx_ra_msg3_t) - sizeof(sgx_mac_t) + quote_size;

    sgx_cmac_128bit_tag_t mac;
    status = sgx_rijndael128_cmac_msg(&secret.smk, (uint8_t *) &msg3.g_a, M_length, &mac);
    check_sgx_status(status);

    if (memcmp(msg3.mac, mac, SGX_CMAC_MAC_SIZE) != 0) {
        return SGX_ERROR_MAC_MISMATCH;
    }

    /* Verify that the first 64 bytes of the report data (inside the quote) are SHA256(Ga||Gb||VK)||0x00[32] */
    /* Derive VK */
    sgx_cmac_128bit_key_t vk;
    status = derive_key(DERIVE_KEY_VK, secret.shared_secret, vk);
    check_sgx_status(status);

    /* Build our plaintext */
    vector<uint8_t> plaintext;
    plaintext.reserve(sizeof(sgx_ec256_public_t) * 2 + sizeof(sgx_cmac_128bit_key_t));

    auto *ptr = (uint8_t *) &secret.public_a;
    plaintext.insert(plaintext.end(), ptr, ptr + sizeof(sgx_ec256_public_t));
    ptr = (uint8_t *) &secret.public_b;
    plaintext.insert(plaintext.end(), ptr, ptr + sizeof(sgx_ec256_public_t));
    ptr = (uint8_t *) &vk;
    plaintext.insert(plaintext.end(), ptr, ptr + sizeof(sgx_cmac_128bit_key_t));

    /* Calculate SHA-256 digest of (Ga || Gb || VK) */
    sgx_sha256_hash_t digest;
    status = sgx_sha256_msg(plaintext.data(), plaintext.size(), &digest);
    check_sgx_status(status);

    /* verify */
    vector<uint8_t> verification(begin(digest), end(digest));
    verification.resize(SGX_REPORT_DATA_SIZE, 0);

    uint8_t *report_data = quote.report_body.report_data.d;
    if (memcmp(verification.data(), report_data, SGX_REPORT_DATA_SIZE) != 0) {
        att_status->error = MSG3_InvalidReportData;
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}


#if 0
// whether trust

        /*
         * This sample's attestion policy is based on isvEnclaveQuoteStatus:
         *
         *   1) if "OK" then return "Trusted"
         *
          *   2) if "CONFIGURATION_NEEDED" then return
         *       "NotTrusted_ItsComplicated" when in --strict-trust-mode
         *        and "Trusted_ItsComplicated" otherwise
         *
         *   3) return "NotTrusted" for all other responses
         *
         *
         * ItsComplicated means the client is not trusted, but can
         * conceivable take action that will allow it to be trusted
         * (such as a BIOS update).
          */

        /*
         * Simply check to see if status is OK, else enclave considered
         * not trusted
         */

        memset(msg4, 0, sizeof(ra_msg4_t));

        if (verbose) edividerWithText("ISV isv_enclave Trust Status");

        if (!(reportObj["isvEnclaveQuoteStatus"].ToString().compare("OK"))) {
            msg4->status.trust = Trusted;
            if (verbose) eprintf("isv_enclave TRUSTED\n");
        } else if (!(reportObj["isvEnclaveQuoteStatus"].ToString().compare("CONFIGURATION_NEEDED"))) {
            if (strict_trust) {
                msg4->status.trust = NotTrusted_Complicated;
                if (verbose)
                    eprintf("isv_enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
                            reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
            } else {
                if (verbose)
                    eprintf("isv_enclave TRUSTED and COMPLICATED - Reason: %s\n",
                            reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
                msg4->status.trust = Trusted_Complicated;
            }
        } else if (!(reportObj["isvEnclaveQuoteStatus"].ToString().compare("GROUP_OUT_OF_DATE"))) {
            msg4->status.trust = NotTrusted_Complicated;
            if (verbose)
                eprintf("isv_enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
                        reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
        } else {
            msg4->status.trust = NotTrusted;
            if (verbose)
                eprintf("isv_enclave NOT TRUSTED - Reason: %s\n",
                        reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
        }


        /* Check to see if a platformInfoBlob was sent back as part of the
         * response */

        if (!reportObj["platformInfoBlob"].IsNull()) {
            if (verbose) eprintf("A Platform Info Blob (PIB) was provided by the IAS\n");

            /* The platformInfoBlob has two parts, a TVL Header (4 bytes),
             * and TLV Payload (variable) */

            string pibBuff = reportObj["platformInfoBlob"].ToString();

            /* remove the TLV Header (8 base16 chars, ie. 4 bytes) from
             * the PIB Buff. */

            pibBuff.erase(pibBuff.begin(), pibBuff.begin() + (4 * 2));

            int ret = from_hexstring((unsigned char *) &msg4->platformInfoBlob,
                                     pibBuff.c_str(), pibBuff.length() / 2);
        } else {
            if (verbose) eprintf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
        }
#endif


#if 0


#ifndef _WIN32
/* Windows implementation is not available yet */

        if (!verify_enclave_identity(config->req_mrsigner,
                                     config->req_isv_product_id, config->min_isvsvn,
                                     config->allow_debug_enclave, r)) {

            eprintf("Invalid enclave.\n");
            msg4->status = NotTrusted;
        }
#endif

        if (verbose) {
            edivider();

            // The enclave report is valid so we can trust the report
            // data.

            edividerWithText("isv_enclave Report Details");

            eprintf("cpu_svn     = %s\n",
                    hexstring(&r->cpu_svn, sizeof(sgx_cpu_svn_t)));
            eprintf("misc_select = %s\n",
                    hexstring(&r->misc_select, sizeof(sgx_misc_select_t)));
            eprintf("attributes  = %s\n",
                    hexstring(&r->attributes, sizeof(sgx_attributes_t)));
            eprintf("mr_enclave  = %s\n",
                    hexstring(&r->mr_enclave, sizeof(sgx_measurement_t)));
            eprintf("mr_signer   = %s\n",
                    hexstring(&r->mr_signer, sizeof(sgx_measurement_t)));
            eprintf("isv_prod_id = %04hX\n", r->isv_prod_id);
            eprintf("isv_svn     = %04hX\n", r->isv_svn);
            eprintf("report_data = %s\n",
                    hexstring(&r->report_data, sizeof(sgx_report_data_t)));
        }


        edividerWithText("Copy/Paste Msg4 Below to Client");

        /* Serialize the members of the Msg4 structure independently */
        /* vs. the entire structure as one send_msg() */

        msgio->send_partial(&msg4->status, sizeof(msg4->status));
        msgio->send(&msg4->platformInfoBlob, sizeof(msg4->platformInfoBlob));

        fsend_msg_partial(fplog, &msg4->status, sizeof(msg4->status));
        fsend_msg(fplog, &msg4->platformInfoBlob,
                  sizeof(msg4->platformInfoBlob));
        edivider();

        /*
         * If the enclave is trusted, derive the MK and SK. Also get
         * SHA256 hashes of these so we can verify there's a shared
         * secret between us and the client.
         */

        if (msg4->status == Trusted) {
            unsigned char hashmk[32], hashsk[32];

            if (debug) eprintf("+++ Deriving the MK and SK\n");
            cmac128(session->kdk, (unsigned char *) ("\x01MK\x00\x80\x00"),
                    6, session->mk);
            cmac128(session->kdk, (unsigned char *) ("\x01SK\x00\x80\x00"),
                    6, session->sk);

            sha256_digest(session->mk, 16, hashmk);
            sha256_digest(session->sk, 16, hashsk);

            if (verbose) {
                if (debug) {
                    eprintf("MK         = %s\n", hexstring(session->mk, 16));
                    eprintf("SK         = %s\n", hexstring(session->sk, 16));
                }
                eprintf("SHA256(MK) = %s\n", hexstring(hashmk, 32));
                eprintf("SHA256(SK) = %s\n", hexstring(hashsk, 32));
            }
        }

    }
#endif