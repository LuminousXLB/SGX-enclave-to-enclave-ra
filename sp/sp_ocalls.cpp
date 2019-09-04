#include <cstring>
#include "key_exchange_message.h"
#include "sp_enclave_u.h"
#include "ias_request.h"
#include "msgio.h"
#include "ias.h"
#include "tmp_config.h"
#include <string>

extern MsgIO *msgio;
extern IAS_Connection *ias;
extern config_t config;

using namespace std;
string sigrl;
vector<uint8_t> msg3;

void ocall_pre_get_sigrl(sgx_epid_group_id_t gid, sgx_spid_t *spid, sgx_quote_sign_type_t *quote_type,
                         uint32_t *sigrl_size) {

    /* copy spid, quote_type */
    memcpy(spid, &config.spid, sizeof(sgx_spid_t));
    *quote_type = config.quote_type;

    /* get sigrl */
    if (get_sigrl(ias, IAS_API_DEF_VERSION, gid, sigrl) == IAS_OK) {
        *sigrl_size = sigrl.length();
    } else {
        eprintf("could not retrieve the sigrl\n");
        exit(-1);
    }
}

void ocall_get_sigrl(uint32_t sigrl_size, uint8_t *sigrl_buffer) {
    if (sigrl_size < sigrl.length()) {
        exit(-1);
    } else {
        strcpy((char *) sigrl_buffer, sigrl.c_str());
    }
}

void ocall_pre_get_msg3(sgx_ra_msg2_t msg2, uint32_t *msg3_length) {
    send_msg2(msg2, (uint8_t *) sigrl.data());

    sgx_ra_msg3_t *buffer;
    uint32_t length;

    recv_msg3(buffer, length);

    auto *ptr = (uint8_t *) buffer;
    msg3.assign(ptr, ptr + length);
    *msg3_length = msg3.size();

    free(buffer);
}

void ocall_get_msg3(uint32_t msg3_size, uint8_t *msg3_buffer) {
    if (msg3_size < msg3.size()) {
        exit(-1);
    } else {
        memcpy(msg3_buffer, msg3.data(), msg3.size());
    }
}

void ocall_pre_get_attestation() {
    uint8_t *quote = ((sgx_ra_msg3_t *) msg3.data())->quote;
    uint32_t quote_size = 436 + ((sgx_quote_t *) quote)->signature_len;

    string content;
    vector<string> messages;

    get_attestation_report(ias, IAS_API_DEF_VERSION, vector<uint8_t>(quote, quote + quote_size), content, messages);

#if 0

    /* Verify that the EPID group ID in the quote matches the one from msg1 */
    if (memcmp(msg1->gid, &q->epid_group_id, sizeof(sgx_epid_group_id_t))) {
        eprintf("EPID GID mismatch. Attestation failed.\n");
        free(b64quote);
        free(msg3);
        return 0;
    }


    if (get_attestation_report(ias, config->apiver, b64quote, msg3->ps_sec_prop, msg4, config->strict_trust)) {

        /*
         * The service provider must validate that the enclave
         * report is from an enclave that they recognize. Namely,
         * that the MRSIGNER matches our signing key, and the MRENCLAVE
         * hash matches an enclave that we compiled.
         *
         * Other policy decisions might include examining ISV_SVN to
         * prevent outdated/deprecated software from successfully
         * attesting, and ensuring the TCB is not out of date.
         *
         * A real-world service provider might allow multiple ISV_SVN
         * values, but for this sample we only allow the enclave that
         * is compiled.
         */

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
}