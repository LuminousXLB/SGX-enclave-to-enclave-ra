/*

Copyright 2019 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/


#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <sgx_key_exchange.h>
#include "common.h"
#include "fileio.h"
#include "byteorder.h"
#include "protocol.h"
#include "base64.h"
#include "ias_request.h"
#include "logfile.h"
#include "ias.h"
#include "enclave_verify.h"
#include "sp_enclave_u.h"
#include "tmp_config.h"

using namespace std;

#include <map>
#include <string>
#include <iostream>
#include <algorithm>
#include <sgx_utils/sgx_utils.h>
#include <crypto.h>
#include "key_exchange_message.h"

void cleanup_and_exit(int signo);

#if 0
int process_msg01(MsgIO *msg, IAS_Connection *ias, sgx_ra_msg1_t *msg1, sgx_ra_msg2_t *msg2, char **sigrl,
                  config_t *config, ra_session_t *session);

int process_msg3(MsgIO *msg, IAS_Connection *ias, sgx_ra_msg1_t *msg1, ra_msg4_t *msg4, config_t *config,
                 ra_session_t *session);
# endif
sgx_enclave_id_t global_eid;
char debug = 0;
char verbose = 0;
MsgIO *msgio = nullptr;
IAS_Connection *ias = nullptr;
extern sgx_spid_t SP_SPID;
extern sgx_quote_sign_type_t SP_QUOTE_TYPE;
config_t config;


void loop_routine() {
    sgx_status_t status;
    sgx_status_t sgx_status;
    attestation_xstatus_t att_status;

    /* Read message 0 and 1 */
    vector<uint8_t> msg01_buffer;
    recv_msg01(msg01_buffer);

    eprintf("[%4d] %s: %s\n", __LINE__, __FILE__, __FUNCTION__);
    hexdump(stderr, msg01_buffer.data(), msg01_buffer.size());

    const auto *msg01 = (const ra_msg01_t *) msg01_buffer.data();
    ra_msg4_t msg4;
    status = ecall_do_attestation(global_eid, &sgx_status, *msg01, &msg4, &att_status);
    eprintf("[%4d] %s: %s\n", __LINE__, __FILE__, __FUNCTION__);


    if (att_status.error != NoErrorInformation) {
//        TODO: print error information
        eprintf("Attestation Error: %d\n", att_status.error);
    }

    if (status != SGX_SUCCESS) {
        goto disconnect;
    }

    if (sgx_status != SGX_SUCCESS) {
        goto disconnect;
    }

//    TODO: Send message4

#if 0

    /* Read message 3, and generate message 4 */

    if (!process_msg3(msgio, ias, &msg1, &msg4, &config, &session)) {
        eprintf("error processing msg3\n");
        goto disconnect;
    }
#endif
    disconnect:

    if (status != SGX_SUCCESS) {
        print_error_message(status);
        exit(EXIT_FAILURE);
    }

    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        exit(EXIT_FAILURE);
    }

    msgio->disconnect();
}

int main(int argc, char *argv[]) {

    /* Create a logfile to capture debug output and actual msg data */

    fplog = create_logfile("sp.log");
    fprintf(fplog, "Server log started\n");

    /* Parse command line options */

    if (!parse_command_line_options(argc, argv, config)) {
        return EXIT_FAILURE;
    }

    /* Initialize out support libraries */

    crypto_init();

    /* Initialize our IAS request object */

    if (!ias_connection_init(config)) {
        return EXIT_FAILURE;
    }

    /* Get our message IO object. */
    if (!msgio_init(config)) {
        return EXIT_FAILURE;
    }

#ifndef _WIN32
    /*
     * Install some rudimentary signal handlers. We just want to make
     * sure we gracefully shutdown the listen socket before we exit
     * to avoid "address already in use" errors on startup.
     */
    struct sigaction sact;

    sigemptyset(&sact.sa_mask);
    sact.sa_flags = 0;
    sact.sa_handler = &cleanup_and_exit;

    if (sigaction(SIGHUP, &sact, NULL) == -1) perror("sigaction: SIGHUP");
    if (sigaction(SIGINT, &sact, NULL) == -1) perror("sigaction: SIGHUP");
    if (sigaction(SIGTERM, &sact, NULL) == -1) perror("sigaction: SIGHUP");
    if (sigaction(SIGQUIT, &sact, NULL) == -1) perror("sigaction: SIGHUP");
#endif

//    Launch the enclave
    if (initialize_enclave(&global_eid, "sp_enclave.token", "sp_enclave.signed.so") < 0) {
        printf("Fail to initialize enclave.\n");
        return 1;
    }

    /* If we're running in server mode, we'll block here.  */

    while (msgio->server_loop()) {
        loop_routine();
    }

    crypto_destroy();

    return 0;
}

#if 0

int process_msg3(MsgIO *msgio, IAS_Connection *ias, sgx_ra_msg1_t *msg1, ra_msg4_t *msg4, config_t *config,
                 ra_session_t *session) {
    sgx_ra_msg3_t *msg3;
    size_t blen = 0;
    size_t sz;
    int rv;
    uint32_t quote_sz;
    char *buffer = NULL;
    char *b64quote;
    sgx_mac_t vrfymac;
    sgx_quote_t *q;

    /*
     * Read our incoming message. We're using base16 encoding/hex strings
     * so we should end up with sizeof(msg)*2 bytes.
     */

    fprintf(stderr, "Waiting for msg3\n");

    /*
     * Read message 3
     *
     * CMACsmk(M) || M
     *
     * where
     *
     * M = ga || PS_SECURITY_PROPERTY || QUOTE
     *
     */

    rv = msgio->read((void **) &msg3, &sz);
    if (rv == -1) {
        eprintf("system error reading msg3\n");
        return 0;
    } else if (rv == 0) {
        eprintf("protocol error reading msg3\n");
        return 0;
    }
    if (debug) {
        eprintf("+++ read %lu bytes\n", sz);
    }

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


    if (get_attestation_report(ias, config->apiver, b64quote, msg3->ps_sec_prop, msg4, config->strict_trust)) {

        unsigned char vfy_rdata[64];
        unsigned char msg_rdata[144]; /* for Ga || Gb || VK */

        sgx_report_body_t *r = (sgx_report_body_t *) &q->report_body;

        memset(vfy_rdata, 0, 64);

        /*
         * Verify that the first 64 bytes of the report data (inside
         * the quote) are SHA256(Ga||Gb||VK) || 0x00[32]
         *
         * VK = CMACkdk( 0x01 || "VK" || 0x00 || 0x80 || 0x00 )
         *
         * where || denotes concatenation.
         */

        /* Derive VK */

        cmac128(session->kdk, (unsigned char *) ("\x01VK\x00\x80\x00"),
                6, session->vk);

        /* Build our plaintext */

        memcpy(msg_rdata, session->g_a, 64);
        memcpy(&msg_rdata[64], session->g_b, 64);
        memcpy(&msg_rdata[128], session->vk, 16);

        /* SHA-256 hash */

        sha256_digest(msg_rdata, 144, vfy_rdata);

        if (verbose) {
            edividerWithText("isv_enclave Report Verification");
            if (debug) {
                eprintf("VK                 = %s\n",
                        hexstring(session->vk, 16));
            }
            eprintf("SHA256(Ga||Gb||VK) = %s\n",
                    hexstring(vfy_rdata, 32));
            eprintf("report_data[64]    = %s\n",
                    hexstring(&r->report_data, 64));
        }

        if (CRYPTO_memcmp((void *) vfy_rdata, (void *) &r->report_data,
                          64)) {

            eprintf("Report verification failed.\n");
            free(b64quote);
            free(msg3);
            return 0;
        }

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

    } else {
        eprintf("Attestation failed\n");
        free(msg3);
        free(b64quote);
        return 0;
    }

    free(b64quote);
    free(msg3);

    return 1;
}

/*
 * Read and process message 0 and message 1. These messages are sent by
 * the client concatenated together for efficiency (msg0||msg1).
 */

int process_msg01(MsgIO *msgio, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
                  sgx_ra_msg2_t *msg2, char **sigrl, config_t *config, ra_session_t *session) {
    ra_msg01_t *msg01;
    size_t blen = 0;
    char *buffer = NULL;
    unsigned char digest[32], r[32], s[32], gb_ga[128];
    EVP_PKEY *Gb;
    int rv;

    memset(msg2, 0, sizeof(sgx_ra_msg2_t));

    /*
     * Read our incoming message. We're using base16 encoding/hex strings
     * so we should end up with sizeof(msg)*2 bytes.
     */

    fprintf(stderr, "Waiting for msg0||msg1\n");

    rv = msgio->read((void **) &msg01, NULL);
    if (rv == -1) {
        eprintf("system error reading msg0||msg1\n");
        return 0;
    } else if (rv == 0) {
        eprintf("protocol error reading msg0||msg1\n");
        return 0;
    }

    if (verbose) {
        edividerWithText("Msg0 Details (from Client)");
        eprintf("msg0.extended_epid_group_id = %u\n", msg01->msg0_extended_epid_group_id);
        edivider();
    }

    /* According to the Intel SGX Developer Reference
     * "Currently, the only valid extended Intel(R) EPID group ID is zero. The
     * server should verify this value is zero. If the Intel(R) EPID group ID
     * is not zero, the server aborts remote attestation"
     */

    if (msg01->msg0_extended_epid_group_id != 0) {
        eprintf("msg0 Extended Epid Group ID is not zero.  Exiting.\n");
        free(msg01);
        return 0;
    }

    // Pass msg1 back to the pointer in the caller func
    memcpy(msg1, &msg01->msg1, sizeof(sgx_ra_msg1_t));

    if (verbose) {
        edividerWithText("Msg1 Details (from Client)");
        eprintf("msg1.g_a.gx = %s\n", hexstring(&msg1->g_a.gx, sizeof(msg1->g_a.gx)));
        eprintf("msg1.g_a.gy = %s\n", hexstring(&msg1->g_a.gy, sizeof(msg1->g_a.gy)));
        eprintf("msg1.gid    = %s\n", hexstring(&msg1->gid, sizeof(msg1->gid)));
        edivider();
    }

    /* Generate our session key */

    if (debug) eprintf("+++ generating session key Gb\n");

    Gb = key_generate();
    if (Gb == NULL) {
        eprintf("Could not create a session key\n");
        free(msg01);
        return 0;
    }

    /*
     * Derive the KDK from the key (Ga) in msg1 and our session key.
     * An application would normally protect the KDK in memory to
     * prevent trivial inspection.
     */

    if (debug) eprintf("+++ deriving KDK\n");

    if (!derive_kdk(Gb, session->kdk, msg1->g_a, config)) {
        eprintf("Could not derive the KDK\n");
        free(msg01);
        return 0;
    }

    if (debug) eprintf("+++ KDK = %s\n", hexstring(session->kdk, 16));

    /*
      * Derive the SMK from the KDK
     * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00)
     */

    if (debug) eprintf("+++ deriving SMK\n");

    cmac128(session->kdk, (unsigned char *) ("\x01SMK\x00\x80\x00"), 7,
            session->smk);

    if (debug) eprintf("+++ SMK = %s\n", hexstring(session->smk, 16));

    /*
     * Build message 2
     *
     * A || CMACsmk(A) || SigRL
     * (148 + 16 + SigRL_length bytes = 164 + SigRL_length bytes)
     *
     * where:
     *
     * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga)
     *          (64 + 16 + 2 + 2 + 64 = 148 bytes)
     * Ga     = Client enclave's session key
     *          (32 bytes)
     * Gb     = Service Provider's session key
     *          (32 bytes)
     * SPID   = The Service Provider ID, issued by Intel to the vendor
     *          (16 bytes)
     * TYPE   = Quote type (0= linkable, 1= linkable)
     *          (2 bytes)
     * KDF-ID = (0x0001= CMAC entropy extraction and key derivation)
     *          (2 bytes)
     * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
     *          (signed with the Service Provider's private key)
     *          (64 bytes)
     *
     * CMACsmk= AES-128-CMAC(A)
     *          (16 bytes)
     *
     * || denotes concatenation
     *
     * Note that all key components (Ga.x, etc.) are in little endian
     * format, meaning the byte streams need to be reversed.
     *
     * For SigRL, send:
     *
     *  SigRL_size || SigRL_contents
     *
     * where sigRL_size is a 32-bit uint (4 bytes). This matches the
     * structure definition in sgx_ra_msg2_t
     */

    key_to_sgx_ec256(&msg2->g_b, Gb);
    memcpy(&msg2->spid, &config->spid, sizeof(sgx_spid_t));
    msg2->quote_type = config->quote_type;
    msg2->kdf_id = 1;

    /* Get the sigrl */

    if (!get_sigrl(ias, config->apiver, msg1->gid, sigrl, &msg2->sig_rl_size)) {

        eprintf("could not retrieve the sigrl\n");
        free(msg01);
        return 0;
    }

    memcpy(gb_ga, &msg2->g_b, 64);
    memcpy(session->g_b, &msg2->g_b, 64);

    memcpy(&gb_ga[64], &msg1->g_a, 64);
    memcpy(session->g_a, &msg1->g_a, 64);

    if (debug) eprintf("+++ GbGa = %s\n", hexstring(gb_ga, 128));

    ecdsa_sign(gb_ga, 128, config->service_private_key, r, s, digest);
    reverse_bytes(&msg2->sign_gb_ga.x, r, 32);
    reverse_bytes(&msg2->sign_gb_ga.y, s, 32);

    if (debug) {
        eprintf("+++ sha256(GbGa) = %s\n", hexstring(digest, 32));
        eprintf("+++ r = %s\n", hexstring(r, 32));
        eprintf("+++ s = %s\n", hexstring(s, 32));
    }

    /* The "A" component is conveniently at the start of sgx_ra_msg2_t */

    cmac128(session->smk, (unsigned char *) msg2, 148,
            (unsigned char *) &msg2->mac);

    if (verbose) {
        edividerWithText("Msg2 Details");
        eprintf("msg2.g_b.gx      = %s\n", hexstring(&msg2->g_b.gx, sizeof(msg2->g_b.gx)));
        eprintf("msg2.g_b.gy      = %s\n", hexstring(&msg2->g_b.gy, sizeof(msg2->g_b.gy)));
        eprintf("msg2.spid        = %s\n", hexstring(&msg2->spid, sizeof(msg2->spid)));
        eprintf("msg2.quote_type  = %s\n", hexstring(&msg2->quote_type, sizeof(msg2->quote_type)));
        eprintf("msg2.kdf_id      = %s\n", hexstring(&msg2->kdf_id, sizeof(msg2->kdf_id)));
        eprintf("msg2.sign_ga_gb  = %s\n", hexstring(&msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga)));
        eprintf("msg2.mac         = %s\n", hexstring(&msg2->mac, sizeof(msg2->mac)));
        eprintf("msg2.sig_rl_size = %s\n", hexstring(&msg2->sig_rl_size, sizeof(msg2->sig_rl_size)));
        edivider();
    }

    free(msg01);

    return 1;
}
#endif

/* We don't care which signal it is since we're shutting down regardless */

void cleanup_and_exit(int signo) {
    /* Signal-safe, and we don't care if it fails or is a partial write. */

    ssize_t bytes = write(STDERR_FILENO, "\nterminating\n", 13);

    /*
     * This destructor consists of signal-safe system calls (close,
     * shutdown).
     */

    delete msgio;

    exit(1);
}


/* vim: ts=4: */

