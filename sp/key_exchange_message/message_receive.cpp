#include "key_exchange_message.h"
#include <vector>
#include <cstring>

using namespace std;

int recv_msg01(vector<uint8_t> &msg01_buf) {
    fprintf(stderr, "Waiting for msg0||msg1\n");

    int rv = msgio->read(msg01_buf);

    const auto *msg01 = (const ra_msg01_t *) msg01_buf.data();

    eprintf("[%4d] %s: %s\n", __LINE__, __FILE__, __FUNCTION__);
    hexdump(stderr, (uint8_t *) &msg01, sizeof(ra_msg01_t));

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

    if (verbose) {
        edividerWithText("Msg1 Details (from Client)");
        eprintf("msg1.g_a.gx = %s\n", hexstring(&msg01->msg1.g_a.gx, SGX_ECP256_KEY_SIZE));
        eprintf("msg1.g_a.gy = %s\n", hexstring(&msg01->msg1.g_a.gy, SGX_ECP256_KEY_SIZE));
        eprintf("msg1.gid    = %s\n", hexstring(&msg01->msg1.gid, sizeof(sgx_epid_group_id_t)));
        edivider();
    }

    return rv;
}

int recv_msg3(sgx_ra_msg3_t *&msg3, uint32_t &msg3_length) {
    fprintf(stderr, "Waiting for msg3\n");

    int rv = msgio->read((void **) &msg3, (size_t *) &msg3_length);

    if (rv == -1) {
        eprintf("system error reading msg3\n");
        return 0;
    } else if (rv == 0) {
        eprintf("protocol error reading msg3\n");
        return 0;
    }
    if (debug) {
        eprintf("+++ read %lu bytes\n", msg3_length);
    }

    if (verbose) {

        edividerWithText("Msg3 Details (from Client)");
        eprintf("msg3.mac                 = %s\n", hexstring(&msg3->mac, sizeof(msg3->mac)));
        eprintf("msg3.g_a.gx              = %s\n", hexstring(msg3->g_a.gx, sizeof(msg3->g_a.gx)));
        eprintf("msg3.g_a.gy              = %s\n", hexstring(&msg3->g_a.gy, sizeof(msg3->g_a.gy)));
        eprintf("msg3.ps_sec_prop         = %s\n", hexstring(&msg3->ps_sec_prop, sizeof(msg3->ps_sec_prop)));

        sgx_quote_t *q = (sgx_quote_t *) msg3->quote;
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

        eprintf("\n");
        edivider();
    }

    return rv;
}