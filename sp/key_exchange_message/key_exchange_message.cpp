#include "key_exchange_message.h"

int recv_msg01(ra_msg01_t *msg01) {
    fprintf(stderr, "Waiting for msg0||msg1\n");

    int rv = msgio->read((void **) &msg01, nullptr);

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
        eprintf("msg1.g_a.gx = %s\n", hexstring(&msg01->msg1.g_a.gx, sizeof(msg01->msg1.g_a.gx)));
        eprintf("msg1.g_a.gy = %s\n", hexstring(&msg01->msg1.g_a.gy, sizeof(msg01->msg1.g_a.gy)));
        eprintf("msg1.gid    = %s\n", hexstring(&msg01->msg1.gid, sizeof(msg01->msg1.gid)));
        edivider();
    }

    return rv;
}

int recv_msg3(sgx_ra_msg3_t *msg3, size_t size) {
    fprintf(stderr, "Waiting for msg3\n");

    int rv = msgio->read((void **) &msg3, &size);

    if (rv == -1) {
        eprintf("system error reading msg3\n");
        return 0;
    } else if (rv == 0) {
        eprintf("protocol error reading msg3\n");
        return 0;
    }
    if (debug) {
        eprintf("+++ read %lu bytes\n", size);
    }

    return rv;
}