#include "key_exchange_message.h"

void send_msg2(const sgx_ra_msg2_t &msg2, const uint8_t *sigrl) {
    /*
     * sgx_ra_msg2_t is a struct with a flexible array member at the
     * end (defined as uint8_t sig_rl[]). We could go to all the
     * trouble of building a byte array large enough to hold the
     * entire struct and then cast it as (sgx_ra_msg2_t) but that's
     * a lot of work for no gain when we can just send the fixed
     * portion and the array portion by hand.
     */

    if (verbose) {
        dividerWithText(stderr, "Copy/Paste Msg2 Below to Client");
    }
    dividerWithText(fplog, "Msg2 (send to Client)");

    msgio->send_partial((void *) &msg2, sizeof(sgx_ra_msg2_t));
    fsend_msg_partial(fplog, (void *) &msg2, sizeof(sgx_ra_msg2_t));

    msgio->send((void *) sigrl, msg2.sig_rl_size);
    fsend_msg(fplog, (void *) sigrl, msg2.sig_rl_size);

    if (verbose) {
        edivider();
    }
}
