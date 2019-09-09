#include "key_exchange_message.h"

void send_msg2(const vector<uint8_t> &msg2) {
    if (verbose) {
        dividerWithText(stderr, "Copy/Paste Msg2 Below to Client");
    }
    dividerWithText(fplog, "Msg2 (send to Client)");

    msgio->send(msg2);
    fsend_msg(fplog, msg2.data(), msg2.size());

    if (verbose) {
        edivider();
    }
}
