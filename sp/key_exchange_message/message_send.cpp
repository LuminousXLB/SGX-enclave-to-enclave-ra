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

void send_msg4(const vector<uint8_t> &msg4) {
    if (verbose) {
        dividerWithText(stderr, "Copy/Paste Msg4 Below to Client");
    }
    dividerWithText(fplog, "Msg4 (send to Client)");

    msgio->send(msg4);
    fsend_msg(fplog, msg4.data(), msg4.size());

    if (verbose) {
        edivider();
    }
}
