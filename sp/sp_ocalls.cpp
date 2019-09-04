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
    if (get_sigrl(ias, IAS_API_DEF_VERSION, gid, sigrl)) {
        *sigrl_size = sigrl.length();
    } else {
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
}

void ocall_get_msg3(uint32_t msg3_size, uint8_t *msg3_buffer) {
    if (msg3_size < msg3.size()) {
        exit(-1);
    } else {
        memcpy(msg3_buffer, msg3.data(), msg3.size());
    }
}

