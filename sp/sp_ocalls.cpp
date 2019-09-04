#include <cstring>
#include "sp_enclave_u.h"
#include "ias_request.h"
#include "msgio.h"
#include "ias.h"
#include "tmp_config.h"

extern MsgIO *msgio;
extern IAS_Connection *ias;
extern config_t config;

char *sigrl_buffer = nullptr;
uint32_t sigrl_buffer_size = 0;

void ocall_pre_get_sigrl(sgx_epid_group_id_t gid, sgx_spid_t *spid, sgx_quote_sign_type_t *quote_type,
                         uint32_t *sigrl_size) {

    memcpy(spid, &config.spid, sizeof(sgx_spid_t));
    *quote_type = config.quote_type;

    int ret = get_sigrl(ias, IAS_API_DEF_VERSION, gid, &sigrl_buffer, &sigrl_buffer_size);
    if (ret) {
        *sigrl_size = sigrl_buffer_size;
    } else {
        if (sigrl_buffer) {
            free(sigrl_buffer);
        }
        exit(-1);
    }
}

void ocall_get_sigrl(uint32_t sigrl_size, uint8_t *sigrl) {
    if (!sigrl_buffer) {
        exit(-1);
    } else if (sigrl_size < sigrl_buffer_size) {
        exit(-1);
    } else {
        memcpy(sigrl, sigrl_buffer, sigrl_buffer_size);
    }
}

void ocall_get_msg3(sgx_ra_msg2_t msg2, sgx_ra_msg3_t *msg3, uint32_t *msg3_length) {
//  send msg2
//  recv msg3
}

