#include "sp_ocalls.h"
#include "ias_request.h"
#include "msgio.h"
#include "ias.h"
#include "string.h"

extern sgx_spid_t SP_SPID;
extern uint16_t SP_QUOTE_TYPE;

extern MsgIO *msgio;
extern IAS_Connection *ias;

char *sigrl_buffer = nullptr;
uint32_t sigrl_buffer_size = 0;

void ocall_pre_get_sigrl(sgx_epid_group_id_t gid, sgx_spid_t *spid, uint16_t *quote_type, uint32_t *sigrl_size) {
//    int get_sigrl(IAS_Connection *ias, int version, sgx_epid_group_id_t gid, char **sigrl, uint32_t *msg2);
    memcpy(spid, &SP_SPID, sizeof(SP_SPID));
    *quote_type = SP_QUOTE_TYPE;

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
    } else if (sigrl_buffer_size != sigrl_size) {
        exit(-1);
    } else {
        memcpy(sigrl, sigrl_buffer, sigrl_buffer_size);
    }
}
