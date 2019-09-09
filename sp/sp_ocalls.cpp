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

string ias_content;
vector<string> ias_messages;

void ocall_eputs(const char *macro_file, const char *macro_function, int macro_line, const char *message) {
    if (message) {
        eprintf("[%4d] %s: %s - %s\n", macro_line, macro_file, macro_function, message);
    } else {
        eprintf("[%4d] %s: %s\n", macro_line, macro_file, macro_function);
    }
}

void ocall_pre_get_sigrl(sgx_epid_group_id_t gid, sgx_spid_t *spid, sgx_quote_sign_type_t *quote_type,
                         uint32_t *sigrl_size) {
    printf("[%4d] %s: %s\n", __LINE__, __FILE__, __FUNCTION__);

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
    printf("[%4d] %s: %s\n", __LINE__, __FILE__, __FUNCTION__);

    if (sigrl_size < sigrl.length()) {
        exit(-1);
    } else {
        strcpy((char *) sigrl_buffer, sigrl.c_str());
    }
    printf("[%4d] %s: %s\n", __LINE__, __FILE__, __FUNCTION__);
}

void ocall_pre_get_msg3(sgx_ra_msg2_t msg2, uint32_t *msg3_length) {
    printf("[%4d] %s: %s\n", __LINE__, __FILE__, __FUNCTION__);

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
    printf("[%4d] %s: %s\n", __LINE__, __FILE__, __FUNCTION__);

    if (msg3_size < msg3.size()) {
        exit(-1);
    } else {
        memcpy(msg3_buffer, msg3.data(), msg3.size());
    }
}

void ocall_pre_get_attestation() {
    printf("[%4d] %s: %s\n", __LINE__, __FILE__, __FUNCTION__);

    uint8_t *p_quote = ((sgx_ra_msg3_t *) msg3.data())->quote;
    vector<uint8_t> quote(p_quote, p_quote + 436 + ((sgx_quote_t *) p_quote)->signature_len);

    ias_error_t status = get_attestation_report(ias, IAS_API_DEF_VERSION, quote, ias_content, ias_messages);
    if (status != IAS_OK) {
        eprintf("attestation query returned %lu: \n", status);

        switch (status) {
            case IAS_QUERY_FAILED:
                eprintf("Could not query IAS\n");
                break;
            case IAS_BADREQUEST:
                eprintf("Invalid payload\n");
                break;
            case IAS_UNAUTHORIZED:
                eprintf("Failed to authenticate or authorize request\n");
                break;
            case IAS_SERVER_ERR:
                eprintf("An internal error occurred on the IAS server\n");
                break;
            case IAS_UNAVAILABLE:
                eprintf("Service is currently not able to process the request. Try again later.\n");
                break;
            case IAS_INTERNAL_ERROR:
                eprintf("An internal error occurred while processing the IAS response\n");
                break;
            case IAS_BAD_CERTIFICATE:
                eprintf("The signing certificate could not be validated\n");
                break;
            case IAS_BAD_SIGNATURE:
                eprintf("The report signature could not be validated\n");
                break;
            default:
                if (status >= 100 && status < 600) {
                    eprintf("Unexpected HTTP response code\n");
                } else {
                    eprintf("An unknown error occurred.\n");
                }
        }

        exit(EXIT_FAILURE);
    }
}