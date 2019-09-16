#include <error.h>
#include <key_exchange_message.h>
#include <sgx_utils/sgx_utils.h>
#include "sp_enclave_u.h"
#include "ias.h"
#include "config.h"

void do_attestation(sgx_enclave_id_t enclave_id, IAS_Connection *ias, const UserArgs &user_args) {
    sgx_status_t ret_status = SGX_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    attestation_error_t att_error = NoErrorInformation;

    do {
        /**************** Read message 0 and 1 ****************/
        vector<uint8_t> msg01_bytes;

        eprintf(">>> Receiving Msg 01\n");
        recv_msg01(msg01_bytes);

        const auto &msg01 = *(const ra_msg01_t *) msg01_bytes.data();

        /**************** Request sigrl ****************/
        string sigrl;
        eprintf(">>> Requesting SigRL\n");
        if (get_sigrl(ias, IAS_API_DEF_VERSION, msg01.msg1.gid, sigrl) != IAS_OK) {
            eprintf("could not retrieve the sigrl\n");
            break;
        }

        vector<uint8_t> msg2_bytes(sizeof(sgx_ra_msg2_t) + sigrl.size(), 0);

        /**************** Process message 0 and 1, generate message 2 ****************/
        eprintf("!!! user_args.get_quote_type(): %d\n", user_args.get_quote_type());
        sgx_status = ecall_sp_proc_msg01(enclave_id, &ret_status, user_args.get_spid(), user_args.get_quote_type(),
                                         msg01, sigrl.c_str(), sigrl.size(), (sgx_ra_msg2_t *) &msg2_bytes[0],
                                         msg2_bytes.size(), &att_error);

        if (sgx_status != SGX_SUCCESS) {
            eprintf("Ecall Error: %04x", sgx_status);
            break;
        }

        if (att_error != NoErrorInformation) {
            eprintf("Attestation Error: %d\n", att_error);
            break;
        }

        if (ret_status != SGX_SUCCESS) {
            eprintf("ecall_sp_proc_msg3 Error: %04x", sgx_status);
            break;
        }

        /**************** Send message 2 ****************/
        eprintf(">>> Sending Msg2\n");
        send_msg2(msg2_bytes);

        /**************** Read message 3 ****************/
        vector<uint8_t> msg3_bytes;
        eprintf(">>> Receiving Msg3\n");
        recv_msg3(msg3_bytes);

        const sgx_ra_msg3_t &msg3 = *(sgx_ra_msg3_t *) msg3_bytes.data();

        /**************** Request attestation report ****************/
        vector<uint8_t> quote_bytes(msg3.quote, msg3.quote + msg3_bytes.size() - sizeof(sgx_ra_msg3_t));
        string attestation_response;
        eprintf(">>> Requesting Attestation Report\n");
        ias_error_t ias_error = get_attestation_report(ias, IAS_API_DEF_VERSION, quote_bytes, attestation_response);
        if (ias_error != IAS_OK) {
            eprintf("ias_error [%4d] = %u\n", __LINE__, ias_error);
            break;
        }

        ra_trust_policy policy;
        policy.allow_debug = true;
        policy.allow_configuration_needed = false;
        policy.isv_min_svn = 1;
        policy.isv_product_id = 0;

        /**************** Process attestation report, generate message 4 ****************/
        vector<uint8_t> msg4_bytes(sizeof(ra_msg4_t));
        sgx_status = ecall_sp_proc_msg3(enclave_id, &ret_status,
                                        &msg3, msg3_bytes.size(), attestation_response.c_str(), policy,
                                        (ra_msg4_t *) &msg4_bytes[0], &att_error);

        if (sgx_status != SGX_SUCCESS) {
            break;
        }

        if (att_error != NoErrorInformation) {
            eprintf("Attestation Error: %d\n", att_error);
            break;
        }

        if (ret_status != SGX_SUCCESS) {
            break;
        }

        eprintf(">>> Sending Msg4\n");
        send_msg4(msg4_bytes);

    } while (false);


    if (ret_status != SGX_SUCCESS) {
        print_error_message(ret_status);
        exit(EXIT_FAILURE);
    }

    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        exit(EXIT_FAILURE);
    }

    msgio->disconnect();
}