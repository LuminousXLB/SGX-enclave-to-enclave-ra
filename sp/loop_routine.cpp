//
// Created by ncl on 9/9/19.
//

#include <error.h>
#include <key_exchange_message.h>
#include <sgx_utils/sgx_utils.h>
#include "loop_routine.h"
#include "sp_enclave_u.h"
#include "ias.h"

void do_attestation(sgx_enclave_id_t enclave_id, MsgIO *msgio, IAS_Connection *ias, const config_t &config) {
    sgx_status_t ret_status = SGX_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    attestation_error_t att_error = NoErrorInformation;

    do {
        /* Read message 0 and 1 */
        vector<uint8_t> msg01_bytes;
        recv_msg01(msg01_bytes);

        const auto &msg01 = *(const ra_msg01_t *) msg01_bytes.data();

        /* Request sigrl */
        string sigrl;
        if (get_sigrl(ias, IAS_API_DEF_VERSION, msg01.msg1.gid, sigrl) != IAS_OK) {
            eprintf("could not retrieve the sigrl\n");
            break;
        }

        vector<uint8_t> msg2_bytes(sizeof(sgx_ra_msg2_t) + sigrl.size(), 0);

        /* Process message 0 and 1, generate message 2 */
        sgx_status = ecall_sp_proc_msg01(enclave_id, &ret_status, config.spid, config.quote_type, msg01, sigrl.c_str(),
                                         sigrl.size(), (sgx_ra_msg2_t *) &msg2_bytes[0], msg2_bytes.size(), &att_error);

        /* Send message 2 */
        send_msg2(msg2_bytes);

        /* Read message 3 */
        vector<uint8_t> msg3_bytes;
        recv_msg3(msg3_bytes);

        const sgx_ra_msg3_t &msg3 = *(sgx_ra_msg3_t *) msg3_bytes.data();

        /* Request attestation report */
        vector<uint8_t> quote_bytes(msg3.quote, msg3.quote + msg3_bytes.size() - sizeof(sgx_ra_msg3_t));
        string attestation_response;
        ias_error_t ias_error = get_attestation_report(ias, IAS_API_DEF_VERSION, quote_bytes, attestation_response);
        if (ias_error != IAS_OK) {
            eprintf("ias_error = %u\n", ias_error);
            exit(EXIT_FAILURE);
        }

        /* Process attestation report, generate message 4 */
        ra_msg4_t msg4;
        sgx_status = ecall_sp_proc_msg3(enclave_id, &ret_status, &msg3, msg3_bytes.size(), attestation_response.c_str(),
                                        &msg4, &att_error);
        //        status = ecall_do_attestation(global_eid, &sgx_status, *msg01, &msg4, &att_status);



    } while (false);


#if 0

    ra_msg4_t msg4;

    if (att_status.error != NoErrorInformation) {
//        TODO: print error information
        eprintf("Attestation Error: %d\n", att_status.error);
    }

    if (status != SGX_SUCCESS) {
        goto disconnect;
    }

    if (sgx_status != SGX_SUCCESS) {
        goto disconnect;
    }

//    TODO: Send message4


    /* Read message 3, and generate message 4 */

    if (!process_msg3(msgio, ias, &msg1, &msg4, &config, &session)) {
        eprintf("error processing msg3\n");
        goto disconnect;
    }
#endif

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