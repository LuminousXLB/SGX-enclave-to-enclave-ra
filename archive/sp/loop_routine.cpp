#include <error.h>
#include <message/message.h>
#include <sgx_utils/sgx_utils.h>
#include "sp_enclave_u.h"
#include "../../app/ias.h"
#include "config.h"
#include "../../app/sp_attestation.h"

void sp_do_attestation(sgx_enclave_id_t enclave_id, MsgIO *msgio, IAS_Connection *ias, const UserArgs &user_args) {
//    attestation_error_t att_error = NoErrorInformation;

    sp_att_enclave sp_att_enclave_instance(enclave_id, user_args);

    /**************** Read message 0 and 1 ****************/
    vector<uint8_t> msg01_bytes;

    eprintf(">>> Receiving Msg 01\n");
    recv_msg01(msgio, msg01_bytes);

    const auto &msg01 = *(const ra_msg01_t *) msg01_bytes.data();

    /**************** Request sigrl ****************/
    string sigrl;
    eprintf(">>> Requesting SigRL\n");
    if (get_sigrl(ias, IAS_API_DEF_VERSION, msg01.msg1.gid, sigrl) != IAS_OK) {
        eprintf("could not retrieve the sigrl\n");
        exit(EXIT_FAILURE);
    }

    /**************** Process message 0 and 1, generate message 2 ****************/
    vector<uint8_t> msg2_bytes = sp_att_enclave_instance.process_msg01(msg01_bytes, sigrl);
    /**************** Send message 2 ****************/
    eprintf(">>> Sending Msg2\n");
    send_msg2(msgio, msg2_bytes);

    /**************** Read message 3 ****************/
    vector<uint8_t> msg3_bytes;
    eprintf(">>> Receiving Msg3\n");
    recv_msg3(msgio, msg3_bytes);

    const sgx_ra_msg3_t &msg3 = *(sgx_ra_msg3_t *) msg3_bytes.data();

    /**************** Request attestation report ****************/
    vector<uint8_t> quote_bytes(msg3.quote, msg3.quote + msg3_bytes.size() - sizeof(sgx_ra_msg3_t));
    string attestation_response;
    eprintf(">>> Requesting Attestation Report\n");
    ias_error_t ias_error = get_attestation_report(ias, IAS_API_DEF_VERSION, quote_bytes, attestation_response);
    if (ias_error != IAS_OK) {
        eprintf("ias_error [%4d] = %u\n", __LINE__, ias_error);
        exit(EXIT_FAILURE);
    }

    /**************** Process attestation report, generate message 4 ****************/
    vector<uint8_t> msg4_bytes = sp_att_enclave_instance.process_msg3(msg3_bytes, attestation_response);
    eprintf(">>> Sending Msg4\n");
    send_msg4(msgio, msg4_bytes);


    msgio->disconnect();
}