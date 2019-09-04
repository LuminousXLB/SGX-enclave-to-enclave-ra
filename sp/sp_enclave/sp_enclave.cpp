#include <sgx_tkey_exchange.h>
#include "protocol.h"
#include "sp_routines.h"
#include "sp_enclave_t.h"
#include <vector>

using namespace std;

//typedef struct ra_secret_struct {
//    sgx_ec256_private_t private_b;
//    sgx_ec256_public_t public_b;
//    sgx_ec256_dh_shared_t shared_secret;
//    sgx_cmac_128bit_key_t smk;
//    sgx_ec256_public_t public_a;
//    sgx_epid_group_id_t client_gid;
//} ra_secret_t;

static const unsigned char def_service_private_key[32] = {
        0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
        0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
        0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
        0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};

ra_secret_t secret;

sgx_status_t ecall_do_attestation(ra_msg01_t msg01,
                                  ra_msg4_t *msg4, attestation_status_t *att_status) {

    if (!msg4 || !att_status) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t status;
    att_status->trust = attestation_status_t::NotTrusted;
    att_status->error = attestation_status_t::NoErrorInformation;

//    proc msg0
    status = private_proc_msg0(msg01.msg0_extended_epid_group_id, att_status);
    check_sgx_status(status);

//    proc msg1
    status = private_proc_msg1(secret, &msg01.msg1, att_status);
    check_sgx_status(status);

//    [ocall] get SigRL, spid, quote_type
    sgx_spid_t spid;
    sgx_quote_sign_type_t quote_type;
    uint32_t sigrl_size;
    ocall_pre_get_sigrl(secret.client_gid, &spid, &quote_type, &sigrl_size);

    vector<uint8_t> sigrl(sigrl_size, 0);
    ocall_get_sigrl(sigrl.size(), &sigrl[0]);

//    build msg2
    sgx_ra_msg2_t msg2;
    status = private_build_msg2(secret, spid, quote_type, sigrl, msg2);
    check_sgx_status(status);

//    send msg2


//    recv msg3
//    proc msg3
//    get  report
//    proc msg4
//    send msg4
}
