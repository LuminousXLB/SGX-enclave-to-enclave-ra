#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_ISV_ATTESTATION_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_ISV_ATTESTATION_H

#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <sgx_urts.h>
#include <exception>
#include <string>
#include <utility>
#include "config.h"

using namespace std;

class sgx_error : public exception {
    sgx_status_t status;
    string where;
public:
    sgx_error(string where, sgx_status_t status) : where(std::move(where)), status(status) {}

};

class isv_attestation {
    sgx_enclave_id_t eid;
    bool client_use_platform_services;
    sgx_ra_context_t ra_ctx = 0xdeadbeef;

    uint32_t msg0 = 0;
    vector<uint8_t> msg1_bytes;
    vector<uint8_t> msg3_bytes;

public:
    isv_attestation(sgx_enclave_id_t enclave_id, const UserArgs &user_args) :
            eid(enclave_id),
            client_use_platform_services(user_args.get_client_use_platform_services()) {
        /*
         * WARNING! Normally, the public key would be hardcoded into the
         * enclave, not passed in as a parameter. Hardcoding prevents
         * the enclave using an unauthorized key.
         *
         * This is diagnostic/test application, however, so we have
         * the flexibility of a dynamically assigned key.
         */

        sgx_status_t sgx_status, ret_status, pse_status;

//        if (debug) fprintf(stderr, "+++ using default public key\n");
        sgx_status = enclave_ra_init_def(eid, &ret_status, client_use_platform_services, &ra_ctx, &pse_status);

        /* Did the ECALL succeed? */
        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("enclave_ra_init", sgx_status);
        }

        /* If we asked for a PSE session, did that succeed? */
        if (client_use_platform_services) {
            if (pse_status != SGX_SUCCESS) {
                throw sgx_error("pse_session", pse_status);
            }
        }

        /* Did sgx_ra_init() succeed? */
        if (ret_status != SGX_SUCCESS) {
            throw sgx_error("sgx_ra_init", ret_status);
        }
    }

    ~isv_attestation() {
        sgx_status_t ret_status;
        enclave_ra_close(eid, &ret_status, ra_ctx);
    }

    const uint32_t &generate_msg0() {
        sgx_status_t sgx_status = sgx_get_extended_epid_group_id(&msg0);
        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("sgx_get_extended_epid_group_id", sgx_status);
        }

        return msg0;
    }

    const vector<uint8_t> &generate_msg1() {
        sgx_ra_msg1_t msg1;
        sgx_status_t sgx_status = sgx_ra_get_msg1(ra_ctx, eid, sgx_ra_get_ga, &msg1);
        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("sgx_ra_get_msg1", sgx_status);
        }

        msg1_bytes.assign((uint8_t *) &msg1, (uint8_t *) &msg1 + sizeof(msg1));
        return msg1_bytes;
    }

    const vector<uint8_t> &generate_msg3(const vector<uint8_t> &msg2_bytes) {
        const auto *msg2 = (const sgx_ra_msg2_t *) msg2_bytes.data();
        sgx_ra_msg3_t *msg3 = nullptr;
        uint32_t msg3_sz = 0;

        sgx_status_t sgx_status = sgx_ra_proc_msg2(
                ra_ctx, eid, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted,
                msg2, msg2_bytes.size(), &msg3, &msg3_sz
        );
        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("sgx_ra_proc_msg2", sgx_status);
        }

        msg3_bytes.assign((uint8_t *) msg3, (uint8_t *) msg3 + msg3_sz);
        return msg3_bytes;
    }

};


#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_ISV_ATTESTATION_H
