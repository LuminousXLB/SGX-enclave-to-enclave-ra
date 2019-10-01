//
// Created by ncl on 17/9/19.
//

#include <cstdio>
#include <sgx_urts.h>
#include <sgx_utils/sgx_utils.h>
#include "config.h"
#include "protocol.h"
#include "socket.hpp"
#include "codec_io.hpp"
#include "sp_att_enclave.hpp"
#include "isv_att_enclave.hpp"
#include "ias_request/http_agent/agent_wget.hpp"
#include "ias_request/httpparser/response.h"
#include "ias_request/ias_request.hpp"
#include <hexdump.h>
#include "business.h"

void mutual_attestation(int fd, sgx_enclave_id_t eid, const UserArgs &userArgs);

void fprint_usage(FILE *fp, const char *executable) {
    fprintf(fp, "Usage: \n");
    fprintf(fp, "    %s <toml config> server <port>", executable);
    fprintf(fp, "    %s <toml config> client <host> <port>", executable);
}


int main(int argc, char const *argv[]) {
    if (argc < 2) {
        fprint_usage(stderr, argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *toml = argv[1];
    UserArgs userArgs = UserArgs(toml);

    sgx_enclave_id_t eid;

    /* Enclave Initialization */
    if (initialize_enclave(&eid, "Enclave_p2p.token", "Enclave_p2p.signed.so") < 0) {
        printf("Fail to initialize enclave.\n");
        return 1;
    }

    if (argc == 4 && *argv[2] == 's') {
        const char *port = argv[3];

        if (userArgs.get_sgx_debug()) {
            fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
        }

        Socket socket(Socket::SOCKET_SERVER, "", port);
        string client_hostname, client_port;

        if (userArgs.get_sgx_debug()) {
            fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
        }

        while (int fd = socket.serve(client_hostname, client_port)) {
            cout << "Connected to " << client_hostname << ":" << client_port << endl;

            mutual_attestation(fd, eid, userArgs);
            server_business(fd, eid);

            Socket::disconnect(fd);
            cout << "Disconnected" << endl;
        }

        return 0;
    }

    if (userArgs.get_sgx_debug()) {
        fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
    }

    if (argc == 5 && *argv[2] == 'c') {
        const char *host = argv[3];
        const char *port = argv[4];

        Socket socket(Socket::SOCKET_CLIENT, host, port);

        mutual_attestation(socket.get_file_decriptor(), eid, userArgs);
        client_business(socket.get_file_decriptor(), eid);

        return 0;
    }

    if (userArgs.get_sgx_debug()) {
        fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
    }

    fprint_usage(stdout, argv[0]);
    return -1;
}

///////////////////////////////////////////////////////////////////////////////
using bytes = vector<uint8_t>;

void mutual_attestation(int fd, sgx_enclave_id_t eid, const UserArgs &userArgs) {
    CodecIO codecIo(fd);
    sp_att_enclave spAttEnclave(eid, userArgs);
    isv_att_enclave isvAttEnclave(eid, userArgs);

    IAS_Request iasRequest(userArgs.get_ias_primary_subscription_key(), userArgs.get_ias_secondary_subscription_key(),
                           userArgs.get_query_ias_production());

    if (userArgs.get_sgx_debug()) {
        fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
    }
    AgentWget agent(userArgs.get_sgx_verbose(), userArgs.get_sgx_debug());

    if (userArgs.get_sgx_debug()) {
        fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
    }


    {
        /**************** Generate message 0 and 1 ****************/
        const uint32_t msg0 = isvAttEnclave.generate_msg0();
        bytes msg01_bytes((uint8_t *) &msg0, (uint8_t *) &msg0 + sizeof(uint32_t));
        const bytes msg1_bytes = isvAttEnclave.generate_msg1();

        /**************** Send message 0 and 1 ****************/
        msg01_bytes.insert(msg01_bytes.end(), msg1_bytes.begin(), msg1_bytes.end());

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Generate message 0 and 1 ****************/\n");
            hexdump(stdout, msg01_bytes.data(), msg01_bytes.size());
        }

        codecIo.write(msg01_bytes);
    }

    {
        /**************** Receive message 0 and 1 ****************/
        bytes msg01_bytes = codecIo.read();
        const ra_msg01_t &msg01 = *(const ra_msg01_t *) msg01_bytes.data();

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Receive message 0 and 1 ****************/\n");
            hexdump(stdout, msg01_bytes.data(), msg01_bytes.size());
        }

        /**************** Request sigrl ****************/
        httpparser::Response sigrl_response;
        string sigrl = iasRequest.sigrl((Agent *) &agent, *(uint32_t *) msg01.msg1.gid, sigrl_response);

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Request sigrl ****************/\n");
            puts(sigrl.c_str());
        }

        /**************** Process message 0 and 1, generate message 2 ****************/
        const bytes msg2_bytes = spAttEnclave.process_msg01(msg01_bytes, sigrl);

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Generate message 2 ****************/\n");
            hexdump(stdout, msg2_bytes.data(), msg2_bytes.size());
        }

        /**************** Send message 2 ****************/
        codecIo.write(msg2_bytes);
    }

    {

        /**************** Receive message 2 ****************/
        bytes msg2_bytes = codecIo.read();

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Receive message 2 ****************/\n");
            hexdump(stdout, msg2_bytes.data(), msg2_bytes.size());
        }

        /**************** Generate message 3 ****************/
        const bytes msg3_bytes = isvAttEnclave.generate_msg3(msg2_bytes);

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Generate message 0 and 1 ****************/\n");
            hexdump(stdout, msg3_bytes.data(), msg3_bytes.size());
        }
        /**************** Send message 3 ****************/
        codecIo.write(msg3_bytes);

        if (userArgs.get_sgx_debug()) {
            fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
        }

    }

    {
        /**************** Read message 3 ****************/
        bytes msg3_bytes = codecIo.read();
        const sgx_ra_msg3_t &msg3 = *(sgx_ra_msg3_t *) msg3_bytes.data();

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Receive message 3 ****************/\n");
            hexdump(stdout, msg3_bytes.data(), msg3_bytes.size());
        }

        /**************** Request attestation report ****************/
        bytes quote_bytes(msg3.quote, msg3.quote + msg3_bytes.size() - sizeof(sgx_ra_msg3_t));
        map<Attestation_Evidence_Payload, vector<uint8_t >> payload;
        payload.insert({isvEnclaveQuote, quote_bytes});

        httpparser::Response att_response;
        string str_response = iasRequest.report((Agent *) &agent, payload, att_response);

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Request attestation report ****************/\n");
            puts(str_response.c_str());
        }

        /**************** Process attestation report, generate message 4 ****************/
        const bytes msg4_bytes = spAttEnclave.process_msg3(msg3_bytes, str_response);

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Generate message 4 ****************/\n");
            hexdump(stdout, msg4_bytes.data(), msg4_bytes.size());
        }

        codecIo.write(msg4_bytes);
    }


    /**************** Receive message 4 ****************/
    bytes msg4_bytes = codecIo.read();
    const ra_msg4_t &msg4 = *(ra_msg4_t *) msg4_bytes.data();

    if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
        puts("/**************** Receive message 4 ****************/\n");
        hexdump(stdout, msg4_bytes.data(), msg4_bytes.size());
    }

    if (msg4.status == Trusted) {
        cout << "Trusted" << endl;

        auto key_hash = isvAttEnclave.generate_key();
        hexdump(stdout, key_hash.data(), key_hash.size());
    }
}
