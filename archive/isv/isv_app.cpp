/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/




#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <climits>
#include <cstdio>
#include <ctime>
#include <sgx_urts.h>
#include <sgx_utils/sgx_utils.h>
#include <message/message.h>
#include "isv_enclave_u.h"
#include "../../app/isv_attestation.h"
#include "../../app/config.h"
#include "common.h"
#include "logfile.h"

using namespace std;


char debug = 0;
char verbose = 0;

int isv_do_attestation(sgx_enclave_id_t eid, MsgIO *msgio, const UserArgs &user_args);

int main(int argc, char *argv[]) {
    const UserArgs user_args = UserArgs();

    sgx_enclave_id_t global_eid = 0;

    /* Create a logfile to capture debug output and actual msg data */
    fplog = create_logfile("client.log");
    dividerWithText(fplog, "Client Log Timestamp");

    const time_t timeT = time(nullptr);
    struct tm lt{}, *ltp;

    ltp = localtime(&timeT);
    if (ltp == nullptr) {
        perror("localtime");
        return 1;
    }
    lt = *ltp;

    fprintf(fplog, "%4d-%02d-%02d %02d:%02d:%02d\n",
            lt.tm_year + 1900,
            lt.tm_mon + 1,
            lt.tm_mday,
            lt.tm_hour,
            lt.tm_min,
            lt.tm_sec);
    divider(fplog);


    /* Launch the enclave */
    if (initialize_enclave(&global_eid, "isv_enclave.token", "isv_enclave.signed.so") < 0) {
        printf("Fail to initialize enclave.\n");
        exit(EXIT_FAILURE);
    }


    MsgIO *msgio = nullptr;
    if (user_args.get_bind_port().empty()) {
        msgio = new MsgIO();
    } else {
        try {
            msgio = new MsgIO(user_args.get_bind_address().c_str(), user_args.get_bind_port().c_str());
        }
        catch (...) {
            exit(1);
        }
    }

    isv_do_attestation(global_eid, msgio, user_args);

    close_logfile(fplog);

    return 0;
}

