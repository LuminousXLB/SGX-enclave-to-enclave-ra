/*

Copyright 2019 Intel Corporation

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


#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <sgx_key_exchange.h>
#include "common.h"
#include "fileio.h"
#include "ias_request.h"
#include "logfile.h"
#include <algorithm>
#include <sgx_utils/sgx_utils.h>
#include <crypto.h>
#include "config.h"
#include "msgio.h"

using namespace std;


void cleanup_and_exit(int signo);


sgx_enclave_id_t global_eid;
char debug = 1;
char verbose = 1;
IAS_Connection *ias = nullptr;
extern sgx_spid_t SP_SPID;
extern sgx_quote_sign_type_t SP_QUOTE_TYPE;

MsgIO *msgio = nullptr;

int main(int argc, char *argv[]) {
    /* Parse user args from env */
    const UserArgs user_args = UserArgs();

    /* Create a logfile to capture debug output and actual msg data */
    fplog = create_logfile("sp.log");
    fprintf(fplog, "Server log started\n");

    /* Initialize out support libraries */
    crypto_init();

    /* Initialize our IAS request object */
    try {
        ias = new IAS_Connection(
                (user_args.get_query_ias_production()) ? IAS_SERVER_PRODUCTION : IAS_SERVER_DEVELOPMENT,
                0,
                user_args.get_ias_primary_subscription_key(),
                user_args.get_ias_secondary_subscription_key()
        );
    }
    catch (...) {
        eprintf("exception while creating IAS request object\n");
        exit(EXIT_FAILURE);
    }

    /* Get our message IO object. */
    msgio = new MsgIO(nullptr, user_args.get_bind_port().c_str());
    if (msgio == nullptr) {
        exit(EXIT_FAILURE);
    }

#ifndef _WIN32
    /*
     * Install some rudimentary signal handlers. We just want to make
     * sure we gracefully shutdown the listen socket before we exit
     * to avoid "address already in use" errors on startup.
     */
    struct sigaction sig_act{};

    sigemptyset(&sig_act.sa_mask);
    sig_act.sa_flags = 0;
    sig_act.sa_handler = &cleanup_and_exit;

    if (sigaction(SIGHUP, &sig_act, nullptr) == -1) perror("sigaction: SIGHUP");
    if (sigaction(SIGINT, &sig_act, nullptr) == -1) perror("sigaction: SIGHUP");
    if (sigaction(SIGTERM, &sig_act, nullptr) == -1) perror("sigaction: SIGHUP");
    if (sigaction(SIGQUIT, &sig_act, nullptr) == -1) perror("sigaction: SIGHUP");
#endif

//    Launch the enclave
    if (initialize_enclave(&global_eid, "sp_enclave.token", "sp_enclave.signed.so") < 0) {
        printf("Fail to initialize enclave.\n");
        return 1;
    }

    /* If we're running in server mode, we'll block here.  */

    while (msgio->server_loop()) {
        void do_attestation(sgx_enclave_id_t enclave_id, IAS_Connection *ias, const UserArgs &user_args);

        do_attestation(global_eid, ias, user_args);
    }

    crypto_destroy();

    return 0;
}

/* We don't care which signal it is since we're shutting down regardless */

void cleanup_and_exit(int signo) {
    /* Signal-safe, and we don't care if it fails or is a partial write. */

    ssize_t count = write(STDERR_FILENO, "\nterminating\n", 13);

    /*
     * This destructor consists of signal-safe system calls (close, shutdown).
     */

    delete msgio;

    exit(1);
}


