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


using namespace std;


#include "isv_enclave_u.h"
#include "config.h"

#if !defined(SGX_HW_SIM) && !defined(_WIN32)

#include "sgx_detect/sgx_stub.h"

#endif

#include <cstdlib>
#include <climits>
#include <cstdio>
#include <ctime>
#include <sgx_urts.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <getopt.h>
#include <unistd.h>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <string>
#include "common.h"
#include "protocol.h"
#include "sgx_detect/sgx_detect.h"
#include "hexutil.h"
#include "fileio.h"
#include "base64.h"
#include "crypto.h"
#include "msgio.h"
#include "logfile.h"
#include "quote_size.h"
#include "config.h"
#include "do_attestation.h"

#define MAX_LEN 80

#define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif


int file_in_searchpath(const char *file, const char *search, char *fullpath, size_t len);

sgx_status_t sgx_create_enclave_search(
        const char *filename,
        int edebug,
        sgx_launch_token_t *token,
        int *updated,
        sgx_enclave_id_t *eid,
        sgx_misc_attribute_t *attr
);

void usage();

//int do_quote(sgx_enclave_id_t eid, config_t *config);


char debug = 0;
char verbose = 0;


int main(int argc, char *argv[]) {
    const UserArgs user_args = UserArgs();

//    config_t config;
    sgx_launch_token_t token = {0};
    sgx_status_t status;
    sgx_enclave_id_t eid = 0;
    int updated = 0;

    /* Create a logfile to capture debug output and actual msg data */
    fplog = create_logfile("client.log");
    dividerWithText(fplog, "Client Log Timestamp");

    const time_t timeT = time(nullptr);
    struct tm lt, *ltp;

    ltp = localtime(&timeT);
    if (ltp == NULL) {
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

#if 0
    static struct option long_opt[] =
            {
                    {"help",        no_argument,       0, 'h'},
                    {"debug",       no_argument,       0, 'd'},
                    {"epid-gid",    no_argument,       0, 'e'},
                    {"pse-manifest",
                                    no_argument,       0, 'm'},
                    {"nonce",       required_argument, 0, 'n'},
                    {"nonce-file",  required_argument, 0, 'N'},
                    {"rand-nonce",  no_argument,       0, 'r'},
                    {"spid",        required_argument, 0, 's'},
                    {"spid-file",   required_argument, 0, 'S'},
                    {"linkable",    no_argument,       0, 'l'},
                    {"pubkey",      optional_argument, 0, 'p'},
                    {"pubkey-file", required_argument, 0, 'P'},
                    {"quote",       no_argument,       0, 'q'},
                    {"verbose",     no_argument,       0, 'v'},
                    {"stdio",       no_argument,       0, 'z'},
                    {0, 0,                             0, 0}
            };
    /* Parse our options */


    while (true) {
        int c;
        int opt_index = 0;
        unsigned char keyin[64];

        c = getopt_long(argc, argv, "N:P:S:dehlmn:p:qrs:vz", long_opt, &opt_index);
        if (c == -1) break;

        switch (c) {
            case 0:
                break;
            case 'N':
                if (!from_hexstring_file((unsigned char *) &config.nonce, optarg, 16)) {
                    fprintf(stderr, "nonce must be 32-byte hex string\n");
                    exit(1);
                }
                SET_OPT(config.flags, OPT_NONCE);

                break;
            case 'P':
                if (!key_load_file(&service_public_key, optarg, KEY_PUBLIC)) {
                    fprintf(stderr, "%s: ", optarg);
                    crypto_perror("key_load_file");
                    exit(1);
                }

                if (!key_to_sgx_ec256(&config.pubkey, service_public_key)) {
                    fprintf(stderr, "%s: ", optarg);
                    crypto_perror("key_to_sgx_ec256");
                    exit(1);
                }
                SET_OPT(config.flags, OPT_PUBKEY);

                break;
            case 'S':
                if (!from_hexstring_file((unsigned char *) &config.spid,
                                         optarg, 16)) {

                    fprintf(stderr, "SPID must be 32-byte hex string\n");
                    exit(1);
                }
                ++have_spid;

                break;
            case 'd':
                debug = 1;
                break;
            case 'e':
                config.mode = MODE_EPID;
                break;
            case 'l':
                SET_OPT(config.flags, OPT_LINK);
                break;
            case 'm':
                SET_OPT(config.flags, OPT_PSE);
                break;
            case 'n':
                if (strlen(optarg) < 32) {
                    fprintf(stderr, "nonce must be 32-byte hex string\n");
                    exit(1);
                }
                if (!from_hexstring((unsigned char *) &config.nonce,
                                    (unsigned char *) optarg, 16)) {

                    fprintf(stderr, "nonce must be 32-byte hex string\n");
                    exit(1);
                }

                SET_OPT(config.flags, OPT_NONCE);

                break;
            case 'p':
                if (!from_hexstring((unsigned char *) keyin,
                                    (unsigned char *) optarg, 64)) {

                    fprintf(stderr, "key must be 128-byte hex string\n");
                    exit(1);
                }

                /* Reverse the byte stream to make a little endien style value */
                for (i = 0; i < 32; ++i) config.pubkey.gx[i] = keyin[31 - i];
                for (i = 0; i < 32; ++i) config.pubkey.gy[i] = keyin[63 - i];

                SET_OPT(config.flags, OPT_PUBKEY);

                break;
            case 'q':
                config.mode = MODE_QUOTE;
                break;
            case 'r':
                for (i = 0; i < 2; ++i) {
                    int retry = 10;
                    unsigned char ok = 0;
                    uint64_t *np = (uint64_t * ) & config.nonce;

                    while (!ok && retry) ok = _rdrand64_step(&np[i]);
                    if (ok == 0) {
                        fprintf(stderr, "nonce: RDRAND underflow\n");
                        exit(1);
                    }
                }
                SET_OPT(config.flags, OPT_NONCE);
                break;
            case 's':
                if (strlen(optarg) < 32) {
                    fprintf(stderr, "SPID must be 32-byte hex string\n");
                    exit(1);
                }
                if (!from_hexstring((unsigned char *) &config.spid,
                                    (unsigned char *) optarg, 16)) {

                    fprintf(stderr, "SPID must be 32-byte hex string\n");
                    exit(1);
                }
                ++have_spid;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'z':
                flag_stdio = 1;
                break;
            case 'h':
            case '?':
            default:
                usage();
        }
    }

    argc -= optind;
    if (argc > 1) usage();

    /* Remaining argument is host[:port] */

    if (flag_stdio && argc) usage();
    else if (!flag_stdio && !argc) {
        // Default to localhost
        config.server = strdup("localhost");
        if (config.server == NULL) {
            perror("malloc");
            return 1;
        }
    } else if (argc) {
        char *cp;

        config.server = strdup(argv[optind]);
        if (config.server == NULL) {
            perror("malloc");
            return 1;
        }

        /* If there's a : then we have a port, too */
        cp = strchr(config.server, ':');
        if (cp != NULL) {
            *cp++ = '\0';
            config.port = cp;
        }
    }

    if (!have_spid && config.mode != MODE_EPID) {
        fprintf(stderr, "SPID required. Use one of --spid or --spid-file \n");
        return 1;
    }

#endif

    /* Can we run SGX? */

#ifndef SGX_HW_SIM
    unsigned sgx_support = get_sgx_support();
    if (sgx_support & SGX_SUPPORT_NO) {
        fprintf(stderr, "This system does not support Intel SGX.\n");
        return 1;
    } else {
        if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED) {
            fprintf(stderr, "Intel SGX is supported on this system but disabled in the BIOS\n");
            return 1;
        } else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED) {
            fprintf(stderr, "Intel SGX will be enabled after the next reboot\n");
            return 1;
        } else if (!(sgx_support & SGX_SUPPORT_ENABLED)) {
            fprintf(stderr, "Intel SGX is supported on this sytem but not available for use\n");
            fprintf(stderr, "The system may lock BIOS support, or the Platform Software is not available\n");
            return 1;
        }
    }
#endif

    /* Launch the enclave */

    status = sgx_create_enclave_search(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "sgx_create_enclave: %s: %08x\n", ENCLAVE_NAME, status);
        if (status == SGX_ERROR_ENCLAVE_FILE_ACCESS)
            fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
        return 1;
    }

    /* Are we attesting, or just spitting out a quote? */

    do_attestation(eid, user_args);

    close_logfile(fplog);

    return 0;
}


/*
 * Search for the enclave file and then try and load it.
 */

#ifndef _WIN32

sgx_status_t sgx_create_enclave_search(const char *filename, const int edebug,
                                       sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
                                       sgx_misc_attribute_t *attr) {
    struct stat sb;
    char epath[PATH_MAX];    /* includes NULL */

    /* Is filename an absolute path? */

    if (filename[0] == '/')
        return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

    /* Is the enclave in the current working directory? */

    if (stat(filename, &sb) == 0)
        return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

    /* Search the paths in LD_LBRARY_PATH */

    if (file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX))
        return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

    /* Search the paths in DT_RUNPATH */

    if (file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX))
        return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

    /* Standard system library paths */

    if (file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX))
        return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

    eprintf("%s is not in current working directory, and we don't know where it is.", filename);
    /*
     * If we've made it this far then we don't know where else to look.
     * Just call sgx_create_enclave() which assumes the enclave is in
     * the current working directory. This is almost guaranteed to fail,
     * but it will insure we are consistent about the error codes that
     * get reported to the calling function.
     */

    return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
}

int file_in_searchpath(const char *file, const char *search, char *fullpath,
                       size_t len) {
    char *p, *str;
    size_t rem;
    struct stat sb;

    if (search == NULL) return 0;
    if (strlen(search) == 0) return 0;

    str = strdup(search);
    if (str == NULL) return 0;

    p = strtok(str, ":");
    while (p != NULL) {
        size_t lp = strlen(p);

        if (lp) {

            strncpy(fullpath, p, len - 1);
            rem = (len - 1) - lp - 1;
            fullpath[len - 1] = 0;

            strncat(fullpath, "/", rem);
            --rem;

            strncat(fullpath, file, rem);

            if (stat(fullpath, &sb) == 0) {
                free(str);
                return 1;
            }
        }

        p = strtok(NULL, ":");
    }

    free(str);

    return 0;
}

#endif


void usage() {
    fprintf(stderr, "usage: client [ options ] [ host[:port] ]\n\n");
    fprintf(stderr, "Required:\n");
    fprintf(stderr, "  -N, --nonce-file=FILE    Set a nonce from a file containing a 32-byte\n");
    fprintf(stderr, "                             ASCII hex string\n");
    fprintf(stderr, "  -P, --pubkey-file=FILE   File containing the public key of the service\n");
    fprintf(stderr, "                             provider.\n");
    fprintf(stderr, "  -S, --spid-file=FILE     Set the SPID from a file containing a 32-byte\n");
    fprintf(stderr, "                             ASCII hex string\n");
    fprintf(stderr, "  -d, --debug              Show debugging information\n");
    fprintf(stderr, "  -e, --epid-gid           Get the EPID Group ID instead of performing\n");
    fprintf(stderr, "                             an attestation.\n");
    fprintf(stderr, "  -l, --linkable           Specify a linkable quote (default: unlinkable)\n");
    fprintf(stderr, "  -m, --pse-manifest       Include the PSE manifest in the quote\n");
    fprintf(stderr, "  -n, --nonce=HEXSTRING    Set a nonce from a 32-byte ASCII hex string\n");
    fprintf(stderr, "  -p, --pubkey=HEXSTRING   Specify the public key of the service provider\n");
    fprintf(stderr, "                             as an ASCII hex string instead of using the\n");
    fprintf(stderr, "                             default.\n");
    fprintf(stderr, "  -q                       Generate a quote instead of performing an\n");
    fprintf(stderr, "                             attestation.\n");
    fprintf(stderr, "  -r                       Generate a nonce using RDRAND\n");
    fprintf(stderr, "  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string\n");
    fprintf(stderr, "  -v, --verbose            Print decoded RA messages to stderr\n");
    fprintf(stderr, "  -z                       Read from stdin and write to stdout instead\n");
    fprintf(stderr, "                             connecting to a server.\n");
    fprintf(stderr,
            "\nOne of --spid OR --spid-file is required for generating a quote or doing\nremote attestation.\n");
    exit(1);
}

