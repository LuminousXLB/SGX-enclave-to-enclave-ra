#include "tmp_config.h"
#include <../crypto/crypto.h>
#include <../utils/hexutil.h>
#include <../utils/common.h>
#include <../utils/fileio.h>
#include <../utils/msgio.h>

extern char debug;
extern char verbose;
extern IAS_Connection *ias;
extern MsgIO *msgio;

#define NNL <<endl<<endl<<
#define NL <<endl<<


void usage() {
    cerr << "usage: sp [ options ] [ port ]" NL
         "Required:" NL
         "  -A, --ias-signing-cafile=FILE" NL
         "                           Specify the IAS Report Signing CA file." NNL
         "  -N, --mrsigner=HEXSTRING" NL
         "                           Specify the MRSIGNER value of encalves that" NL
         "                           are allowed to attest. Enclaves signed by" NL
         "                           other signing keys are rejected." NNL
         "  -R, --isv-product-id=INT" NL
         "                           Specify the ISV Product Id for the service." NL
         "                           Only Enclaves built with this Product Id" NL
         "                           will be accepted." NNL
         "  -V, --min-isv-svn=INT" NL
         "                           The minimum ISV SVN that the service provider" NL
         "                           will accept. Enclaves with a lower ISV SVN" NL
         "                           are rejected." NNL
         "Required (one of):" NL
         "  -S, --spid-file=FILE     Set the SPID from a file containg a 32-byte" NL
         "                           ASCII hex string." NNL
         "  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string." NNL
         "Required (one of):" NL
         "  -I, --ias-pri-api-key-file=FILE" NL
         "                           Set the IAS Primary Subscription Key from a" NL
         "                           file containing a 32-byte ASCII hex string." NNL
         "  -i, --ias-pri-api-key=HEXSTRING" NL
         "                           Set the IAS Primary Subscription Key from a" NL
         "                           32-byte ASCII hex string." NNL
         "Required (one of):" NL
         "  -J, --ias-sec-api-key-file=FILE" NL
         "                           Set the IAS Secondary Subscription Key from a" NL
         "                           file containing a 32-byte ASCII hex string." NNL
         "  -j, --ias-sec-api-key=HEXSTRING" NL
         "                           Set the IAS Secondary Subscription Key from a" NL
         "                           32-byte ASCII hex string." NNL
         "Optional:" NL
         //  "  -B, --ca-bundle-file=FILE" NL
         //  "                           Use the CA certificate bundle at FILE (default:" NL
         //  "                           " << DEFAULT_CA_BUNDLE << ")" NNL
         "  -D, --no-debug-enclave   Reject Debug-mode enclaves (default: accept)" NNL
         "  -G, --list-agents        List available user agent names for --user-agent" NNL
         "  -P, --production         Query the production IAS server instead of dev." NNL
         "  -X, --strict-trust-mode  Don't trust enclaves that receive a " NL
         "                           CONFIGURATION_NEEDED response from IAS " NL
         "                           (default: trust)" NNL
         "  -d, --debug              Print debug information to stderr." NNL
         "  -g, --user-agent=NAME    Use NAME as the user agent for contacting IAS." NNL
         "  -l, --linkable           Request a linkable quote (default: unlinkable)." NNL
         "  -r, --api-version=N      Use version N of the IAS API (default: " << to_string(IAS_API_DEF_VERSION)
         << ")" NNL
         "  -v, --verbose            Be verbose. Print message structure details and" NL
         "                           the results of intermediate operations to stderr." NNL
         "  -z  --stdio              Read from stdin and write to stdout instead of" NL
         "                           running as a network server." << endl;

    ::exit(1);
}

int parse_command_line_options(int argc, char *argv[], config_t &config) {
    /* Command line options */

    static struct option long_opt[] = {
            {"ias-signing-cafile",   required_argument, 0, 'A'},
            {"ca-bundle",            required_argument, 0, 'B'},
            {"no-debug-enclave",     no_argument,       0, 'D'},
            {"list-agents",          no_argument,       0, 'G'},
            {"ias-pri-api-key-file", required_argument, 0, 'I'},
            {"ias-sec-api-key-file", required_argument, 0, 'J'},
            {"service-key-file",     required_argument, 0, 'K'},
            {"mrsigner",             required_argument, 0, 'N'},
            {"production",           no_argument,       0, 'P'},
            {"isv-product-id",       required_argument, 0, 'R'},
            {"spid-file",            required_argument, 0, 'S'},
            {"min-isv-svn",          required_argument, 0, 'V'},
            {"strict-trust-mode",    no_argument,       0, 'X'},
            {"debug",                no_argument,       0, 'd'},
            {"user-agent",           required_argument, 0, 'g'},
            {"help",                 no_argument,       0, 'h'},
            {"ias-pri-api-key",      required_argument, 0, 'i'},
            {"ias-sec-api-key",      required_argument, 0, 'j'},
            {"key",                  required_argument, 0, 'k'},
            {"linkable",             no_argument,       0, 'l'},
            {"api-version",          required_argument, 0, 'r'},
            {"spid",                 required_argument, 0, 's'},
            {"verbose",              no_argument,       0, 'v'},
            {"stdio",                no_argument,       0, 'z'},
            {0, 0,                                      0, 0}
    };

    char flag_spid = 0;
    char flag_ca = 0;
    char flag_usage = 0;
    char flag_isv_product_id = 0;
    char flag_min_isvsvn = 0;
    char flag_mrsigner = 0;


    /* Config defaults */
    memset(&config, 0, sizeof(config));
    config.apiver = IAS_API_DEF_VERSION;

    /*
     * For demo purposes only. A production/release enclave should
     * never allow debug-mode enclaves to attest.
     */
    config.allow_debug_enclave = 1;

    /* Parse our options */

    while (1) {
        int c;
        int opt_index = 0;
        off_t offset = IAS_SUBSCRIPTION_KEY_SIZE;
        int ret = 0;
        char *eptr = NULL;
        unsigned long val;

        c = getopt_long(argc, argv,
                        "A:B:DGI:J:K:N:PR:S:V:X:dg:hk:lp:r:s:i:j:vxz",
                        long_opt, &opt_index);
        if (c == -1) break;

        switch (c) {

            case 0:
                break;

            case 'A':
                if (!cert_load_file(&config.signing_ca, optarg)) {
                    crypto_perror("cert_load_file");
                    eprintf("%s: could not load IAS Signing Cert CA\n", optarg);
                    return 1;
                }

                config.store = cert_init_ca(config.signing_ca);
                if (config.store == NULL) {
                    eprintf("%s: could not initialize certificate store\n", optarg);
                    return 1;
                }
                ++flag_ca;

                break;

            case 'D':
                config.allow_debug_enclave = 0;
                break;
            case 'G':
                ias_list_agents(stdout);
                return 1;

            case 'I':
                // Get Size of File, should be IAS_SUBSCRIPTION_KEY_SIZE + EOF
                ret = from_file(NULL, optarg, &offset);

                if ((offset != IAS_SUBSCRIPTION_KEY_SIZE + 1) || (ret == 0)) {
                    eprintf("IAS Primary Subscription Key must be %d-byte hex string.\n",
                            IAS_SUBSCRIPTION_KEY_SIZE);
                    return 1;
                }

                // Remove the EOF
                offset--;

                // Read the contents of the file
                if (!from_file((unsigned char *) &config.pri_subscription_key, optarg, &offset)) {
                    eprintf("IAS Primary Subscription Key must be %d-byte hex string.\n",
                            IAS_SUBSCRIPTION_KEY_SIZE);
                    return 1;
                }
                break;

            case 'J':
                // Get Size of File, should be IAS_SUBSCRIPTION_KEY_SIZE + EOF
                ret = from_file(NULL, optarg, &offset);

                if ((offset != IAS_SUBSCRIPTION_KEY_SIZE + 1) || (ret == 0)) {
                    eprintf("IAS Secondary Subscription Key must be %d-byte hex string.\n",
                            IAS_SUBSCRIPTION_KEY_SIZE);
                    return 1;
                }

                // Remove the EOF
                offset--;

                // Read the contents of the file
                if (!from_file((unsigned char *) &config.sec_subscription_key, optarg, &offset)) {
                    eprintf("IAS Secondary Subscription Key must be %d-byte hex string.\n",
                            IAS_SUBSCRIPTION_KEY_SIZE);
                    return 1;
                }

                break;

            case 'N':
                if (!from_hexstring((unsigned char *) &config.req_mrsigner, optarg, 32)) {
                    eprintf("MRSIGNER must be 64-byte hex string\n");
                    return 1;
                }
                ++flag_mrsigner;
                break;

            case 'P':
                config.flag_prod = 1;
                break;

            case 'R':
                eptr = NULL;
                val = strtoul(optarg, &eptr, 10);
                if (*eptr != '\0' || val > 0xFFFF) {
                    eprintf("Product Id must be a positive integer <= 65535\n");
                    return 1;
                }
                config.req_isv_product_id = val;
                ++flag_isv_product_id;
                break;

            case 'S':
                if (!from_hexstring_file((unsigned char *) &config.spid, optarg, 16)) {
                    eprintf("SPID must be 32-byte hex string\n");
                    return 1;
                }
                ++flag_spid;

                break;

            case 'V':
                eptr = NULL;
                val = strtoul(optarg, &eptr, 10);
                if (*eptr != '\0' || val > (unsigned long) 0xFFFF) {
                    eprintf("Minimum ISV SVN must be a positive integer <= 65535\n");
                    return 1;
                }
                config.min_isvsvn = val;
                ++flag_min_isvsvn;
                break;

            case 'X':
                config.strict_trust = 1;
                break;

            case 'd':
                debug = 1;
                break;

            case 'g':
                config.user_agent = strdup(optarg);
                if (config.user_agent == NULL) {
                    perror("malloc");
                    return 1;
                }
                break;

            case 'i':
                if (strlen(optarg) != IAS_SUBSCRIPTION_KEY_SIZE) {
                    eprintf("IAS Subscription Key must be %d-byte hex string\n", IAS_SUBSCRIPTION_KEY_SIZE);
                    return 1;
                }

                strncpy((char *) config.pri_subscription_key, optarg, IAS_SUBSCRIPTION_KEY_SIZE);

                break;

            case 'j':
                if (strlen(optarg) != IAS_SUBSCRIPTION_KEY_SIZE) {
                    eprintf("IAS Secondary Subscription Key must be %d-byte hex string\n", IAS_SUBSCRIPTION_KEY_SIZE);
                    return 1;
                }

                strncpy((char *) config.sec_subscription_key, optarg, IAS_SUBSCRIPTION_KEY_SIZE);

                break;


            case 'l':
                config.quote_type = SGX_LINKABLE_SIGNATURE;
                break;

            case 'r':
                config.apiver = atoi(optarg);
                if (config.apiver < IAS_MIN_VERSION || config.apiver > IAS_MAX_VERSION) {
                    eprintf("version must be between %d and %d\n", IAS_MIN_VERSION, IAS_MAX_VERSION);
                    return 1;
                }
                break;

            case 's':
                if (strlen(optarg) < 32) {
                    eprintf("SPID must be 32-byte hex string\n");
                    return 1;
                }
                if (!from_hexstring((unsigned char *) &config.spid, (unsigned char *) optarg, 16)) {
                    eprintf("SPID must be 32-byte hex string\n");
                    return 1;
                }
                ++flag_spid;
                break;

            case 'v':
                verbose = 1;
                break;

            case 'z':
                config.flag_stdio = 1;
                break;

            case 'h':
            case '?':
            default:
                usage();
        }
    }

    /* We should have zero or one command-line argument remaining */

    argc -= optind;
    if (argc > 1) usage();

    /* The remaining argument, if present, is the port number. */

    if (config.flag_stdio && argc) {
        usage();
    } else if (argc) {
        config.port = argv[optind];
    } else {
        config.port = strdup(DEFAULT_PORT);
        if (config.port == NULL) {
            perror("strdup");
            return 1;
        }
    }

    if (debug) {
        eprintf("+++ IAS Primary Subscription Key set to '%c%c%c%c........................%c%c%c%c'\n",
                config.pri_subscription_key[0],
                config.pri_subscription_key[1],
                config.pri_subscription_key[2],
                config.pri_subscription_key[3],
                config.pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE - 4],
                config.pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE - 3],
                config.pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE - 2],
                config.pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE - 1]
        );

        eprintf("+++ IAS Secondary Subscription Key set to '%c%c%c%c........................%c%c%c%c'\n",
                config.sec_subscription_key[0],
                config.sec_subscription_key[1],
                config.sec_subscription_key[2],
                config.sec_subscription_key[3],
                config.sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE - 4],
                config.sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE - 3],
                config.sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE - 2],
                config.sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE - 1]
        );
    }


    if (!flag_spid) {
        eprintf("--spid or --spid-file is required\n");
        flag_usage = 1;
    }

    if (!flag_ca) {
        eprintf("--ias-signing-cafile is required\n");
        flag_usage = 1;
    }

    if (!flag_isv_product_id) {
        eprintf("--isv-product-id is required\n");
        flag_usage = 1;
    }

    if (!flag_min_isvsvn) {
        eprintf("--min-isvsvn is required\n");
        flag_usage = 1;
    }

    if (!flag_mrsigner) {
        eprintf("--mrsigner is required\n");
        flag_usage = 1;
    }

    if (flag_usage) usage();

    return 1;
}


int ias_connection_init(config_t &config) {
    try {
        ias = new IAS_Connection(
                (config.flag_prod) ? IAS_SERVER_PRODUCTION : IAS_SERVER_DEVELOPMENT,
                0,
                (char *) (config.pri_subscription_key),
                (char *) (config.sec_subscription_key)
        );
    }
    catch (...) {
        eprintf("exception while creating IAS request object\n");
        return 0;
    }

    ias->proxy_mode(IAS_PROXY_NONE);

    if (config.user_agent != NULL) {
        if (!ias->agent(config.user_agent)) {
            eprintf("%s: unknown user agent\n", config.user_agent);
            return 0;
        }
    }

    /*
     * Set the cert store for this connection. This is used for verifying
     * the IAS signing certificate, not the TLS connection with IAS (the
     * latter is handled using config.ca_bundle).
     */
    ias->cert_store(config.store);

    return 1;
}

int msgio_init(config_t &config) {

    if (config.flag_stdio) {
        msgio = new MsgIO();
    } else {
        try {
            msgio = new MsgIO(nullptr, (config.port == nullptr) ? DEFAULT_PORT : config.port);
        }
        catch (...) {
            return 0;
        }
    }

    return 1;
}


