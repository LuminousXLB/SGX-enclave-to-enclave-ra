#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_TMP_CONFIG_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_TMP_CONFIG_H

#include <getopt.h>
#include "ias_request/ias_request.h" // for IAS_API_DEF_VERSION & IAS_SUBSCRIPTION_KEY_SIZE
#include "string.h"
#include "sgx_key_exchange.h"
#include <iostream>


typedef struct config_struct {
    sgx_spid_t spid;
    unsigned char pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
    unsigned char sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
    sgx_quote_sign_type_t quote_type;
    char *user_agent;
    unsigned char kdk[16];
    X509_STORE *store;
    X509 *signing_ca;
    unsigned int apiver;
    int strict_trust;
    sgx_measurement_t req_mrsigner;
    sgx_prod_id_t req_isv_product_id;
    sgx_isv_svn_t min_isvsvn;
    int allow_debug_enclave;
    char flag_prod;
    char flag_stdio;
    char *port;
} config_t;

void usage();

int parse_command_line_options(int argc, char *argv[], config_t &config);

int ias_connection_init(config_t &config);

int msgio_init(config_t &config);

#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_TMP_CONFIG_H
