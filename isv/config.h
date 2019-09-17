#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_CONFIG_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_CONFIG_H

#include <string>
#include <map>
#include <array>
#include <sgx_key_exchange.h>

using namespace std;


#define MODE_ATTEST     0x0
#define MODE_EPID       0x1
#define MODE_QUOTE      0x2

#define OPT_PSE         0x01
#define OPT_NONCE       0x02
#define OPT_LINK        0x04
#define OPT_PUBKEY      0x08

/* Macros to set, clear, and get the mode and options */

#define SET_OPT(x, y)   x|=y
#define CLEAR_OPT(x, y) x=x&~y
#define OPT_ISSET(x, y) x&y


typedef struct config_struct {
    char mode;
    uint32_t flags;
    sgx_spid_t spid;
    sgx_ec256_public_t pubkey;
    sgx_quote_nonce_t nonce;
    char *server;
    char *port;
} config_t;


struct UserArgs {

    static int parse_int(const string &str);

    template<size_t CharLength>
    array<char, CharLength> check_hstr(const string &hex_str);

    template<class T>
    T search_numeric(const string &name, T default_value) const;

    template<class T>
    T search_numeric(const string &name) const;

    map<string, int> numeric_map;

//    {"QUERY_IAS_PRODUCTION",              false, TYPE_BOOL},
//    {"CLIENT_RANDOM_NONCE",               false, TYPE_BOOL},
//    {"CLIENT_USE_PLATFORM_SERVICES",      false, TYPE_BOOL},
//    {"POLICY_ALLOW_DEBUG",                false, TYPE_BOOL},
//    {"POLICY_ALLOW_CONFIGURATION_NEEDED", false, TYPE_BOOL},
//    {"SGX_VERBOSE",                       false, TYPE_BOOL},
//    {"SGX_DEBUG",                         false, TYPE_BOOL}

//    {"QUOTE_TYPE",                        false, TYPE_UINT16},
//    {"POLICY_PRODUCT_ID",                 true,  TYPE_UINT16},
//    {"POLICY_ISV_MIN_SVN",                false, TYPE_UINT16},

    map<string, array<char, 32>> h32_map;
//    {"SPID",                              true,  TYPE_HEX32_BYTES},
//    {"IAS_PRIMARY_SUBSCRIPTION_KEY",      true,  TYPE_HEX32_STRING},
//    {"IAS_SECONDARY_SUBSCRIPTION_KEY",    true,  TYPE_HEX32_STRING},

    array<uint8_t, 32> POLICY_MRSIGNER;
//    {"POLICY_MRSIGNER",                   true,  TYPE_HEX64_BYTES},
    map<string, string> str_map;

public:
    UserArgs();

    string get_bind_address() const;

    string get_bind_port() const;

    bool get_query_ias_production() const;

    sgx_spid_t get_spid() const;

    sgx_quote_sign_type_t get_quote_type() const;

    bool get_client_random_nonce() const;

    bool get_client_use_platform_services() const;

    array<char, 32> get_ias_primary_subscription_key() const;

    array<char, 32> get_ias_secondary_subscription_key() const;

    array<uint8_t, 32> get_policy_mrsigner() const;

    uint16_t get_policy_product_id() const;

    uint16_t get_policy_isv_min_svn() const;

    bool get_policy_allow_debug() const;

    bool get_policy_allow_configuration_needed() const;

    bool get_sgx_verbose() const;

    bool get_sgx_debug() const;
};

#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_CONFIG_H
