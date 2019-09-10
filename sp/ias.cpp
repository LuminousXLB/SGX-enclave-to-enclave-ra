#include <string.h>
#include <base64.h>
#include "ias.h"
#include "common.h"
#include "json.hpp"

extern char debug;
extern char verbose;

using namespace json;

ias_error_t get_sigrl(IAS_Connection *ias, int version, const sgx_epid_group_id_t &gid, string &sig_rl) {
    IAS_Request *req = nullptr;

    try {
        req = new IAS_Request(ias, (uint16_t) version);
    }
    catch (...) {
        eprintf("Exception while creating IAS request object\n");
        if (!req) delete req;
        return 0;
    }

    ias_error_t ret;

    do {
        ret = req->sigrl(*(uint32_t *) gid, sig_rl);

        if (debug) {
            eprintf("+++ RET = %zu\n, ret");
            eprintf("+++ SubscriptionKeyID = %d\n", (int) ias->getSubscriptionKeyID());
        }

        if (ret == IAS_UNAUTHORIZED && (ias->getSubscriptionKeyID() == IAS_Connection::SubscriptionKeyID::Primary)) {
            if (debug) {
                eprintf("+++ IAS Primary Subscription Key failed with IAS_UNAUTHORIZED\n");
                eprintf("+++ Retrying with IAS Secondary Subscription Key\n");
            }

            // Retry with Secondary Subscription Key
            ias->SetSubscriptionKeyID(IAS_Connection::SubscriptionKeyID::Secondary);
            continue;
        } else {
            break;
        }
    } while (true);

    delete req;

    return ret;
}

ias_error_t get_attestation_report(IAS_Connection *ias, int version, const vector<uint8_t> &quote, string &response) {
    char *b64quote = base64_encode((char *) quote.data(), quote.size());
    if (b64quote == nullptr) {
        eprintf("Could not base64 encode the quote\n");
        return 0;
    }

    IAS_Request *req = nullptr;
    try {
        req = new IAS_Request(ias, (uint16_t) version);
    } catch (...) {
        eprintf("Exception while creating IAS request object\n");
        if (!req) delete req;
        return 0;
    }

    map<string, string> payload;
    payload.insert(make_pair("isvEnclaveQuote", b64quote));
    int exitcode;

    string content;

    vector<string> messages;
    req->report(payload, content, messages, response, exitcode);

    //#define WGET_NO_ERROR       0
    //#define WGET_SERVER_ERROR   8
    //#define WGET_AUTH_ERROR     6

    delete req;
    if (exitcode == 8 || exitcode == 0) {
        return IAS_OK;
    } else if (exitcode == 6) {
        return IAS_UNAUTHORIZED;
    } else {
        return -1;
    }
}

#if 0
ias_error_t get_attestation_report(IAS_Connection *ias, int version, const vector<uint8_t> &quote,
                                   string &content, vector<string> &messages) {

    if (verbose) {
        edividerWithText("isv_enclave Quote (base64) ==> Send to IAS");

        eputs(b64quote);
        eprintf("\n");
        edivider();
    }
    map<string, string> payload;
    payload.insert(make_pair("isvEnclaveQuote", b64quote));

    ias_error_t status = req->report(payload, content, messages);

    if (status == IAS_OK) {

        JSON reportObj = JSON::Load(content);

        if (verbose) {
            edividerWithText("Report Body");
            eprintf("%s\n", content.c_str());
            edivider();
            if (!messages.empty()) {
                edividerWithText("IAS Advisories");
                for (vector<string>::const_iterator i = messages.begin();
                     i != messages.end(); ++i) {

                    eprintf("%s\n", i->c_str());
                }
                edivider();
            }

            edividerWithText("IAS Report - JSON - Required Fields");
            if (version >= 3) {
                eprintf("version               = %d\n", reportObj["version"].ToInt());
            }
            eprintf("id:                   = %s\n", reportObj["id"].ToString().c_str());
            eprintf("timestamp             = %s\n", reportObj["timestamp"].ToString().c_str());
            eprintf("isvEnclaveQuoteStatus = %s\n", reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
            eprintf("isvEnclaveQuoteBody   = %s\n", reportObj["isvEnclaveQuoteBody"].ToString().c_str());

            edividerWithText("IAS Report - JSON - Optional Fields");

            eprintf("platformInfoBlob  = %s\n", reportObj["platformInfoBlob"].ToString().c_str());
            eprintf("revocationReason  = %s\n", reportObj["revocationReason"].ToString().c_str());
            eprintf("pseManifestStatus = %s\n", reportObj["pseManifestStatus"].ToString().c_str());
            eprintf("pseManifestHash   = %s\n", reportObj["pseManifestHash"].ToString().c_str());
            eprintf("nonce             = %s\n", reportObj["nonce"].ToString().c_str());
            eprintf("epidPseudonym     = %s\n", reportObj["epidPseudonym"].ToString().c_str());
            edivider();
        }

//        TODO: Put this to a better place
        /*
         * If the report returned a version number (API v3 and above), make
         * sure it matches the API version we used to fetch the report.
         *
         * For API v3 and up, this field MUST be in the report.
         */

        if (reportObj.hasKey("version")) {
            unsigned int rversion = (unsigned int) reportObj["version"].ToInt();
            if (verbose)
                eprintf("+++ Verifying report version against API version\n");
            if (version != rversion) {
                eprintf("Report version %u does not match API version %u\n", rversion, version);
                delete req;
                return 0;
            }
        } else if (version >= 3) {
            eprintf("attestation report version required for API version >= 3\n");
            delete req;
            return 0;
        }
    }

    delete req;
    return status;
}

#endif