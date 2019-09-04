#include <string.h>
#include <hexutil.h>
#include "ias.h"
#include "common.h"
#include "json.hpp"

extern char debug;
extern char verbose;

using namespace json;

int get_sigrl(IAS_Connection *ias, int version, const sgx_epid_group_id_t gid, char **sig_rl, uint32_t *sig_rl_size) {
    IAS_Request *req = nullptr;
    int oops = 1;
    string sigrlstr;

    try {
        oops = 0;
        req = new IAS_Request(ias, (uint16_t) version);
    }
    catch (...) {
        oops = 1;
    }

    if (oops) {
        eprintf("Exception while creating IAS request object\n");
        delete req;
        return 0;
    }

    ias_error_t ret = IAS_OK;

    while (true) {

        ret = req->sigrl(*(uint32_t *) gid, sigrlstr);
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
        } else if (ret != IAS_OK) {

            delete req;
            return 0;
        }

        break;
    }


    *sig_rl = strdup(sigrlstr.c_str());
    if (*sig_rl == NULL) {
        delete req;
        return 0;
    }

    *sig_rl_size = (uint32_t) sigrlstr.length();

    delete req;

    return 1;
}

int get_attestation_report(IAS_Connection *ias, int version, const char *b64quote, sgx_ps_sec_prop_desc_t secprop,
                           ra_msg4_t *msg4, int strict_trust) {
    IAS_Request *req = NULL;
    map<string, string> payload;
    vector<string> messages;
    ias_error_t status;
    string content;

    try {
        req = new IAS_Request(ias, (uint16_t) version);
    }
    catch (...) {
        eprintf("Exception while creating IAS request object\n");
        if (req != NULL) delete req;
        return 0;
    }

    payload.insert(make_pair("isvEnclaveQuote", b64quote));

    status = req->report(payload, content, messages);
    if (status == IAS_OK) {
        JSON reportObj = JSON::Load(content);

        if (verbose) {
            edividerWithText("Report Body");
            eprintf("%s\n", content.c_str());
            edivider();
            if (messages.size()) {
                edividerWithText("IAS Advisories");
                for (vector<string>::const_iterator i = messages.begin();
                     i != messages.end(); ++i) {

                    eprintf("%s\n", i->c_str());
                }
                edivider();
            }
        }

        if (verbose) {
            edividerWithText("IAS Report - JSON - Required Fields");
            if (version >= 3) {
                eprintf("version               = %d\n",
                        reportObj["version"].ToInt());
            }
            eprintf("id:                   = %s\n",
                    reportObj["id"].ToString().c_str());
            eprintf("timestamp             = %s\n",
                    reportObj["timestamp"].ToString().c_str());
            eprintf("isvEnclaveQuoteStatus = %s\n",
                    reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
            eprintf("isvEnclaveQuoteBody   = %s\n",
                    reportObj["isvEnclaveQuoteBody"].ToString().c_str());

            edividerWithText("IAS Report - JSON - Optional Fields");

            eprintf("platformInfoBlob  = %s\n",
                    reportObj["platformInfoBlob"].ToString().c_str());
            eprintf("revocationReason  = %s\n",
                    reportObj["revocationReason"].ToString().c_str());
            eprintf("pseManifestStatus = %s\n",
                    reportObj["pseManifestStatus"].ToString().c_str());
            eprintf("pseManifestHash   = %s\n",
                    reportObj["pseManifestHash"].ToString().c_str());
            eprintf("nonce             = %s\n",
                    reportObj["nonce"].ToString().c_str());
            eprintf("epidPseudonym     = %s\n",
                    reportObj["epidPseudonym"].ToString().c_str());
            edivider();
        }

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

        /*
         * This sample's attestion policy is based on isvEnclaveQuoteStatus:
         *
         *   1) if "OK" then return "Trusted"
         *
          *   2) if "CONFIGURATION_NEEDED" then return
         *       "NotTrusted_ItsComplicated" when in --strict-trust-mode
         *        and "Trusted_ItsComplicated" otherwise
         *
         *   3) return "NotTrusted" for all other responses
         *
         *
         * ItsComplicated means the client is not trusted, but can
         * conceivable take action that will allow it to be trusted
         * (such as a BIOS update).
          */

        /*
         * Simply check to see if status is OK, else enclave considered
         * not trusted
         */

        memset(msg4, 0, sizeof(ra_msg4_t));

        if (verbose) edividerWithText("ISV isv_enclave Trust Status");

        if (!(reportObj["isvEnclaveQuoteStatus"].ToString().compare("OK"))) {
            msg4->status.trust = attestation_status_t::Trusted;
            if (verbose) eprintf("isv_enclave TRUSTED\n");
        } else if (!(reportObj["isvEnclaveQuoteStatus"].ToString().compare("CONFIGURATION_NEEDED"))) {
            if (strict_trust) {
                msg4->status.trust = attestation_status_t::NotTrusted_Complicated;
                if (verbose)
                    eprintf("isv_enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
                            reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
            } else {
                if (verbose)
                    eprintf("isv_enclave TRUSTED and COMPLICATED - Reason: %s\n",
                            reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
                msg4->status.trust = attestation_status_t::Trusted_Complicated;
            }
        } else if (!(reportObj["isvEnclaveQuoteStatus"].ToString().compare("GROUP_OUT_OF_DATE"))) {
            msg4->status.trust = attestation_status_t::NotTrusted_Complicated;
            if (verbose)
                eprintf("isv_enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
                        reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
        } else {
            msg4->status.trust = attestation_status_t::NotTrusted;
            if (verbose)
                eprintf("isv_enclave NOT TRUSTED - Reason: %s\n",
                        reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
        }


        /* Check to see if a platformInfoBlob was sent back as part of the
         * response */

        if (!reportObj["platformInfoBlob"].IsNull()) {
            if (verbose) eprintf("A Platform Info Blob (PIB) was provided by the IAS\n");

            /* The platformInfoBlob has two parts, a TVL Header (4 bytes),
             * and TLV Payload (variable) */

            string pibBuff = reportObj["platformInfoBlob"].ToString();

            /* remove the TLV Header (8 base16 chars, ie. 4 bytes) from
             * the PIB Buff. */

            pibBuff.erase(pibBuff.begin(), pibBuff.begin() + (4 * 2));

            int ret = from_hexstring((unsigned char *) &msg4->platformInfoBlob,
                                     pibBuff.c_str(), pibBuff.length() / 2);
        } else {
            if (verbose) eprintf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
        }

        delete req;
        return 1;
    }

    eprintf("attestation query returned %lu: \n", status);

    switch (status) {
        case IAS_QUERY_FAILED:
            eprintf("Could not query IAS\n");
            break;
        case IAS_BADREQUEST:
            eprintf("Invalid payload\n");
            break;
        case IAS_UNAUTHORIZED:
            eprintf("Failed to authenticate or authorize request\n");
            break;
        case IAS_SERVER_ERR:
            eprintf("An internal error occurred on the IAS server\n");
            break;
        case IAS_UNAVAILABLE:
            eprintf("Service is currently not able to process the request. Try again later.\n");
            break;
        case IAS_INTERNAL_ERROR:
            eprintf("An internal error occurred while processing the IAS response\n");
            break;
        case IAS_BAD_CERTIFICATE:
            eprintf("The signing certificate could not be validated\n");
            break;
        case IAS_BAD_SIGNATURE:
            eprintf("The report signature could not be validated\n");
            break;
        default:
            if (status >= 100 && status < 600) {
                eprintf("Unexpected HTTP response code\n");
            } else {
                eprintf("An unknown error occurred.\n");
            }
    }

    delete req;

    return 0;
}

