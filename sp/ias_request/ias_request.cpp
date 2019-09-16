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


#include <cstring>
#include <cstdio>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include "agent.h"
#include "agent_wget.h"
#include "ias_request.h"

#include "../../crypto/crypto.h"
#include "../../utils/common.h"
#include "../../utils/logfile.h"
#include "../../utils/base64.h"
#include "../../utils/hexutil.h"

using namespace std;
using namespace httpparser;

#include <string>
#include <exception>
#include <httpresponseparser.h>

extern "C"
{
extern char verbose;
extern char debug;
};

static string ias_servers[2] = {
        IAS_SERVER_DEVELOPMENT_HOST,
        IAS_SERVER_PRODUCTION_HOST
};

static string url_decode(string str);

void ias_list_agents(FILE *fp) {
    fprintf(fp, "Available user agents:\n");
#ifdef AGENT_WGET
    fprintf(fp, "%s\n", AgentWget::name.c_str());
#endif
}

IAS_Connection::IAS_Connection(int server_idx, uint32_t flags, const subkey_t &priSubscriptionKey,
                               const subkey_t &secSubscriptionKey) {

    c_server = ias_servers[server_idx];
    c_flags = flags;
    c_server_port = IAS_PORT;
    c_proxy_mode = IAS_PROXY_AUTO;
    c_agent = nullptr;
    c_agent_name = "";
    c_proxy_port = 80;
    c_store = nullptr;

    subscription_key[SubscriptionKeyID::Primary] = priSubscriptionKey;
    subscription_key[SubscriptionKeyID::Secondary] = secSubscriptionKey;
}

IAS_Connection::~IAS_Connection() {
}

int IAS_Connection::agent(const char *agent_name) {
#ifdef AGENT_WGET
    if (AgentWget::name == agent_name) {
        c_agent_name = agent_name;
        return 1;
    }
#endif
    return 0;
}

//int IAS_Connection::proxy(const char *server, uint16_t port) {
//    int rv = 1;
//    try {
//        c_proxy_server = server;
//    }
//    catch (...) {
//        rv = 0;
//    }
//    c_proxy_port = port;
//
//    c_proxy_mode = IAS_PROXY_FORCE;
//
//    return rv;
//}
//
//string IAS_Connection::proxy_url() {
//    string proxy_url;
//
//    if (c_proxy_server.empty())
//        return "";
//
//    proxy_url = "http://" + c_proxy_server;
//
//    if (c_proxy_port != 80) {
//        proxy_url += ":";
//        proxy_url += to_string(c_proxy_port);
//    }
//
//    return proxy_url;
//}


// Decrypt then return the subscription key
string IAS_Connection::getSubscriptionKey() {

    string subscriptionKeyBuff(subscription_key[currentKeyID].data(),
                               subscription_key[currentKeyID].data() + IAS_SUBSCRIPTION_KEY_SIZE);

    if (debug) {
        eprintf("\n+++ Reconstructed Subscription Key:\t'%s'\n", subscriptionKeyBuff.c_str());
    }

    return subscriptionKeyBuff;
}

string IAS_Connection::base_url() {
    string url = "https://" + c_server;

    if (c_server_port != 443) {
        url += ":";
        url += to_string(c_server_port);
    }

    url += "/attestation/v";

    return url;
}

// Reuse the existing agent or get a new one.

Agent *IAS_Connection::agent() {
    if (c_agent == nullptr)
        return this->new_agent();
    return c_agent;
}

// Get a new agent (and discard the old one if there was one)

Agent *IAS_Connection::new_agent() {
    Agent *newagent = nullptr;

    // If we've requested a specific agent, use that one

    if (c_agent_name.length()) {
#ifdef AGENT_WGET
        if (c_agent_name == AgentWget::name) {
            try {
                newagent = (Agent *) new AgentWget(this);
            }
            catch (...) {
                if (newagent != nullptr) {
                    delete newagent;
                }
                return nullptr;
            }
            return newagent;
        }
#endif
    } else {
        // Otherwise, take the first available using this hardcoded
        // order of preference.
#ifdef AGENT_WGET
        if (newagent == nullptr) {
            if (debug)
                eprintf("+++ Trying agent_wget\n");
            try {
                newagent = (Agent *) new AgentWget(this);
            }
            catch (...) {
                if (newagent != NULL) {
                    delete newagent;
                }
                newagent = nullptr;
            }
        }
#endif
    }

    if (newagent == nullptr)
        return nullptr;

    if (newagent->initialize() == 0) {
        delete newagent;
        return nullptr;
    }

    c_agent = newagent;
    return c_agent;
}

IAS_Request::IAS_Request(IAS_Connection *conn, uint16_t version) {
    r_conn = conn;
    r_api_version = version;
}

IAS_Request::~IAS_Request() {
}

ias_error_t IAS_Request::sigrl(uint32_t gid, string &sigrl) {
    Response response;
    char sgid[9];
    string url = r_conn->base_url();
    Agent *agent = r_conn->new_agent();

    if (agent == nullptr) {
        eprintf("Could not allocate agent object");
        return IAS_QUERY_FAILED;
    }

    snprintf(sgid, 9, "%08x", gid);

    url += to_string(r_api_version);
    url += "/sigrl/";
    url += sgid;

    if (verbose) {
        edividerWithText("IAS sigrl HTTP Request");
        eprintf("HTTP GET %s\n", url.c_str());
        edivider();
    }

    if (agent->request(url, "", response)) {
        if (verbose) {
            edividerWithText("IAS sigrl HTTP Response");
            eputs(response.inspect().c_str());
            edivider();
        }

        if (response.statusCode == IAS_OK) {
            sigrl = response.content_string();
        }
    } else {
        eprintf("Could not query IAS\n");
        delete agent;
        return IAS_QUERY_FAILED;
    }

    delete agent;
    return response.statusCode;
}

ias_error_t IAS_Request::report(map<string, string> &payload, string &content, vector<string> &messages,
                                string &sresponse, int &exitcode) {
    Response response;
    map<string, string>::iterator imap;
    string url = r_conn->base_url();
    string body = "{\n";
    string header;
    ias_error_t status = IAS_OK;
    Agent *agent = r_conn->new_agent();

    if (agent == nullptr) {
        eprintf("Could not allocate agent object");
        return IAS_QUERY_FAILED;
    }

    try {
        for (imap = payload.begin(); imap != payload.end(); ++imap) {
            if (imap != payload.begin()) {
                body.append(",\n");
            }
            body.append("\"");
            body.append(imap->first);
            body.append("\":\"");
            body.append(imap->second);
            body.append("\"");
        }
        body.append("\n}");

        url += to_string(r_api_version);
        url += "/report";
    }
    catch (...) {
        delete agent;
        return IAS_QUERY_FAILED;
    }

    if (verbose) {
        edividerWithText("IAS report HTTP Request");
        eprintf("HTTP POST %s\n", url.c_str());
        edivider();
    }

    int rv = agent->request(url, body, sresponse, exitcode);
    if (rv) {
        //#define WGET_NO_ERROR       0
        //#define WGET_SERVER_ERROR   8
        //#define WGET_AUTH_ERROR     6

        if (exitcode == 6) {
            response.statusCode = IAS_UNAUTHORIZED;
        } else if (exitcode == 0 || exitcode == 8) {
            HttpResponseParser parser;
            HttpResponseParser::ParseResult result;

            result = parser.parse(response, sresponse.c_str(), sresponse.c_str() + sresponse.length());
            rv = (result == HttpResponseParser::ParsingCompleted);
        }
    }

//    if (agent->request(url, body, response)) {
    if (rv) {
        if (verbose) {
            edividerWithText("IAS report HTTP Response");
            eputs(response.inspect().c_str());
            edivider();
        }
    } else {
        eprintf("Could not query IAS\n");
        delete agent;
        return IAS_QUERY_FAILED;
    }

    if (response.statusCode != IAS_OK) {
        delete agent;
        return response.statusCode;
    }
    /*
     * Check IAS Certicicate
     */

//    status = verify_certificate(response);
//    if (status != IAS_OK) {
//        goto cleanup;
//    }
    content = response.content_string();

    /*
     * Check for advisory headers
     */

    header = response.headers_as_string("Advisory-URL");
    if (header.length())
        messages.push_back(header);

    header = response.headers_as_string("Advisory-IDs");
    if (header.length())
        messages.push_back(header);


    delete agent;

    return status;
}


// A simple URL decoder

static string url_decode(string str) {
    string decoded;
    size_t i;
    size_t len = str.length();

    for (i = 0; i < len; ++i) {
        if (str[i] == '+')
            decoded += ' ';
        else if (str[i] == '%') {
            char *e = nullptr;
            unsigned long int v;

            // Have a % but run out of characters in the string

            if (i + 3 > len)
                throw std::length_error("premature end of string");

            v = strtoul(str.substr(i + 1, 2).c_str(), &e, 16);

            // Have %hh but hh is not a valid hex code.
            if (*e)
                throw std::out_of_range("invalid encoding");

            decoded += static_cast<char>(v);
            i += 2;
        } else
            decoded += str[i];
    }

    return decoded;
}
