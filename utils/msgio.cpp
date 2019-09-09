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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sgx_urts.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
//#include <exception>
#include <stdexcept>
#include <string>
#include <vector>
//#include "hexutil.h"
#include "msgio.h"
#include "common.h"
#include <cppcodec/hex_lower.hpp>

using namespace std;

using msgio_codec = cppcodec::hex_lower;

#ifndef _WIN32
# ifndef INVALID_SOCKET
#  define INVALID_SOCKET -1
# endif
#endif

/* With no arguments, we read/write to stdin/stdout using stdio */

MsgIO::MsgIO() {
    s = -1;
    ls = -1;
}

/* Connect to a remote server and port, and use socket IO */

MsgIO::MsgIO(const char *peer, const char *port) {
    int rv, proto;
    struct addrinfo *addrs, *addr, hints;
    s = ls = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (peer == nullptr) hints.ai_flags = AI_PASSIVE; // Server here
    hints.ai_protocol = IPPROTO_TCP;

    rv = getaddrinfo(peer, port, &hints, &addrs);
    if (rv != 0) {
        eprintf("getaddrinfo: %s\n", gai_strerror(rv));
        throw std::runtime_error("getaddrinfo failed");
    }

    for (addr = addrs; addr != nullptr; addr = addr->ai_next) {
        proto = addr->ai_family;
        s = socket(addr->ai_family, addr->ai_socktype,
                   addr->ai_protocol);
        if (s == -1) {
            perror("socket");
            continue;
        }

        if (peer == nullptr) {    // We're the server
            int enable = 1;

            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &enable, sizeof(enable));
#ifdef SO_REUSEPORT
            setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));
#endif
#ifdef IPV6_V6ONLY
            // If we have an IPV6 socket, make sure it will accept IPv4 connections, too
            if (addr->ai_family == AF_INET6) {
                int disable = 0;
                setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &disable, sizeof(disable));
            }
#endif

            if (bind(s, addr->ai_addr, (int) addr->ai_addrlen) == 0) break;
        } else {    // We're the client
            if (connect(s, addr->ai_addr, (int) addr->ai_addrlen) == 0) break;
        }

        close(s);

        s = INVALID_SOCKET;
    }

    freeaddrinfo(addrs);

    if (s == INVALID_SOCKET) {
        if (peer == nullptr) {
            perror("bind");
        } else {
            eprintf("%s: ", peer);
            perror("connect");
        }
        throw std::runtime_error("could not establish socket");
    }

    if (peer == nullptr) {    // Server here. Create our listening socket.
        int enable = 1;
        ls = s;                // Use 'ls' to refer to the listening socket
        s = INVALID_SOCKET;    // and 's' as the session socket.

        if (listen(ls, 5) == -1) { // The "traditional" backlog value in UNIX
            perror("listen");
            close(ls);
            throw std::runtime_error("could not listen on socket");
        }

        // We have a very simple server: it will block until we get a
        // connection.

        eprintf("Listening for connections on port %s\n", port);
    } else { // Client here
    }
}

MsgIO::~MsgIO() {
    // Shutdown our socket(s)
    if (s != -1) {
        shutdown(s, SHUT_RDWR);
        close(s);
    }

    if (ls != -1) {
        shutdown(ls, SHUT_RDWR);
        close(ls);
    }
}


int MsgIO::server_loop() {
    int proto;
    struct sockaddr_in6 cliaddr; // Large enough for an IP4 or IP6 peer
    socklen_t slen = sizeof(struct sockaddr_in6);

    // This will block until we get a client.

    printf("Waiting for a client to connect...\n");
    fflush(stdout);

    s = accept(ls, (sockaddr *) &cliaddr, &slen);
    if (s == INVALID_SOCKET) {
        close(ls);
        perror("accept");
        return 0;
    }

    proto = cliaddr.sin6_family;

    eprintf("Connection from ");

    // A client has connected.

    if (proto == AF_INET) {
        char clihost[INET_ADDRSTRLEN];
        auto *sa = (sockaddr_in *) &cliaddr;

        memset(clihost, 0, sizeof(clihost));

        if (inet_ntop(proto, &sa->sin_addr, clihost, sizeof(clihost)) != nullptr) {

            eprintf("%s", clihost);
        } else eprintf("(could not translate network address)");
    } else if (proto == AF_INET6) {
        char clihost[INET6_ADDRSTRLEN];

        memset(clihost, 0, sizeof(clihost));

        if (inet_ntop(proto, &cliaddr.sin6_addr, clihost, sizeof(clihost)) != nullptr) {
            eprintf("%s", clihost);
        } else eprintf("(could not translate network address)");
    }
    eprintf("\n");

    return 1;
}

void MsgIO::disconnect() {
    if (s != -1) {
        shutdown(s, SHUT_RDWR);
        close(s);
    }
}

int MsgIO::read(vector<uint8_t> &message_buffer) {
    string encoded_message;

    if (read(encoded_message)) {
        message_buffer = msgio_codec::decode(encoded_message);
        return 1;
    } else {
        return 0;
    }
}

int MsgIO::read(string &encoded_message) {
    /*
     * We don't know how many bytes are coming, so read until we find a
     * newline.
     */

    size_t idx; // newline index
    int ws;     // trail length, different between "/r/n" and "/n"

    do {
        ssize_t bread = 0;

        bread = recv(s, lbuffer, sizeof(lbuffer), 0);

        if (bread == -1) {
            if (errno == EINTR) continue;
            perror("recv");
            return -1;
        }

        if (bread > 0) {
            if (debug) {
                eprintf("+++ read %ld bytes from socket\n", bread);
            }

            rbuffer.append(lbuffer, bread);
            idx = rbuffer.find("\r\n");
            if (idx != string::npos) {
                ws = 2;
                break;
            }

            idx = rbuffer.find('\n');
            if (idx != string::npos) {
                ws = 1;
                break;
            }
        } else {
            return 0;
        }
    } while (true);


    if (idx == 0) {
        return 1;
    } else if (idx % 2) {
        eprintf("read odd byte count %zu\n", idx);
        return 0;
    }

    if (debug) {
        edividerWithText("read buffer");
        fwrite(rbuffer.c_str(), 1, idx, stdout);
        printf("\n");
        edivider();
    }

    encoded_message = rbuffer.substr(0, idx);
    rbuffer.erase(0, idx + ws);

    return 1;
}

void MsgIO::send_partial(const vector<uint8_t> &message_buffer) {
    wbuffer.append(msgio_codec::encode(message_buffer));
}


void MsgIO::send(const vector<uint8_t> &message_buffer) {
    wbuffer.append(msgio_codec::encode(message_buffer));
    wbuffer.append("\n");
    send();
}

void MsgIO::send_partial(void *src, size_t sz) {
    wbuffer.append(msgio_codec::encode((uint8_t *) src, sz));
}

void MsgIO::send() {
    ssize_t bsent;
    size_t len;

    while ((len = wbuffer.length())) {
        again:
        bsent = ::send(s, wbuffer.c_str(), (int) len, 0);
        if (bsent == -1) {
            if (errno == EINTR) goto again;
            perror("send");
            return;
        }
        fwrite(wbuffer.c_str(), 1, bsent, stdout);

        if (bsent == len) {
            wbuffer.clear();
            return;
        }

        wbuffer.erase(0, bsent);
    }
}


