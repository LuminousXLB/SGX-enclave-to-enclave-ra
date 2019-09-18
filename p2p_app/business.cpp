//
// Created by ncl on 18/9/19.
//

#include <string>
#include <vector>
#include <cstring>
#include "business.h"
#include <p2p_enclave_u.h>
#include <common.h>

using namespace std;

void write_text_message(sgx_enclave_id_t enclave_id, CodecIO &codecIo, const string &message) {
    printf("[%4d] %s\n", __LINE__, "write_text_message ...");

    sgx_status_t status;

    vector<uint8_t> tuple_bytes(COUNTER_LENGTH_IN_BYTES + sizeof(uint32_t), 0);
    tuple_bytes.insert(tuple_bytes.end(), message.begin(), message.end());

    message_tuple &tuple = *(message_tuple *) &tuple_bytes[0];
    tuple.length = message.size();

    tuple_bytes.resize((tuple_bytes.size() / 32 + 1) * 32, 0);

    aes_ctr_128_encrypt(enclave_id, &status, (uint8_t *) &tuple.length,
                        tuple_bytes.size() - COUNTER_LENGTH_IN_BYTES, tuple.nonce);
    if (status != SGX_SUCCESS) {
        fprintf(stdout, "Error[%04x] @ %4d\n", status, __LINE__);
        exit(EXIT_FAILURE);
    }

    printf("[%4d] length is %lu\n", __LINE__, message.size());

    codecIo.write(tuple_bytes);
}

string read_text_message(sgx_enclave_id_t enclave_id, CodecIO &codecIo) {
    printf("[%4d] %s\n", __LINE__, "read_text_message ...");

    vector<uint8_t> tuple_bytes = codecIo.read();
    message_tuple &tuple = *(message_tuple *) &tuple_bytes[0];

    sgx_status_t status;
    aes_ctr_128_decrypt(enclave_id, &status, (uint8_t *) &tuple.length,
                        tuple_bytes.size() - COUNTER_LENGTH_IN_BYTES, tuple.nonce);

    if (status != SGX_SUCCESS) {
        fprintf(stdout, "Error[%04x] @ %4d\n", status, __LINE__);
        exit(EXIT_FAILURE);
    }

    printf("[%4d] length is %u\n", __LINE__, tuple.length);
    uint32_t length = tuple.length;

    return string(tuple.payload, tuple.payload + tuple.length);
}


char *Fgets(char *ptr, int n, FILE *stream) {
    char *rptr = fgets(ptr, n, stream);

    if (rptr == nullptr && ferror(stream)) {
        fprintf(stderr, "Fgets error");
    }
    return rptr;
}

void client_business(int conn_fd, sgx_enclave_id_t enclaveId) {
    printf("[%s: %4d] %s\n", "client", __LINE__, "started ...");
    CodecIO socket(conn_fd);

    char buf[MESSAGE_LENGTH];
    while (fgets(buf, MESSAGE_LENGTH, stdin)) {
        write_text_message(enclaveId, socket, buf);
        string ret = read_text_message(enclaveId, socket);

        printf("[%s: %4d] %s\n", "client", __LINE__, "Message returned");
        hexdump(stdout, (uint8_t *) ret.c_str(), ret.size());
    }
}

void server_business(int conn_fd, sgx_enclave_id_t enclaveId) {
    printf("[%s: %4d] %s\n", "server", __LINE__, "started ...");
    CodecIO socket(conn_fd);

    string str = read_text_message(enclaveId, socket);
    while (str.length() > 0) {
        printf("[%s: %4d] %s\n", "server", __LINE__, "Message coming");
        hexdump(stdout, (uint8_t *) str.c_str(), str.size());
        write_text_message(enclaveId, socket, str);
        str = read_text_message(enclaveId, socket);
    }
}
