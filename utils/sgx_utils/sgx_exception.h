//
// Created by ncl on 17/9/19.
//

#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_SGX_ERROR_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_SGX_ERROR_H

#include <sgx_urts.h>
#include <string>
#include <exception>

using namespace std;

static char buffer[4096];

class sgx_error : public exception {
    sgx_status_t status;
    string where;
public:
    sgx_error(string where, sgx_status_t status) : where(std::move(where)), status(status) {}

    const char *what() const noexcept {
        sprintf(buffer, "%s: %04x", where.c_str(), status);
        return buffer;
    };
};

#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_SGX_ERROR_H
