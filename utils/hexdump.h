//
// Created by ncl on 18/9/19.
//

#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_HEXDUMP_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_HEXDUMP_H

#include <cstdio>
#include <cstdint>

void hexdump(FILE *stream, uint8_t const *data, size_t len);

#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_HEXDUMP_H
