//
// Created by ncl on 4/9/19.
//

#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_MESSAGE_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_MESSAGE_H

#include "../logfile.h"
#include "msgio.h"
#include "sgx_key_exchange.h"
#include "protocol.h"
#include <cstdio>
#include "../common.h"
#include "../hexutil.h"
#include <vector>

using namespace std;
//void send_msg01(ra_msg01_t *msg01);


int recv_msg01(MsgIO *msgio, vector<uint8_t> &msg01_buf);

//int recv_msg2(sgx_ra_msg2_t *msg2);
int recv_msg3(MsgIO *msgio, vector<uint8_t> &msg3_buf);
//int recv_msg3(ra_msg4_t *msg4);


void send_msg2(MsgIO *msgio, const vector<uint8_t> &msg2);

//void send_msg3(sgx_ra_msg3_t *msg3);
void send_msg4(MsgIO *msgio, const vector<uint8_t> &msg4);

#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_MESSAGE_H
