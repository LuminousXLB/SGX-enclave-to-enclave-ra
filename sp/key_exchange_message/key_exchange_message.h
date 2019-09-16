//
// Created by ncl on 4/9/19.
//

#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_KEY_EXCHANGE_MESSAGE_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_KEY_EXCHANGE_MESSAGE_H

#include <logfile.h>
#include "msgio.h"
#include "sgx_key_exchange.h"
#include "protocol.h"
#include <cstdio>
#include <common.h>
#include <hexutil.h>
#include <vector>

using namespace std;

extern MsgIO *msgio;


int recv_msg01(vector<uint8_t> &msg01_buf);

//int recv_msg2(sgx_ra_msg2_t *msg2);
int recv_msg3(vector<uint8_t> &msg3_buf);
//int recv_msg3(ra_msg4_t *msg4);


//void send_msg01(ra_msg01_t *msg01);
void send_msg2(const vector<uint8_t> &msg2);
//void send_msg3(sgx_ra_msg3_t *msg3);
void send_msg4(const vector<uint8_t> &msg4);

#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_KEY_EXCHANGE_MESSAGE_H
