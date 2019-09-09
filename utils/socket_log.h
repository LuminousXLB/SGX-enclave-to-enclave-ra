#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_SOCKET_LOG_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_SOCKET_LOG_H


#ifdef __cplusplus
extern "C" {
#endif

extern char debug;
extern char verbose;

int read_msg(void **dest, size_t *sz);

void send_msg_partial(void *buf, size_t f_size);
void send_msg(void *buf, size_t f_size);

void fsend_msg_partial(FILE *fp, void *buf, size_t f_size);
void fsend_msg(FILE *fp, void *buf, size_t f_size);

#ifdef __cplusplus
};
#endif


#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_SOCKET_LOG_H
