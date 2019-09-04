#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_ERROR_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_ERROR_H


#define Attestation_ErrInvalidMsg0 "msg0 Extended Epid Group ID is not zero"


typedef enum {
    Extended_Epid_Group_ID_Is_Not_Zero,
    Client_Enclave_Session_Key_Is_Invalid
} attestation_error_t;


#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_ERROR_H
