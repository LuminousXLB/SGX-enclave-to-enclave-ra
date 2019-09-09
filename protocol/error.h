#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_ERROR_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_ERROR_H


typedef enum {
    NotTrusted = 0,
    NotTrusted_Complicated,
    Trusted_Complicated,
    Trusted
} attestation_status_t;

typedef enum {
    NoErrorInformation = 0,
    MSG0_ExtendedEpidGroupIdIsNotZero,
    MSG1_ClientEnclaveSessionKeyIsInvalid,
    MSG3_ClientEnclaveSessingKeyMismatch,
    MSG3_InvalidReportData,
    MSG3_EpidGroupIdMismatch,
} attestation_error_t;

typedef struct _attestation_status_struct {
    attestation_status_t trust;
    attestation_error_t error;
} attestation_xstatus_t;


#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_ERROR_H
