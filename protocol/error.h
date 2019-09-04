#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_ERROR_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_ERROR_H


typedef struct _attestation_status_struct {
    enum {
        NotTrusted = 0,
        NotTrusted_Complicated,
        Trusted_Complicated,
        Trusted
    } trust;

    enum {
        NoErrorInformation = 0,
        MSG0_ExtendedEpidGroupIdIsNotZero,
        MSG1_ClientEnclaveSessionKeyIsInvalid,
        MSG3_ClientEnclaveSessingKeyMismatch,
        MSG3_InvalidReportData,
        MSG3_EpidGroupIdMismatch,
    } error;
} attestation_status_t;


#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_ERROR_H
