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
    ATTR_ParseFailed,
    ATTR_SigningCertificateNotFound,
    ATTR_CertificateHeaderInvalid,
    ATTR_OpensslError,
    ATTR_CertificationVerifyFailed,
    ATTR_SignatureNotFound,
    ATTR_SignatureInvalid,
    ATTR_SignatureVerifyFailed,
} attestation_error_t;


#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_ERROR_H
