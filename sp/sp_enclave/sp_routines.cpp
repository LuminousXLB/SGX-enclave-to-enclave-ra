#include "sp_routines.h"

sgx_status_t private_proc_msg0(ra_secret_t *secret, uint32_t msg0_extended_epid_group_id, attestation_error_t *error) {
    if (msg0_extended_epid_group_id == 0) {
        return SGX_SUCCESS;
    } else {
        *error = Extended_Epid_Group_ID_Is_Not_Zero;
        return SGX_ERROR_UNEXPECTED;
    }
}


sgx_status_t private_proc_msg1(ra_secret_t *secret, sgx_ra_msg1_t *msg1, attestation_error_t *error) {
//    All components of msg1 are in little-endian byte order.
    sgx_status_t status;

//    Verify A's EC key
    int valid;
    status = key_verify(&msg1->g_a, &valid);
    check_sgx_status(status);
    if (!valid) {
        *error = Client_Enclave_Session_Key_Is_Invalid;
        return SGX_ERROR_UNEXPECTED;
    }

    memcpy_s(&secret->public_b, sizeof(sgx_ec256_public_t) + sizeof(sgx_epid_group_id_t), msg1, sizeof(sgx_ra_msg1_t));

//    Generate a random EC key using the P-256 curve. This key will become Gb.
    status = key_generate(&secret->private_b, &secret->public_b);
    check_sgx_status(status);

//    Derive the key derivation key (KDK) from Ga and Gb:
    status = ecdh_shared_secret(&secret->private_b, &msg1->g_a, &secret->shared_secret);
    check_sgx_status(status);

//    Derive SMK
    status = derive_key(&secret->shared_secret, "SMK", &secret->smk);
    check_sgx_status(status);

    return status;
}

sgx_status_t private_build_msg2(ra_secret_t *secret, sgx_ra_msg2_t *msg2, sgx_spid_t spid, uint16_t quote_type,
                                uint32_t sigrl_size, uint8_t *sigrl) {
    sgx_status_t status;

//    Gb
    memcpy_s((void *) &msg2->g_b, sizeof(sgx_ec256_public_t), (void *) &secret->public_b, sizeof(sgx_ec256_public_t));
//    SPID
    memcpy_s((void *) &msg2->spid, sizeof(sgx_spid_t), (void *) &spid, sizeof(sgx_spid_t));
//    Quote Type
    memcpy_s((void *) &msg2->quote_type, sizeof(uint16_t), (void *) &quote_type, sizeof(uint16_t));

//    KDF-ID
    uint16_t kdf_id = 1;
    memcpy_s((void *) &msg2->kdf_id, sizeof(uint16_t), (void *) &kdf_id, sizeof(uint16_t));

//    SigSP
    sgx_ec256_signature_t sig_sp;

    uint8_t Gb_Ga[SGX_ECP256_KEY_SIZE * 2];
    uint8_t *ptr = Gb_Ga;
    memcpy_s((void *) ptr, sizeof(sgx_ec256_public_t), (void *) &secret->public_b, sizeof(uint16_t));
    ptr = ptr + SGX_ECP256_KEY_SIZE;
    memcpy_s((void *) ptr, sizeof(sgx_ec256_public_t), (void *) &secret->public_a, sizeof(uint16_t));

    status = ecdsa(&secret->private_b, Gb_Ga, SGX_ECP256_KEY_SIZE * 2, &sig_sp);
    check_sgx_status(status);


    /*
     * Build message 2
     *
     * A || CMACsmk(A) || SigRL
     * (148 + 16 + SigRL_length bytes = 164 + SigRL_length bytes)
     *
     * where:
     *
     * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga)
     *          (64 + 16 + 2 + 2 + 64 = 148 bytes)
     * Ga     = Client enclave's session key
     *          (32 bytes)
     * Gb     = Service Provider's session key
     *          (32 bytes)
     * SPID   = The Service Provider ID, issued by Intel to the vendor
     *          (16 bytes)
     * TYPE   = Quote type (0= linkable, 1= linkable)
     *          (2 bytes)
     * KDF-ID = (0x0001= CMAC entropy extraction and key derivation)
     *          (2 bytes)
     * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
     *          (signed with the Service Provider's private key)
     *          (64 bytes)
     *
     * CMACsmk= AES-128-CMAC(A)
     *          (16 bytes)
     *
     * || denotes concatenation
     *
     * Note that all key components (Ga.x, etc.) are in little endian
     * format, meaning the byte streams need to be reversed.
     *
     * For SigRL, send:
     *
     *  SigRL_size || SigRL_contents
     *
     * where sigRL_size is a 32-bit uint (4 bytes). This matches the
     * structure definition in sgx_ra_msg2_t
     */

//    Determine the quote type that should be requested from the client (0x0 for unlinkable, and 0x1 for linkable). Note that this is a service provider policy decision, and the SPID must be associated with the correct quote type.
//            Set the KDF_ID. Normally this is 0x1.
//    Calculate the ECDSA signature of:
//    Gbx || Gby || Gax || Gay
//
//            (traditionally written as r || s) with the service provider's EC private key.
//    Calculate the AES-128 CMAC of:
//    Gb || SPID || Quote_Type || KDF_ID || SigSP
//
//    using the SMK (derived in Step 3) as the key.
//            Query IAS to obtain the SigRL for the client's Intel EPID GID.
}