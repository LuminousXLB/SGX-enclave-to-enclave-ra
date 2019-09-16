cmake_minimum_required(VERSION 3.10)

set(EDL_SEARCH_PATHS isv_enclave)

# build enclave library
add_enclave_library(isv_enclave
        SRCS isv_enclave/isv_enclave.h isv_enclave/isv_enclave.cpp
        EDL isv_enclave/isv_enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

# sign the enclave, according to configurations one-step or two-step signing will be performed.
# default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
enclave_sign(isv_enclave
        KEY isv_enclave/isv_enclave_private.pem
        CONFIG isv_enclave/isv_encalve.config.xml)

## build untrusted library to be run with enclave
#add_untrusted_library(target
#        STATIC | SHARED | MODULE
#        [USE_PREFIX]
#        SRCS src1 src2 ...
#        EDL edl_file1 edl_file2 ...
#        EDL_SEARCH_PATHS path1 path2 ...)

# build untrusted executable to run with enclave
add_untrusted_executable(isv_app
        SRCS isv_app.cpp quote_size.c sgx_detect/sgx_detect_linux.c sgx_detect/sgx_stub.c config.cpp do_attestation.cpp
        EDL isv_enclave/isv_enclave.edl
        EDL_SEARCH_PATHS Enclave})

target_link_libraries(isv_app msgio common fileio logfile hexutil base64 crypto dl)
target_link_libraries(isv_app sgx_urts ${SGX_LIBRARY_PATH}/libsgx_capable.a)
target_compile_options(isv_app PRIVATE -Wno-pointer-to-int-cast)
add_dependencies(isv_app isv_enclave-sign)