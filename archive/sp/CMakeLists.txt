cmake_minimum_required(VERSION 3.10)

set(EDL_SEARCH_PATHS sp_enclave)

set(SP_ENCLAVE_UTILS_IO ../../p2p_enclave/utils/io.h ../../p2p_enclave/utils/io.cpp ../../p2p_enclave/utils/base64.h ../../p2p_enclave/utils/base64.cpp)
set(SP_ENCLAVE_UTILS_CRYPTO ../../p2p_enclave/utils/crypto_utils.h ../../p2p_enclave/utils/crypto_utils.cpp)
set(SP_ENCLAVE_UTILS_CERT ../../p2p_enclave/utils/cert_utils.h ../../p2p_enclave/utils/cert_utils.cpp)
set(SP_ENCLAVE_UTILS_HTTP ../../p2p_enclave/utils/urldecode.h ../../p2p_enclave/utils/urldecode.cpp)
#httpparser/httpresponseparser.h httpparser/response.h

# build enclave library
add_enclave_library(sp_enclave
        SRCS ../../p2p_enclave/sp_enclave.cpp ../../p2p_enclave/sp_routines.cpp ${SP_ENCLAVE_UTILS_IO} ${SP_ENCLAVE_UTILS_CRYPTO} ${SP_ENCLAVE_UTILS_CERT} ${SP_ENCLAVE_UTILS_HTTP}
        EDL ../../p2p_enclave/sp_enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

target_include_directories(sp_enclave PRIVATE ${SGXSSL_INCLUDE_DIR})
include_directories(sp_enclave)

# sign the enclave, according to configurations one-step or two-step signing will be performed.
# default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
enclave_sign(sp_enclave
        KEY ../p2p_enclave/sp_enclave_private.pem
        CONFIG ../p2p_enclave/sp_enclave.config.xml)

# build untrusted library to be run with enclave
#add_untrusted_library(sp_ocalls
#        STATIC
#        SRCS sp_ocalls.cpp
#        EDL sp_enclave/sp_enclave.edl
#        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

# build untrusted executable to run with enclave
add_untrusted_executable(sp_app
        SRCS sp_app.cpp ../ias.h ../ias.cpp ../../p2p_app/sp_ocalls.cpp config.h config.cpp loop_routine.cpp
        EDL ../../p2p_enclave/sp_enclave.edl
        EDL_SEARCH_PATHS Enclave})

#target_compile_options(sp_app PRIVATE -Wno-pointer-to-int-cast)

add_subdirectory(ias_request)

target_include_directories(sp_app PRIVATE ias_request)

target_link_libraries(sp_app ias_request) #  sp_ocalls
target_link_libraries(sp_app common message hexutil logfile fileio base64 sgx_utils crypto)

add_dependencies(sp_app sp_enclave-sign)
