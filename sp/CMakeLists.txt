cmake_minimum_required(VERSION 3.10)

set(EDL_SEARCH_PATHS sp_enclave)

set(SP_ENCLAVE_UTILS_IO sp_enclave/utils/io.h sp_enclave/utils/io.cpp sp_enclave/utils/base64.h sp_enclave/utils/base64.cpp)
set(SP_ENCLAVE_UTILS_CRYPTO sp_enclave/utils/crypto_utils.h sp_enclave/utils/crypto_utils.cpp)
set(SP_ENCLAVE_UTILS_CERT sp_enclave/utils/cert_utils.h sp_enclave/utils/cert_utils.cpp)
set(SP_ENCLAVE_UTILS_HTTP sp_enclave/utils/urldecode.h sp_enclave/utils/urldecode.cpp)
#httpparser/httpresponseparser.h httpparser/response.h

# build enclave library
add_enclave_library(sp_enclave
        SRCS sp_enclave/sp_enclave.cpp sp_enclave/sp_routines.cpp ${SP_ENCLAVE_UTILS_IO} ${SP_ENCLAVE_UTILS_CRYPTO} ${SP_ENCLAVE_UTILS_CERT} ${SP_ENCLAVE_UTILS_HTTP}
        EDL sp_enclave/sp_enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

target_include_directories(sp_enclave PRIVATE ${SGXSSL_INCLUDE_DIR})
include_directories(sp_enclave)

# sign the enclave, according to configurations one-step or two-step signing will be performed.
# default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
enclave_sign(sp_enclave
        KEY sp_enclave/sp_enclave_private.pem
        CONFIG sp_enclave/sp_enclave.config.xml)

# build untrusted library to be run with enclave
#add_untrusted_library(sp_ocalls
#        STATIC
#        SRCS sp_ocalls.cpp
#        EDL sp_enclave/sp_enclave.edl
#        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

# build untrusted executable to run with enclave
add_untrusted_executable(sp_app
        SRCS sp_app.cpp ias.h ias.cpp sp_ocalls.cpp config.h config.cpp loop_routine.cpp
        EDL sp_enclave/sp_enclave.edl
        EDL_SEARCH_PATHS Enclave})

#target_compile_options(sp_app PRIVATE -Wno-pointer-to-int-cast)

add_subdirectory(ias_request)
add_subdirectory(key_exchange_message)

target_include_directories(sp_app PRIVATE ias_request)
target_include_directories(sp_app PRIVATE key_exchange_message)

target_link_libraries(sp_app ias_request key_exchange_message) #  sp_ocalls
target_link_libraries(sp_app common msgio hexutil logfile fileio base64 sgx_utils crypto)

add_dependencies(sp_app sp_enclave-sign)
