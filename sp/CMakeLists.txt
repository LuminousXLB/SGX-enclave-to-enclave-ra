cmake_minimum_required(VERSION 3.10)


set(EDL_SEARCH_PATHS sp_enclave)

# build enclave library
add_enclave_library(sp_enclave
        SRCS sp_enclave/sp_enclave.cpp sp_enclave/crypto_utils.h sp_enclave/crypto_utils.cpp sp_enclave/sp_routines.cpp ../protocol/error.h
        EDL sp_enclave/sp_enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

# sign the enclave, according to configurations one-step or two-step signing will be performed.
# default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
enclave_sign(sp_enclave
        KEY sp_enclave/sp_enclave_private.pem
        CONFIG sp_enclave/sp_enclave.config.xml)

## build untrusted library to be run with enclave
#add_untrusted_library(sp_ocalls
#        STATIC
#        SRCS sp_ocalls.cpp
#        EDL sp_enclave/sp_enclave.edl
#        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

# build untrusted executable to run with enclave
add_untrusted_executable(sp_app
        SRCS sp_app.cpp ias.h ias.cpp enclave_verify.h enclave_verify.c sp_ocalls.cpp tmp_config.h tmp_config.cpp
        EDL sp_enclave/sp_enclave.edl
        EDL_SEARCH_PATHS Enclave})

#target_compile_options(sp_app PRIVATE -Wno-pointer-to-int-cast)

add_subdirectory(ias_request)
add_subdirectory(key_exchange_message)

target_include_directories(sp_app PRIVATE ias_request)
target_include_directories(sp_app PRIVATE key_exchange_message)

target_link_libraries(sp_app ias_request key_exchange_message) #  sp_ocalls
target_link_libraries(sp_app common msgio hexutil logfile fileio base64 byteorder sgx_utils crypto)

add_dependencies(sp_app sp_enclave-sign)
