cmake_minimum_required(VERSION 3.10)
project(SGX_enclave_to_enclave_ra)

set(CMAKE_CXX_STANDARD 11)

# Intel SGX
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(SGX REQUIRED)
include_directories(${SGX_INCLUDE_DIR})

# Common
#add_subdirectory(protocol)
include_directories(protocol)

# Utils
add_subdirectory(utils)
include_directories(utils)


#######################################################################################################################

set(EDL_SEARCH_PATHS p2p_enclave)

set(SP_ENCLAVE_UTILS_IO p2p_enclave/utils/io.h p2p_enclave/utils/io.cpp p2p_enclave/utils/base64.h p2p_enclave/utils/base64.cpp)
set(SP_ENCLAVE_UTILS_CRYPTO p2p_enclave/utils/crypto_utils.h p2p_enclave/utils/crypto_utils.cpp)
set(SP_ENCLAVE_UTILS_CERT p2p_enclave/utils/cert_utils.h p2p_enclave/utils/cert_utils.cpp)
set(SP_ENCLAVE_UTILS_HTTP p2p_enclave/utils/urldecode.h p2p_enclave/utils/urldecode.cpp)
#httpparser/httpresponseparser.h httpparser/response.h

set(SP_ENCLAVE_SRCS p2p_enclave/sp_enclave.cpp p2p_enclave/sp_routines.cpp ${SP_ENCLAVE_UTILS_IO} ${SP_ENCLAVE_UTILS_CRYPTO} ${SP_ENCLAVE_UTILS_CERT} ${SP_ENCLAVE_UTILS_HTTP})
set(ISV_ENCLAVE_SRCS p2p_enclave/isv_enclave.cpp)

# build enclave library
add_enclave_library(Enclave_p2p
        SRCS ${SP_ENCLAVE_SRCS} ${ISV_ENCLAVE_SRCS} p2p_enclave/app_enclave.cpp
        EDL p2p_enclave/p2p_enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

target_include_directories(Enclave_p2p PRIVATE ${SGXSSL_INCLUDE_DIR})
include_directories(p2p_enclave)

# sign the enclave, according to configurations one-step or two-step signing will be performed.
# default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
enclave_sign(Enclave_p2p
        KEY p2p_enclave/p2p_enclave_private.pem
        CONFIG p2p_enclave/p2p_enclave.config.xml)

# build untrusted executable to run with enclave
add_untrusted_executable(App_p2p
        SRCS p2p_app/p2p_app.cpp p2p_app/sp_ocalls.cpp p2p_app/config.cpp p2p_app/business.cpp
        EDL p2p_enclave/p2p_enclave.edl
        EDL_SEARCH_PATHS Enclave})

#target_compile_options(p2p_app PRIVATE -Wno-pointer-to-int-cast)

add_subdirectory(p2p_app/ias_request)

target_include_directories(App_p2p PRIVATE ias_request)
target_link_libraries(App_p2p sgx_utils hexdump)
#hexutil logfile fileio message
add_dependencies(App_p2p Enclave_p2p-sign)
