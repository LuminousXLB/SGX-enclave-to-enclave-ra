cmake_minimum_required(VERSION 3.10)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/../cmake)
find_package(SGX REQUIRED)
include_directories(${SGX_INCLUDE_DIR})

set(EDL_SEARCH_PATHS ./Enclave)

# build enclave library
add_enclave_library(Enclave
        SRCS ./Enclave/Enclave.h ./Enclave/Enclave.cpp
        EDL ./Enclave/Enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

# sign the enclave, according to configurations one-step or two-step signing will be performed.
# default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
enclave_sign(Enclave
        KEY ./Enclave/Enclave_private.pem
        CONFIG ./Enclave/Enclave.config.xml)

# build untrusted executable to run with enclave
add_untrusted_executable(client
        SRCS client.cpp
        EDL ./Enclave/Enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

## build untrusted library to be run with enclave
#add_untrusted_library(target
#        STATIC | SHARED | MODULE
#        [USE_PREFIX]
#        SRCS src1 src2 ...
#        EDL edl_file1 edl_file2 ...
#        EDL_SEARCH_PATHS path1 path2 ...)