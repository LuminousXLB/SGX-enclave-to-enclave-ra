cmake_minimum_required(VERSION 3.10)
project(SGX_enclave_to_enclave_ra)

set(CMAKE_CXX_STANDARD 11)

# Intel OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

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

# Crypto
add_subdirectory(crypto)
include_directories(crypto)

# client
add_subdirectory(isv)
# server
add_subdirectory(sp)
