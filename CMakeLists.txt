cmake_minimum_required(VERSION 3.10)
project(SGX_enclave_to_enclave_ra)

set(CMAKE_CXX_STANDARD 14)

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

add_subdirectory(crypto)
add_subdirectory(isv)


# build untrusted executable to run with enclave
add_untrusted_executable(client
        SRCS ./isv/client.cpp
        EDL ./isv/Enclave/Enclave.edl
        EDL_SEARCH_PATHS ./isv/Enclave})

#add_executable(main main.cpp)

#add_subdirectory(service_provider/ias_request)
#target_link_libraries(main service_provider/ias_request)
