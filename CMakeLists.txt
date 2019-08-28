cmake_minimum_required(VERSION 3.14)
project(SGX_enclave_to_enclave_ra)

set(CMAKE_CXX_STANDARD 14)

#find_package(CURL REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(SGX REQUIRED)
include_directories(${SGX_INCLUDE_DIR})

add_subdirectory(utils)
add_subdirectory(crypto)
add_subdirectory(isv)

add_executable(main main.cpp)

#add_subdirectory(service_provider/ias_request)
#target_link_libraries(main service_provider/ias_request)


