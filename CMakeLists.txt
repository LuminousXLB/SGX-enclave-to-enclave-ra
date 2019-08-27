cmake_minimum_required(VERSION 3.14)
project(SGX_enclave_to_enclave_ra)

set(CMAKE_CXX_STANDARD 14)

find_package(CURL REQUIRED)

add_executable(main main.cpp)

add_subdirectory(ias_http)
target_link_libraries(main ias_http)
