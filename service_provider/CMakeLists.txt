add_subdirectory(ias_request)

add_executable(server sp.cpp enclave_verify.h enclave_verify.c trusted.cpp)
target_include_directories(server PRIVATE ias_request)
target_link_libraries(server ias_request)
target_link_libraries(server common msgio hexutil logfile fileio crypto base64 byteorder)