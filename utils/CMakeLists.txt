add_subdirectory(cppcodec)
include_directories(cppcodec)

add_library(message message/socket_log.cpp)
add_library(fileio fileio.h fileio.c)

add_library(common common.h common.cpp)
add_library(logfile logfile.h logfile.c)

add_library(hexutil hexutil.h hexutil.cpp)
#add_library(json json.hpp)

add_library(sgx_utils sgx_utils/sgx_utils.h sgx_utils/sgx_utils.cpp sgx_utils/search_shared_library.cpp)

