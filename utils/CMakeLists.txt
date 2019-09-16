add_subdirectory(cppcodec)
include_directories(cppcodec)

add_library(msgio msgio.h msgio.cpp socket_log.h socket_log.cpp)
add_library(fileio fileio.h fileio.c)

add_library(common common.h common.cpp)
add_library(logfile logfile.h logfile.c)

add_library(hexutil hexutil.h hexutil.cpp)
add_library(base64 base64.h base64.c socket_log.cpp socket_log.h)
#add_library(json json.hpp)

add_library(sgx_utils sgx_utils/sgx_utils.h sgx_utils/sgx_utils.cpp)

