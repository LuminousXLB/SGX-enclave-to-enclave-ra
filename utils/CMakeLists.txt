add_library(msgio msgio.h msgio.cpp)
add_library(fileio fileio.h fileio.c)

add_library(common common.h common.cpp)
add_library(logfile logfile.h logfile.c)

add_library(hexutil hexutil.h hexutil.c)
add_library(base64 base64.h base64.c ../sp/tmp_config.cpp ../sp/tmp_config.h)
#add_library(json json.hpp)

add_library(byteorder byteorder.h byteorder.c)
add_library(sgx_utils sgx_utils/sgx_utils.h sgx_utils/sgx_utils.cpp)

