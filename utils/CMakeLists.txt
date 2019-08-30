message(STATUS I'm here)
message(STATUS include - ${CMAKE_INCLUDE_PATH})

add_library(msgio msgio.h msgio.cpp)
add_library(fileio fileio.h fileio.c)

add_library(common common.h common.cpp)
add_library(logfile logfile.h logfile.c)

add_library(hexutil hexutil.h hexutil.c)
add_library(base64 base64.h base64.c)
#add_library(json json.hpp)

add_library(byteorder byteorder.h byteorder.c)
