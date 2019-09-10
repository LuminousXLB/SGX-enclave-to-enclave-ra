
# Intel OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})


add_library(crypto crypto.h crypto.c)

target_link_libraries(crypto ${OPENSSL_CRYPTO_LIBRARY})