add_library(crypto crypto.h crypto.c)

target_link_libraries(crypto ${OPENSSL_CRYPTO_LIBRARY})