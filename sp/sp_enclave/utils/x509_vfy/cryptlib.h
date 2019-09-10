//
// Created by ncl on 10/9/19.
//

#ifndef SGX_ENCLAVE_TO_ENCLAVE_RA_CRYPTLIB_H
#define SGX_ENCLAVE_TO_ENCLAVE_RA_CRYPTLIB_H



# define ossl_assert(x) ((x) != 0)
//#ifdef NDEBUG
//#else
//__owur static ossl_inline int ossl_assert_int(int expr, const char *exprstr,
//                                              const char *file, int line)
//{
//    if (!expr)
//        OPENSSL_die(exprstr, file, line);
//
//    return expr;
//}
//
//# define ossl_assert(x) ossl_assert_int((x) != 0, "Assertion failed: "#x, \
//                                         __FILE__, __LINE__)
//
//#endif


#endif //SGX_ENCLAVE_TO_ENCLAVE_RA_CRYPTLIB_H
