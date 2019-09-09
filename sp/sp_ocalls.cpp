#include "key_exchange_message.h"
#include "sp_enclave_u.h"

using namespace std;


void ocall_eputs(const char *macro_file, const char *macro_function, int macro_line, const char *message) {
    if (message) {
        eprintf("[%4d] %s: %s - %s\n", macro_line, macro_file, macro_function, message);
    } else {
        eprintf("[%4d] %s: %s\n", macro_line, macro_file, macro_function);
    }
}

