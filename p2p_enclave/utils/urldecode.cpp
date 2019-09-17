#include "urldecode.h"
#include <string>

using namespace std;

string url_decode(string str) {
    string decoded;
    size_t i;
    size_t len = str.length();

    for (i = 0; i < len; ++i) {
        if (str[i] == '+')
            decoded += ' ';
        else if (str[i] == '%') {
            char *e = nullptr;
            unsigned long int v;

            // Have a % but run out of characters in the string

            if (i + 3 > len)
                throw std::length_error("premature end of string");

            v = strtoul(str.substr(i + 1, 2).c_str(), &e, 16);

            // Have %hh but hh is not a valid hex code.
            if (*e)
                throw std::out_of_range("invalid encoding");

            decoded += static_cast<char>(v);
            i += 2;
        } else
            decoded += str[i];
    }

    return decoded;
}
