/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

using namespace std;


#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <cstdio>
#include <string.h>
#include <string>
#include "common.h"
#include "logfile.h"

#define LINE_TYPE '-'
#define LINE_SHORT_LEN 4
#define LINE_MAX_LEN   76
#define LINE_TRAILING_LEN(header) ((LINE_MAX_LEN - string(header).size()) - LINE_SHORT_LEN -2)

#define LINE_COMPLETE (string( LINE_MAX_LEN, LINE_TYPE).c_str())

#define LINE_HEADER(header) (string(string( LINE_SHORT_LEN, LINE_TYPE) + ' ' + string(header) + ' ' + string(LINE_TRAILING_LEN(header), LINE_TYPE)).c_str())

#define INDENT(level) (string( level, ' ' ))

#define WARNING_INDENT(level) (string(level, '*'))

#define TIMESTR_SIZE    64

void edividerWithText(const char *text) {
    dividerWithText(stderr, text);
    if (fplog != nullptr) dividerWithText(fplog, text);
}

void dividerWithText(FILE *fd, const char *text) {
    fprintf(fd, "\n%s\n", LINE_HEADER(text));
}

void edivider() {
    divider(stderr);
    if (fplog != nullptr) divider(fplog);
}

void divider(FILE *fd) {
    fprintf(fd, "%s\n", LINE_COMPLETE);
}

int eprintf(const char *format, ...) {
    va_list va;
    int rv;

    va_start(va, format);
    rv = vfprintf(stderr, format, va);
    va_end(va);

    if (fplog != NULL) {
        time_t ts;
        struct tm timetm, *timetmp;
        char timestr[TIMESTR_SIZE];

        /* Don't timestamp a single "\n" */
        if (!(strlen(format) == 1 && format[0] == '\n')) {
            time(&ts);
#ifndef _WIN32
            timetmp = localtime(&ts);
            if (timetmp == NULL) {
                perror("localtime");
                return 0;
            }
            timetm = *timetmp;
#else
            localtime_s(&timetm, &ts);
#endif

            /* If you change this format, you _may_ need to change TIMESTR_SIZE */
            if (strftime(timestr, TIMESTR_SIZE, "%b %e %Y %T", &timetm) == 0) {
                /* oops */
                timestr[0] = 0;
            }
            fprintf(fplog, "%s ", timestr);
        }
        va_start(va, format);
        rv = vfprintf(fplog, format, va);
        va_end(va);
    }

    return rv;
}

int eputs(const char *s) {
    if (fplog != nullptr) fputs(s, fplog);
    return fputs(s, stderr);
}

void hexdump(FILE *stream, uint8_t const *data, uint32_t len)
{
    unsigned int i;
    unsigned int r, c;

    if (!stream)
        return;
    if (!data)
        return;

    for (r = 0, i = 0; r < (len / 16 + (len % 16 != 0)); r++, i += 16)
    {
        fprintf(stream, "%04X:   ", i); /* location of first byte in line */

        for (c = i; c < i + 8; c++) /* left half of hex dump */
            if (c < len)
                fprintf(stream, "%02X ", ((unsigned char const *)data)[c]);
            else
                fprintf(stream, "   "); /* pad if short line */

        fprintf(stream, "  ");

        for (c = i + 8; c < i + 16; c++) /* right half of hex dump */
            if (c < len)
                fprintf(stream, "%02X ", ((unsigned char const *)data)[c]);
            else
                fprintf(stream, "   "); /* pad if short line */

        fprintf(stream, "   ");

        for (c = i; c < i + 16; c++) /* ASCII dump */
            if (c < len)
                if (((unsigned char const *)data)[c] >= 32 &&
                    ((unsigned char const *)data)[c] < 127)
                    fprintf(stream, "%c", ((char const *)data)[c]);
                else
                    fprintf(stream, "."); /* put this for non-printables */
            else
                fprintf(stream, " "); /* pad if short line */

        fprintf(stream, "\n");
    }

    fflush(stream);
}