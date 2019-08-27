//
// Created by ncl on 27/8/19.
//
#include "app.h"

void doit() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if (curl) {
        curl_slist *chunk = NULL;
        chunk = curl_slist_append(chunk, "Host: example.com");
//        /* Add a header with "blank" contents to the right of the colon. Note that
//           we're then using a semicolon in the string we pass to curl! */
//        chunk = curl_slist_append(chunk, "X-silly-header;");

        curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");

        /* Perform the request, res will get the return code */
        CURLcode res = curl_easy_perform(curl);
        /* Check for errors */
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        /* always cleanup */
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
}