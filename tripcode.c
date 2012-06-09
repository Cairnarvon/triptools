#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#ifndef SECURE_TRIP

#ifdef SJIS_CONVERT
#include <iconv.h>
#endif

#include <openssl/des.h>

const char *salt = "................................"
                   ".............../0123456789ABCDEF"
                   "GABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
                   "fabcdefghijklmnopqrstuvwxyz....."
                   "................................"
                   "................................"
                   "................................"
                   "................................";

#else

#include <openssl/sha.h>
#include "salt.h"

extern const unsigned char salt[];

const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
                  "ghijklmnopqrstuvwxyz0123456789+/";

#endif

int main(int argc, char **argv)
{
#ifndef SECURE_TRIP
    char s[3], c_ret[14], *trip = c_ret + 3, *sjis, cap[9];
    int k;
#else
    char trip[16];
    unsigned char *cap, *sectrip_bin;
#endif
    int i, j;
    size_t l;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s capcode\n", argv[0]);
        return 1;
    }


    for (i = 1; i < argc; ++i) {

#ifndef SECURE_TRIP

#ifdef SJIS_CONVERT

        size_t outleft = 20;

        sjis = malloc(20);
        memset(sjis, 0, 20);

        l = strlen(argv[i]);

        iconv(iconv_open("SJIS//IGNORE", "UTF-8"),
              &argv[i], &l, &sjis, &outleft);

        outleft = 20 - outleft;
        sjis[outleft] = 0;
        sjis -= outleft;

#else

        l = strlen(argv[i]);
        sjis = argv[i];

#endif

        memset(cap, 0, 9);

        for (j = k = 0; j < 8 && k < 8; ++j, ++k) {
            switch (sjis[j]) {
            case '&':
                if (sjis[j + 1] != '#') {
                    cap[k] = '&';
                    if (++k < 8) cap[k] = 'a';
                    if (++k < 8) cap[k] = 'm';
                    if (++k < 8) cap[k] = 'p';
                    if (++k < 8) cap[k] = ';';
                }
                break;
            case '"':
                cap[k] = '&';
                if (++k < 8) cap[k] = 'q';
                if (++k < 8) cap[k] = 'u';
                if (++k < 8) cap[k] = 'o';
                if (++k < 8) cap[k] = 't';
                if (++k < 8) cap[k] = ';';
                break;
            case '\'':
                cap[k] = '&';
                if (++k < 8) cap[k] = '#';
                if (++k < 8) cap[k] = '0';
                if (++k < 8) cap[k] = '3';
                if (++k < 8) cap[k] = '9';
                if (++k < 8) cap[k] = ';';
                break;
            case '<':
                cap[k] = '&';
                if (++k < 8) cap[k] = 'l';
                if (++k < 8) cap[k] = 't';
                if (++k < 8) cap[k] = ';';
                break;
            case '>':
                cap[k] = '&';
                if (++k < 8) cap[k] = 'g';
                if (++k < 8) cap[k] = 't';
                if (++k < 8) cap[k] = ';';
                break;
            default:
                cap[k] = sjis[j];
            }
        }

        cap[k > 8 ? 8 : k] = 0;
        l = strlen(cap);

        s[0] = l > 1 ? salt[(unsigned char) cap[1]] : l > 0 ? 'H' : '.';
        s[1] = l > 2 ? salt[(unsigned char) cap[2]] : l > 1 ? 'H' : '.';

        DES_fcrypt(cap, s, c_ret);
        trip[10] = 0;

#ifdef SJIS_CONVERT

        free(sjis);

#endif

#else

        l = strlen(argv[i]);
        cap = malloc((l + sizeof(salt)) * sizeof(unsigned char));

        memcpy(cap, argv[i], l);
        memcpy(cap + l, salt, sizeof(salt));

        sectrip_bin = SHA1(cap, l + sizeof(salt), NULL);

        free(cap);

        for (j = 0; j < 4; ++j) {
            trip[j * 4]     = b64[sectrip_bin[j * 3] >> 2];
            trip[j * 4 + 1] = b64[((sectrip_bin[j * 3] & 3) << 4) |
                                   (sectrip_bin[j * 3 + 1] >> 4)];
            trip[j * 4 + 2] = b64[((sectrip_bin[j * 3 + 1] & 15) << 2) |
                                   (sectrip_bin[j * 3 + 2] >> 6)];
            trip[j * 4 + 3] = b64[sectrip_bin[j * 3 + 2] & 63];
        }

        trip[15] = 0;

#endif

        printf("%s\n", trip);
    }

    return 0;
}
