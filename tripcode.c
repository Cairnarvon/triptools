#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SECURE_TRIP

#include <openssl/des.h>

const char *salt = "................................"
                   ".............../0123456789ABCDEF"
                   "GABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
                   "fabcdefghijklmnopqrstuvwxyz.....";

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
    char s[3], c_ret[14], *trip = c_ret + 3, cap[9];
    int k;
#else
    char trip[16];
    unsigned char *cap, *sectrip_bin;
#endif
    int i, j, l;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s capcode\n", argv[0]);
        return 1;
    }


    for (i = 1; i < argc; ++i) {
        l = strlen(argv[i]);

#ifndef SECURE_TRIP

        for (j = k = 0; j < l && k < 8; ++j, ++k) {
            switch (argv[i][j]) {
            case '&':
                if (argv[i][j + 1] != '#') {
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
                cap[k] = argv[i][j];
            }
        }

        cap[k > 8 ? 8 : k] = 0;
        l = strlen(cap);

        s[0] = l > 1 ? salt[(int) cap[1]] : l > 0 ? 'H' : '.';
        s[1] = l > 2 ? salt[(int) cap[2]] : l > 1 ? 'H' : '.';

        DES_fcrypt(cap, s, c_ret);
        trip[10] = 0;

#else

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
