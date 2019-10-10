#ifndef BASE_64_H
#define BASE_64_H

#include <stdint.h>

static inline size_t to_base64(const uint8_t *in, char *out, size_t len) {
    const static char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        "ghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j;

    for (i = j = 0; i + 2 < len; i+=3) {
        out[j++] = b64[( in[i] >> 2) & 0x3f];
        out[j++] = b64[((in[i]     &   3) << 4) | ((in[i + 1] >> 4) & 0xf)];
        out[j++] = b64[((in[i + 1] & 0xf) << 2) | ((in[i + 2] >> 6) &   3)];
        out[j++] = b64[( in[i + 2] & 0x3f)];
    }

    switch (len - i) {
    case 1:
        out[j++] = b64[(in[i] >> 2) & 0x3f];
        out[j++] = b64[(in[i] & 3) << 4];
        break;
    case 2:
        out[j++] = b64[( in[i] >> 2) & 0x3f];
        out[j++] = b64[((in[i] & 3) << 4) | ((in[i + 1] >> 4) & 0xf)];
        out[j++] = b64[((in[i + 1] & 0xf) << 2)];
        break;
    default:
        break;
    }

    return j;
}

static inline ssize_t from_base64(const char *in, uint8_t *out, size_t olen,
                                  const char *source) {
    size_t c, i;
    ssize_t j;
    uint32_t acc = 0;
    const int8_t b64_tab[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -2, -2, -2, -2, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -2,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };

    for (c = i = j = 0; in[i]; i++) {
        int val = b64_tab[(uint8_t) in[i]];
        if (val == -2) continue;
        if (val == -1) {
            fprintf(stderr, "Illegal base64 character '%c' in \"%s\"\n",
                    in[i], source);
            return -1;
        }
        acc = acc << 6 | val;
        if (++c == 4) {
            if (j < olen) out[j++] = (acc >> 16) & 0xff;
            if (j < olen) out[j++] = (acc >>  8) & 0xff;
            if (j < olen) out[j++] =  acc        & 0xff;
            acc = 0;
            c = 0;
        }
    }
    if (c == 2) {
        if (j < olen) out[j++] = (acc >> 4) & 0xff;
    } else if (c == 3) {
        if (j < olen) out[j++] = (acc >> 10) & 0xff;
        if (j < olen) out[j++] = (acc >>  2) & 0xff;
    }

    return j;
}

#endif
