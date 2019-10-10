/*  keyfile.c -- Encryption key handling

    Copyright (C) 2019 Genome Research Ltd.

    Author: Rob Davies <rmd@sanger.ac.uk>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.  */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>

#include <htslib/hts_defs.h>
#include <keyfile.h>
#include <sodium_if.h>

#define TTY_NAME "/dev/tty"

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

static inline int grow_buffer(void *buffer, size_t new_sz, size_t *size_out) {
    void *new_buffer = realloc(*((void **) buffer), new_sz);
    if (!new_buffer) {
        perror(NULL);
        return -1;
    }
    *((void **) buffer) = new_buffer;
    *size_out = new_sz;
    return 0;
}

static int get_base64_wrapped_data(const char *fname, FILE *kf,
                                   uint8_t **data_out, size_t *data_len) {
    uint8_t buffer[256], *b = buffer;
    size_t dsz = 32, dl = 0;
    uint8_t *data = malloc(dsz);
    uint32_t i, acc = 0, c = 0;

    if (!data) {
        perror("Allocating data buffer");
        return -1;
    }
    while (fgets((char *) b, sizeof(buffer) - (b - buffer), kf)) {
        if (memcmp(buffer, "-----", 5) == 0) break;
        for (i = 0; i < sizeof(buffer) && buffer[i]; i++) {
            int val = b64_tab[buffer[i]];
            if (val == -2) continue;
            if (val == -1) {
                fprintf(stderr, "Illegal base 64 character \"%c\" in \"%s\"\n",
                        buffer[i], fname);
                goto fail;
            }
            acc = acc << 6 | val;
            if (++c == 4) {
                if (dsz - dl < 3) {
                    if (grow_buffer(&data, dsz * 2, &dsz) != 0) goto fail;
                }
                data[dl++] = (acc >> 16) & 0xff;
                data[dl++] = (acc >>  8) & 0xff;
                data[dl++] =  acc        & 0xff;
                acc = 0;
                c = 0;
            }
        }
    }
    if (c > 1) {
        if (dsz - dl < c - 1) {
            if (grow_buffer(&data, dsz + c - 1, &dsz) != 0) goto fail;
        }
        if (c == 2) {
            data[dl++] = (acc >> 4) & 0xff;
        } else {
            data[dl++] = (acc >> 10) & 0xff;
            data[dl++] = (acc >>  2) & 0xff;
        }
    }
    *data_out = data;
    *data_len = dl;
    return 0;
 fail:
    free(data);
    return -1;
}

int get_passphrase(const char *prompt, uint8_t **passwd_out, size_t *len_out) {
    int tty_fd;
    uint8_t *passwd = NULL;
    size_t len = 0, sz = 1024;
    ssize_t got;
    struct termios t_orig, t_new;
    int noecho_set = 0, sigblock_res = -1;
    int siglist[11] = { SIGALRM, SIGHUP, SIGPIPE, SIGPROF, SIGQUIT, SIGINT,
                        SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU, SIGVTALRM };
    sigset_t s_blocked, s_orig;
    size_t i;
    ssize_t ignored HTS_UNUSED;

    tty_fd = open(TTY_NAME, O_RDWR);
    if (tty_fd < 0) {
        fprintf(stderr, "[%s] Couldn't open terminal : %s\n",
                __func__, strerror(errno));
        return -1;
    }

    passwd = malloc(sz);
    if (!passwd) goto fail;

    if (tcgetattr(tty_fd, &t_orig) != 0) {
        fprintf(stderr, "[%s] Getting terminal settings : %s\n",
                __func__, strerror(errno));
        goto fail;
    }
    memcpy(&t_new, &t_orig, sizeof(t_new));
    t_new.c_lflag &= ~(ECHO | ECHONL);
    if (t_orig.c_lflag != t_new.c_lflag) {
        if (tcsetattr(tty_fd, TCSAFLUSH, &t_new) != 0) {
            fprintf(stderr, "[%s] Setting terminal settings : %s\n",
                    __func__, strerror(errno));
            goto fail;
        }
        noecho_set = 1;
        sigemptyset(&s_blocked);
        for (i = 0; i < sizeof(siglist) / sizeof(siglist[0]); i++)
            sigaddset(&s_blocked, siglist[i]);
        sigblock_res = pthread_sigmask(SIG_BLOCK, &s_blocked, &s_orig);
    }

    ignored = write(tty_fd, prompt, strlen(prompt));

    do {
        got = 1;
        while (len < sz) {
            got = read(tty_fd, passwd + len, sz - len);
            if (got > 0) len += got;
            if (len > 0 && (passwd[len - 1] == '\n' || passwd[len - 1] == '\r'))
                break;
            if (got <= 0) break;
        }
    } while (got < 0 && (errno == EAGAIN || errno == EINTR));
    if (got < 0) {
        fprintf(stderr, "[%s] Reading from \"%s\" : %s\n",
                __func__, TTY_NAME, strerror(errno));
        goto fail;
    }

    ignored = write(tty_fd, "\r\n", 2);

    while (len > 0 && (passwd[len - 1] == '\n' || passwd[len - 1] == '\r'))
        len--;

    if (noecho_set && memcmp(&t_orig, &t_new, sizeof(t_orig)) != 0
        && tcsetattr(tty_fd, TCSAFLUSH, &t_orig) != 0) {
        fprintf(stderr, "[%s] Restoring terminal settings : %s\n",
                __func__, strerror(errno));
        noecho_set = 0;
        goto fail;
    }
    if (sigblock_res == 0) {
        pthread_sigmask(SIG_SETMASK, &s_orig, NULL);
    }

    close(tty_fd);
    *passwd_out = passwd;
    *len_out = len;
    return 0;

 fail:
    if (noecho_set) {
        if (tcsetattr(tty_fd, TCSAFLUSH, &t_orig) != 0) {
            fprintf(stderr, "[%s] Restoring terminal settings : %s\n",
                    __func__, strerror(errno));
        }
        if (sigblock_res == 0) {
            pthread_sigmask(SIG_SETMASK, &s_orig, NULL);
        }
    }
    if (passwd) {
        secure_zero(passwd, len);
        free(passwd);
    }
    close(tty_fd);
    return -1;
}

static int decrypt_crypt4gh_key(uint8_t *data, size_t data_len,
                                uint8_t *key, size_t key_len) {
    const char magic[] = "c4gh-v1";
    const size_t magic_len = sizeof(magic) - 1;
    const char kdfname[] = "scrypt";
    const char ciphername[] = "chacha20_poly1305";
    uint8_t *passwd = NULL;
    size_t passwd_len = 0;
    uint8_t hdr_key[CC20_KEY_LEN];
    uint8_t *salt, *iv;
    size_t decrypt_len;
    int res = -1;
    uint16_t salt_len;
    uint16_t slen;
    // uint32_t rounds;  Unused for scrypt

    // Magic
    if (data_len < magic_len || memcmp(data, magic, magic_len) != 0) goto out;
    data_len -= magic_len; data += magic_len;

    // kdfname
    if (data_len < 2) goto out;
    slen = (data[0] << 8) | data[1];
    data_len -= 2; data += 2;
    if (data_len < slen) goto out;
    if (data_len != sizeof(kdfname) - 1
        && memcmp(data, kdfname, sizeof(kdfname) - 1) != 0) goto out;
    data_len -= slen; data += slen;

    // rounds and salt
    if (data_len < 2) goto out;
    slen = (data[0] << 8) | data[1];
    data_len -= 2; data += 2;
    if (data_len < slen) goto out;
    if (slen < 4) goto out;
    // rounds not used for scrypt
    // rounds = (((uint32_t) data[0] << 24)
    //          | (data[1] << 16) | (data[2] << 8) | data[3]);
    data_len -= 4; data += 4; slen -= 4;
    salt = data;
    salt_len = slen;
    data_len -= slen; data += slen;

    // ciphername
    if (data_len < 2) return -1;
    slen = (data[0] << 8) | data[1];
    data_len -= 2; data += 2;
    if (data_len != sizeof(ciphername) - 1
        && memcmp(data, ciphername, sizeof(ciphername) - 1) != 0) goto out;
    data_len -= slen; data += slen;

    // iv + encrypted data
    if (data_len < 2) goto out;
    slen = (data[0] << 8) | data[1];
    data_len -= 2; data += 2;
    if (data_len < slen) goto out;
    if (slen < CC20_IV_LEN) goto out;
    iv = data;
    data += CC20_IV_LEN;
    slen -= CC20_IV_LEN;

    if (get_passphrase("Passphrase? ", &passwd, &passwd_len) != 0) goto out;

    if (salsa_kdf(hdr_key, sizeof hdr_key,
                  passwd, passwd_len, salt, salt_len) != 0)
        goto out;

    if (chacha20_decrypt(key, &decrypt_len, data, slen,
                         iv, hdr_key) != 0)
        goto out;

    res = 0;
 out:
    secure_zero(hdr_key, sizeof hdr_key);
    if (passwd) {
        secure_zero(passwd, passwd_len);
        free(passwd);
    }
    return res;
}

static int encrypt_crypt4gh_key(uint8_t *key, size_t key_len,
                                uint8_t **data_out, size_t *data_len_out) {
    const char magic[] = "c4gh-v1";
    const size_t magic_len = sizeof(magic) - 1;
    const char kdfname[] = "scrypt";
    const char ciphername[] = "chacha20_poly1305";
    const size_t salt_len = 16;
    const size_t iv_len = CC20_IV_LEN;
    const size_t mac_len = P1305_MAC_LEN;
    uint8_t *passwd = NULL, *passwd2 = NULL;
    size_t passwd_len = 0, passwd_len2 = 0;
    uint8_t hdr_key[CC20_KEY_LEN];
    uint8_t *data = NULL, *d, *salt, *iv;
    size_t data_len, encrypt_len;
    int res = -1;

    if (get_passphrase("Passphrase? ", &passwd, &passwd_len) != 0) goto out;
    if (get_passphrase("Repeat passphrase? ", &passwd2, &passwd_len2) != 0)
        goto out;
    if (passwd_len != passwd_len2
        || memcmp(passwd, passwd2, passwd_len) != 0) {
        fprintf(stderr, "Passphrases don't match\n");
        goto out;
    }

    data_len = (magic_len
                + 2 + sizeof(kdfname) - 1
                + 2 + 4 + salt_len
                + 2 + sizeof(ciphername) - 1
                + 2 + iv_len + key_len + mac_len
                + 2);
    data = malloc(data_len);
    if (!data) goto out;
    d = data;
    // Magic
    memcpy(d, magic, magic_len); d += magic_len;
    // kdfname
    *d++ = ((sizeof(kdfname) - 1) >> 8) & 0xff;
    *d++ = ((sizeof(kdfname) - 1)     ) & 0xff;
    memcpy(d, kdfname, sizeof(kdfname) - 1);
    d += sizeof(kdfname) - 1;
    // rounds and salt
    *d++ = ((4 + salt_len) >> 8) & 0xff;
    *d++ = ((4 + salt_len)     ) & 0xff;
    memset(d, 0, 4); d += 4;
    salt = d;
    if (get_random_bytes(d, salt_len) < 0) goto out;
    d += salt_len;
    // ciphername
    *d++ = ((sizeof(ciphername) - 1) >> 8) & 0xff;
    *d++ = ((sizeof(ciphername) - 1)     ) & 0xff;
    memcpy(d, ciphername, sizeof(ciphername) - 1); d += sizeof(ciphername) - 1;
    // iv + encrypted data
    *d++ = ((iv_len + key_len + mac_len) >> 8) & 0xff;
    *d++ = ((iv_len + key_len + mac_len)     ) & 0xff;
    iv = d;
    if (get_random_bytes(d, iv_len) < 0) goto out;
    d += iv_len;
    if (salsa_kdf(hdr_key, sizeof(hdr_key),
                  passwd, passwd_len, salt, salt_len) != 0)
        goto out;
    if (chacha20_encrypt(d, &encrypt_len, key, key_len, iv, hdr_key) != 0)
        goto out;

    d += encrypt_len;
    // comment
    *d++ = 0;
    *d++ = 0;

    assert(d - data == data_len);

    *data_out = data;
    *data_len_out = data_len;
    res = 0;
 out:
    secure_zero(hdr_key, sizeof(hdr_key));
    if (passwd)  { secure_zero(passwd,  passwd_len);  free(passwd);  }
    if (passwd2) { secure_zero(passwd2, passwd_len2); free(passwd2); }
    return res;
}

int read_key_file(const char *fname, uint8_t *key_out, size_t key_len,
                  int *is_public_out) {
    char buffer[80], *c;
    FILE *kf;
    uint8_t *data;
    size_t data_len;
    int res = 0;
    int is_public = 0;
    if (!fname) {
        fprintf(stderr, "[%s] No filename given\n", __func__);
        return -1;
    }
    kf = fopen(fname, "r");
    if (!kf) {
        fprintf(stderr, "Couldn't open \"%s\" : %s\n", fname, strerror(errno));
        return -1;
    }
    if (!fgets(buffer, sizeof(buffer), kf)) {
        fprintf(stderr, "Couldn't read first line of \"%s\" : %s\n",
                fname, feof(kf) ? "end of file" : strerror(errno));
        fclose(kf);
        return -1;
    }
    if ((c = strrchr(buffer, '\n')) != NULL) *c = '\0';
    if (c && c > buffer && *(c - 1) == '\r') *(c - 1) = '\0';
    is_public = (strcmp(buffer, "-----BEGIN CRYPT4GH PUBLIC KEY-----") == 0);
    if (is_public ||
        strcmp(buffer, "-----BEGIN CRYPT4GH PRIVATE KEY-----") == 0) {
        res = get_base64_wrapped_data(fname, kf, &data, &data_len);
        if (res == 0) {
            if (data_len < key_len) {
                fprintf(stderr, "Key in \"%s\" is too short\n", fname);
                res = -1;
            } else {
                memcpy(key_out, data, key_len);
            }
            free(data);
        }
    } else if (strcmp(buffer,
                      "-----BEGIN CRYPT4GH ENCRYPTED PRIVATE KEY-----") == 0
               || strcmp(buffer,
                         "-----BEGIN ENCRYPTED PRIVATE KEY-----") == 0) {
        res = get_base64_wrapped_data(fname, kf, &data, &data_len);
        if (res == 0) {
            res = decrypt_crypt4gh_key(data, data_len, key_out, key_len);
            free(data);
        }
    } else {
        fprintf(stderr, "Unsupported key type in \"%s\"\n", fname);
        res = -1;
    }
    if (fclose(kf) < 0) {
        fprintf(stderr, "Error on closing \"%s\" : %s\n",
                fname, strerror(errno));
        res = -1;
    }
    if (res == 0 && is_public_out) *is_public_out = is_public;
    return res;
}

int write_key_file(const char *fname, uint8_t *key, size_t key_len,
                   int is_public, int is_encrypted) {
    int fd;
    FILE *kf = NULL;
    const static char b64[65] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        "ghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    uint8_t *encrypted = NULL, *data = key;
    size_t len = key_len;

    fd = open(fname, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
              is_public ? 0666 : 0600);
    if (!fd) {
        fprintf(stderr, "Couldn't open \"%s\" for writing : %s\n",
                fname, strerror(errno));
        return -1;
    }
    kf = fdopen(fd, "wb");
    if (!kf) {
        perror("fdopen");
        close(fd);
        goto fail;
    }

    if (is_encrypted) {
        if (encrypt_crypt4gh_key(key, key_len, &encrypted, &len) != 0) {
            fprintf(stderr, "Encryption failed\n");
            goto fail;
        }
        data = encrypted;
    }

    fprintf(kf, "-----BEGIN CRYPT4GH %s%s KEY-----\n",
            is_encrypted ? "ENCRYPTED " : "",
            is_public ? "PUBLIC" : "PRIVATE");
    for (i = 0; i + 2 < len; i += 3) {
        putc(b64[(data[i] >> 2) & 0x3f], kf);
        putc(b64[((data[i]     &   3) << 4) | ((data[i + 1] >> 4) & 0xf)], kf);
        putc(b64[((data[i + 1] & 0xf) << 2) | ((data[i + 2] >> 6) &   3)], kf);
        putc(b64[(data[i + 2] & 0x3f)], kf);
    }
    switch (len - i) {
    case 1:
        putc(b64[(data[i] >> 2) & 0x3f], kf);
        putc(b64[(data[i] & 3) << 4], kf);
        putc('=', kf);
        putc('=', kf);
        break;
    case 2:
        putc(b64[(data[i] >> 2) & 0x3f], kf);
        putc(b64[((data[i] & 3) << 4) | ((data[i + 1] >> 4) & 0xf)], kf);
        putc(b64[((data[i + 1] & 0xf) << 2)], kf);
        putc('=', kf);
        break;
    default:
        break;
    }
    fprintf(kf, "\n-----END CRYPT4GH %s%s KEY-----\n",
            is_encrypted ? "ENCRYPTED " : "",
            is_public ? "PUBLIC" : "PRIVATE");
    if (fclose(kf) != 0) {
        fprintf(stderr, "Error closing \"%s\" : %s\n", fname, strerror(errno));
        goto fail;
    }
    free(encrypted);
    return 0;

 fail:
    if (kf) fclose(kf);
    unlink(fname);
    free(encrypted);
    return -1;
}
