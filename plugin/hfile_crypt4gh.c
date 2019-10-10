/*  hfile_crypt4gh.c -- Encrypted file backend

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
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include <htslib/hts_endian.h>
#include <htslib/hts.h>
#include "hfile_internal.h"
#include <crypt4gh_agent_defs.h>
#include <sodium_if.h>
#include <keyfile.h>
#include <base64.h>


#ifndef ENOTSUP
#define ENOTSUP EINVAL
#endif

#define CRYPTO_BLOCK_LENGTH 65536
#define CC20_P1305_BLOCK_LEN (CRYPTO_BLOCK_LENGTH + CC20_IV_LEN + P1305_MAC_LEN)
#define MAGIC "crypt4gh"

typedef enum {
    data_encryption_parameters = 0,
    data_edit_list = 1
} headerPacketType;

typedef enum {
    X25519_chacha20_ietf_poly1305 = 0
} headerCryptType;

typedef enum {
    chacha20_ietf_poly1305 = 0
} dataCryptType;

typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
} editMapping;

typedef struct {
    hFILE base;
    hFILE *parent;
    off_t real_data_start;
    uint8_t *crypt_in;
    uint8_t *crypt_out;
    uint8_t *key;
    uint8_t *iv;
    editMapping *edit_map;
    uint16_t nkeys;
    uint16_t curr_key;
    uint32_t crypt_buf_used;
    off_t curr_offset;
    dataCryptType type;
    int keylen;
    int ivlen;
    int blocklen;
    int shift;
    uint32_t edit_map_len;
    uint32_t curr_map;
} hFILE_crypt4gh;

static inline void increment_iv(uint8_t *iv, size_t iv_len) {
    size_t i;
    uint16_t c = 1;
    for (i = 0; i < iv_len; i++) {
        c += iv[i];
        iv[i] = c & 0xff;
        c >>= 8;
    }
}

static int write_to_backend(hFILE_crypt4gh *fp, size_t len) {
    size_t done = 0;
    ssize_t n;

    while (done < len) {
        n = fp->parent->backend->write(fp->parent,
                                       fp->crypt_out + done, len - done);
        if (n < 0) {
            fp->base.has_errno = errno;
            if (hts_verbose > 1)
                fprintf(stderr, "[E::%s] Write failed: %s\n",
                        __func__, strerror(errno));
            return -1;
        }
        done += n;
        fp->parent->offset += n;
    }

    return 0;
}

static inline size_t get_block_length(hFILE_crypt4gh *fp) {
    switch (fp->type) {
    case chacha20_ietf_poly1305: return CC20_P1305_BLOCK_LEN;
    default:                     return 0;
    }
}

static inline size_t get_iv_length(hFILE_crypt4gh *fp) {
    switch (fp->type) {
    case chacha20_ietf_poly1305: return CC20_IV_LEN;
    default:                     return 0;
    }
}

static inline size_t get_mac_length(hFILE_crypt4gh *fp) {
    switch (fp->type) {
    case chacha20_ietf_poly1305: return P1305_MAC_LEN;
    default:                     return 0;
    }
}

static int send_all(int fd, uint8_t *buffer, size_t len) {
    ssize_t bytes;
    size_t l = 0;
    do {
        do {
            bytes = send(fd, buffer + l, len - l, 0);
        } while (bytes < 0 && (errno == EINTR
                               || errno == EWOULDBLOCK
                               || errno == EAGAIN));
        l += bytes >= 0 ? bytes : 0;
    } while (bytes >= 0 && l < len);
    return bytes >= 0 ? 0 : -1;
}

static ssize_t recv_all(int fd, uint8_t *buffer, size_t len) {
    ssize_t bytes;
    size_t l = 0;
    do {
        do {
            bytes = recv(fd, buffer + l, len - l, 0);
        } while (bytes < 0 && (errno == EINTR
                               || errno == EWOULDBLOCK
                               || errno == EAGAIN));
        l += bytes > 0 ? bytes : 0;
    } while (bytes > 0 && l < len);
    return bytes >= 0 ? l : -1;
}

static ssize_t get_message(int fd, uint8_t *buffer, size_t max_sz) {
    uint8_t tmp[4];
    uint32_t msg_len;
    ssize_t bytes = recv_all(fd, tmp, sizeof(tmp));
    if (bytes != sizeof(tmp)) return -1;
    msg_len = le_to_u32(tmp);
    if (msg_len > max_sz) return -1;
    bytes = recv_all(fd, buffer, msg_len);
    return bytes == msg_len ? bytes : -1;
}

static int connect_agent(uint8_t rx[X25519_SESSION_LEN],
                         uint8_t tx[X25519_SESSION_LEN],
                         uint8_t iv[CC20_IV_LEN]) {
    const char *agent = getenv("CRYPT4GH_AGENT");
    const char *agent_pk_base64 = getenv("CRYPT4GH_PK");
    struct sockaddr_un agent_addr;
    uint8_t pk[X25519_PK_LEN], sk[X25519_SK_LEN], agent_pk[X25519_PK_LEN];
    uint8_t buffer[256];
    int agent_fd = -1;

    if (!agent) {
        fprintf(stderr, "[E::%s] CRYPT4GH_AGENT not set\n", __func__);
        errno = EIO;
        return -1;
    }
    if (!agent_pk_base64) {
        fprintf(stderr, "[E::%s] CRYPT4GH_PK not set\n", __func__);
        errno = EIO;
        return -1;
    }
    if (from_base64(agent_pk_base64, agent_pk, sizeof(agent_pk),
                    "CRYPT4GH_PK environment variable") < sizeof(agent_pk)) {
        fprintf(stderr, "[E::%s] CRYPT4GH_PK not decodable\n", __func__);
        errno = EIO;
        return -1;
    }

    memset(&agent_addr, 0, sizeof(agent_addr));
    agent_addr.sun_family = AF_UNIX;
    strncpy(agent_addr.sun_path, agent, sizeof(agent_addr.sun_path) - 1);
    if (strcmp(agent, agent_addr.sun_path) != 0) {
        fprintf(stderr, "[E::%s] CRYPT4GH_AGENT path name too long\n",
                __func__);
        errno = EIO;
        return -1;
    }

    agent_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (!agent_fd) {
        fprintf(stderr, "[E::%s] Couldn't make agent socket : %s\n",
                __func__, strerror(errno));
        return -1;
    }

    if (connect(agent_fd, (const struct sockaddr *) &agent_addr,
                sizeof(struct sockaddr_un)) != 0) {
        fprintf(stderr, "[E::%s] Couldn't connect to agent : %s\n",
                __func__, strerror(errno));
        goto fail;
    }

    if (get_X25519_keypair(pk, sk) != 0) {
        fprintf(stderr, "[E::%s] Couldn't generate X25519 key pair\n",
                __func__);
        goto fail;
    }

    u32_to_le(X25519_PK_LEN + 4, buffer);
    u16_to_le(c4gh_msg_connect, buffer + 4);
    u16_to_le(c4gh_proto_v_1, buffer + 6);
    memcpy(buffer + 8, pk, X25519_PK_LEN);
    if (send_all(agent_fd, buffer, X25519_PK_LEN + 8) != 0) goto fail;
    if (get_message(agent_fd, buffer, sizeof(buffer)) < 4)
        goto fail;

    if (le_to_u16(buffer) != c4gh_msg_connect
        || le_to_u16(buffer + 2) != c4gh_proto_v_1) {
        fprintf(stderr, "[E::%s] Unexpected reply from agent\n", __func__);
        goto fail;
    }
    if (get_X25519_client_session_keys(rx, tx, pk, sk, agent_pk) != 0) {
        fprintf(stderr, "[E::%s] Couldn't generate session keys\n", __func__);
        goto fail;
    }
    if (get_random_bytes(iv, CC20_IV_LEN) != 0) {
        fprintf(stderr, "[E::%s] Couldn't generate session iv\n", __func__);
        goto fail;
    }
    secure_zero(sk, sizeof(sk));
    return agent_fd;

 fail:
    close(agent_fd);
    secure_zero(sk, sizeof(sk));
    secure_zero(rx, X25519_SESSION_LEN);
    secure_zero(tx, X25519_SESSION_LEN);
    return -1;
}

static int send_to_agent(int agent_fd, uint8_t *buffer, size_t sz,
                         uint8_t tx[X25519_SESSION_LEN],
                         uint8_t iv[CC20_IV_LEN]) {
    uint8_t encrypted[256 + CC20_IV_LEN + P1305_MAC_LEN];
    size_t encrypt_len;

    if (sz > sizeof(encrypted) - 4 - CC20_IV_LEN - P1305_MAC_LEN) {
        fprintf(stderr, "[E::%s] Message too long\n", __func__);
        return -1;
    }
    memcpy(encrypted + 4, iv, CC20_IV_LEN);
    if (chacha20_encrypt(encrypted + 4 + CC20_IV_LEN, &encrypt_len,
                         buffer, sz, iv, tx) != 0) {
        fprintf(stderr, "[E::%s] Encryption failed\n", __func__);
        return -1;
    }
    constant_time_increment(iv, CC20_IV_LEN);
    assert(encrypt_len == sz + P1305_MAC_LEN);
    encrypt_len += CC20_IV_LEN;
    u32_to_le(encrypt_len, encrypted);
    if (send_all(agent_fd, encrypted, encrypt_len + 4) != 0)
        return -1;
    return 0;
}

static ssize_t read_from_agent(int agent_fd, uint8_t *buffer, size_t sz,
                               uint8_t rx[X25519_SESSION_LEN]) {
    uint8_t encrypted[512];
    ssize_t len;
    size_t decrypt_len;

    if (sz > sizeof(encrypted)) {
        fprintf(stderr, "[E::%s] Message too long\n", __func__);
        return -1;
    }

    len = get_message(agent_fd, encrypted, sizeof(encrypted));
    if (len < 0) {
        fprintf(stderr, "[E::%s] No reply from agent\n", __func__);
        return -1;
    }
    if (len < CC20_IV_LEN + P1305_MAC_LEN) {
        fprintf(stderr, "[E::%s] Agent reply too short\n", __func__);
        return -1;
    }
    if (chacha20_decrypt(buffer, &decrypt_len,
                         encrypted + CC20_IV_LEN, len - CC20_IV_LEN,
                         encrypted, rx) != 0) {
        fprintf(stderr, "[E::%s] Failed to decrypt agent reply\n", __func__);
        return -1;
    }
    return decrypt_len;
}

static int write_encryption_header(hFILE_crypt4gh *fp) {
    char *pk_name = getenv("CRYPT4GH_PUBLIC");
    size_t pk_name_len;
    ssize_t len;
    uint8_t rx[X25519_SESSION_LEN], tx[X25519_SESSION_LEN], iv[CC20_IV_LEN];
    uint8_t buffer[128], *p = buffer;
    int agent_fd = -1;

    assert(fp->keylen <= CC20_KEY_LEN);
    if (!pk_name) pk_name = "";
    pk_name_len = strlen(pk_name) + 1;
    if (pk_name_len + fp->keylen + 20 > sizeof(buffer)) {
        fprintf(stderr, "[E::%s] CRYPT4GH_PUBLIC too long\n", __func__);
        return -1;
    }

    agent_fd = connect_agent(rx, tx, iv);
    if (agent_fd < 0) return -1;

    u16_to_le(c4gh_msg_hdr_encrypt, p); p += 2;          // Agent protocol
    u16_to_le(pk_name_len, p); p += 2;                   // PK name length
    memcpy(p, pk_name, pk_name_len); p += pk_name_len;   // PK name

    u32_to_le(1, p); p += 4;                             // Header version
    u32_to_le(X25519_chacha20_ietf_poly1305, p); p += 4; // Header encryption

    u32_to_le(data_encryption_parameters, p); p += 4;    // Header packet type
    u32_to_le(chacha20_ietf_poly1305, p); p += 4;        // Data encryption
    memcpy(p, fp->key, fp->keylen); p += fp->keylen;     // Data key

    if (send_to_agent(agent_fd, buffer, p - buffer, tx, iv) != 0)
        goto fail;

    len = read_from_agent(agent_fd, buffer, sizeof(buffer), rx);
    if (len < 2) goto fail;
    if (le_to_u16(buffer) != c4gh_msg_hdr_encrypt) goto fail;

    close(agent_fd);
    secure_zero(rx, sizeof(rx));
    secure_zero(tx, sizeof(tx));
    secure_zero(iv, sizeof(iv));

    p = fp->crypt_out;
    memcpy(p, MAGIC, 8); p += 8;                   // Magic number
    u32_to_le(1, p); p += 4;                       // Format version
    u32_to_le(1, p); p += 4;                       // Number of header packets
    u32_to_le(len - 2 + 4, p); p += 4;             // Packet length
    memcpy(p, buffer + 2, len - 2); p += len - 2;  // Packet data
    fp->real_data_start = len - 2 + 20;

    if (write_to_backend(fp, len - 2 + 20) != 0) return -1;
    return 0;

 fail:
    close(agent_fd);
    secure_zero(rx, sizeof(rx));
    secure_zero(tx, sizeof(tx));
    secure_zero(iv, sizeof(iv));
    return -1;
}

static int read_encryption_header(hFILE_crypt4gh *fp) {
    const char *sk_name = getenv("CRYPT4GH_SECRET");
    size_t sk_name_len;
    ssize_t len;
    uint8_t rx[X25519_SESSION_LEN], tx[X25519_SESSION_LEN], iv[CC20_IV_LEN];
    uint8_t buffer[512];
    uint8_t *new_keys;
    uint32_t pkt_len, npackets, pkt;
    int agent_fd = -1;

    assert(fp->key != NULL && fp->keylen >= CC20_KEY_LEN);

    if (!sk_name) sk_name = "";
    sk_name_len = strlen(sk_name) + 1;

    if (hread(fp->parent, buffer, 16) != 16) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Failed to read encryption magic number\n",
                    __func__);
        return -1;
    }
    if (memcmp(buffer, MAGIC, 8) != 0) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Incorrect magic number\n",
                    __func__);
        return -1;
    }
    if (le_to_u32(buffer + 8) != 1) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] Incorrect version number\n",
                    __func__);
        return -1;
    }
    npackets = le_to_u32(buffer + 12);
    if (npackets == 0) {
        if (hts_verbose > 1)
            fprintf(stderr, "[E::%s] crypt4gh header is empty\n", __func__);
        return -1;
    }

    agent_fd = connect_agent(rx, tx, iv);
    if (agent_fd < 0) return -1;

    for (pkt = 0; pkt < npackets; pkt++) {
        if (hread(fp->parent, buffer, 4) != 4) {
            if (hts_verbose > 1)
                fprintf(stderr, "[E::%s] Failed to read header packet length\n",
                        __func__);
            goto fail;
        }
        pkt_len = le_to_u32(buffer);
        if (pkt_len < 8) {
            if (hts_verbose > 1)
                fprintf(stderr, "[E::%s] Header packet too short (%u buffer)\n",
                        __func__, (unsigned int) pkt_len);
            goto fail;
        }
        pkt_len -= 4;
        if (pkt_len > sizeof(buffer) - 4) {
            if (hts_verbose > 1)
                fprintf(stderr, "[E::%s] Header packet too long (%u buffer)\n",
                        __func__, (unsigned int) pkt_len);
            goto fail;
        }

        if (pkt_len + sk_name_len + 4 > sizeof(buffer)) {
            if (hts_verbose > 1)
                fprintf(stderr, "[E::%s] CRYPT4GH_SECRET too long\n",
                        __func__);
            goto fail;
        }

        u16_to_le(c4gh_msg_hdr_decrypt, buffer);
        u16_to_le(sk_name_len, buffer + 2);
        memcpy(buffer + 4, sk_name, sk_name_len);
        if (hread(fp->parent, buffer + 4 + sk_name_len, pkt_len) != pkt_len) {
            if (hts_verbose > 1)
                fprintf(stderr, "[E::%s] Failed to read header packet\n",
                        __func__);
            goto fail;
        }
        if (send_to_agent(agent_fd, buffer, 4 + sk_name_len + pkt_len,
                          tx, iv) != 0) {
            goto fail;
        }
        len = read_from_agent(agent_fd, buffer, sizeof(buffer), rx);
        if (len < 2) goto fail;
        if (le_to_u16(buffer) == c4gh_msg_hdr_decrypt_fail) continue;
        if (le_to_u16(buffer) != c4gh_msg_hdr_decrypt) goto fail;
        if (len < 6) goto fail;
        switch (le_to_u32(buffer + 2)) {
        case data_encryption_parameters:
            if (len < 10 + CC20_KEY_LEN) goto fail;
            if (le_to_u32(buffer + 6) != chacha20_ietf_poly1305) goto fail;
            new_keys = realloc(fp->key, fp->keylen * (fp->nkeys + 1));
            if (!new_keys) goto fail;
            fp->key = new_keys;
            memcpy(fp->key + fp->keylen * fp->nkeys, buffer + 10, CC20_KEY_LEN);
            fp->nkeys++;
            break;
        case data_edit_list: {
            uint32_t nlengths, i;
            uint64_t pos = 0, offset = 0;
            if (len < 10) goto fail;
            nlengths = le_to_u32(buffer + 6);
            if (len - 10 < 8ULL * nlengths) goto fail;
            free(fp->edit_map);
            fp->edit_map = malloc(sizeof(fp->edit_map[0]) * (nlengths / 2 + 1));
            if (!fp->edit_map) goto fail;
            for (i = 0; i < nlengths; i+=2) {
                offset += le_to_u64(buffer + 10 + 8 * i);
                fp->edit_map[i/2].start = pos;
                if (i + 1 < nlengths) {
                    pos += le_to_u64(buffer + 10 + 8 * i + 8);
                    fp->edit_map[i/2].end = pos;
                } else {
                    fp->edit_map[i/2].end = UINT64_MAX;
                }
                fp->edit_map[i/2].offset = offset;
            }
            fp->edit_map_len = nlengths / 2;
            break;
        }
        default:
            goto fail;
        }
    }

    fp->real_data_start = htell(fp->parent);

    close(agent_fd);
    secure_zero(rx, sizeof(rx));
    secure_zero(tx, sizeof(tx));
    secure_zero(iv, sizeof(iv));
    secure_zero(buffer, sizeof(buffer));
    return 0;

 fail:
    close(agent_fd);
    secure_zero(rx, sizeof(rx));
    secure_zero(tx, sizeof(tx));
    secure_zero(iv, sizeof(iv));
    secure_zero(buffer, sizeof(buffer));
    return 0;
}

static ssize_t crypt4gh_read_unedited(hFILE_crypt4gh *fp, void *buffer,
                                      size_t nbytes, off_t offset) {
    ssize_t i = 0;
    uint8_t *buf = (uint8_t *) buffer;
    off_t orig_offset = offset;
    // Find out how much data is available in the current block
    off_t available = ((offset >= fp->curr_offset
                        && offset - fp->curr_offset < fp->crypt_buf_used)
                       ? fp->crypt_buf_used - (offset - fp->curr_offset)
                       : 0);
    ssize_t to_copy;
    size_t block_len = get_block_length(fp);
    size_t iv_len = get_iv_length(fp);
    size_t mac_len = get_mac_length(fp);
    size_t decrypt_len = 0;
    uint16_t curr_key;

    if (!fp->parent || !block_len || offset < fp->curr_offset) {
        errno = EIO;
        return EOF;
    }

    while (i < nbytes) {
        ssize_t got = block_len;

        // If no data available, read a new block and decrypt
        if (available == 0) {
            // If last block was short, must have hit EOF, in which case
            // don't try to read any more.
            if (fp->crypt_buf_used != 0
                && fp->crypt_buf_used != CRYPTO_BLOCK_LENGTH) {
                break;
            }

            fp->curr_offset += fp->crypt_buf_used;
            got = hread(fp->parent, fp->crypt_in, block_len);
            if (got < 0) return EOF; // Error
            if (got < iv_len + mac_len) break;  // At end of file
            curr_key = fp->curr_key;
            for (;;) { // Try all keys to find one that works
                if (chacha20_decrypt(fp->crypt_out, &decrypt_len,
                                     fp->crypt_in + iv_len, got - iv_len,
                                     fp->crypt_in,
                                     fp->key + fp->keylen * curr_key) == 0) {
                    break;
                }
                if (++curr_key >= fp->nkeys) curr_key = 0;
                if (curr_key == fp->curr_key) {
                    errno = EIO;
                    return EOF;
                }
            }
            fp->curr_key = curr_key;
            assert(decrypt_len <= CRYPTO_BLOCK_LENGTH);
            fp->crypt_buf_used = decrypt_len;
            offset = orig_offset + i; // Account for data already read
            available = offset - fp->curr_offset < decrypt_len ? decrypt_len : 0;
        }

        // Copy available data to the output buffer
        to_copy = available;
        if (to_copy > nbytes - i) to_copy = nbytes - i;
        if (to_copy) {
            if (buf) {
                memcpy(buf + i,
                       fp->crypt_out + (offset - fp->curr_offset),
                       to_copy);
            }
            i += to_copy;
            if (to_copy == available) available = 0;
        }

        // Stop if last read was short, as will be at end of file
        if (got < CRYPTO_BLOCK_LENGTH) break;
    }

    return i;
}

static ssize_t crypt4gh_read(hFILE *fpv, void *buffer, size_t nbytes) {
    hFILE_crypt4gh *fp = (hFILE_crypt4gh *) fpv;
    // Need to adjust fp->base.offset by the number of bytes already read
    // from the buffer to find the true file position
    off_t offset = fp->base.offset + (fp->base.end - fp->base.buffer);
    size_t total = 0;
    ssize_t got;
    uint32_t curr = fp->curr_map;

    if (!fp->edit_map)
        return crypt4gh_read_unedited(fp, buffer, nbytes, offset);

    while (total < nbytes) {
        size_t bytes;
        assert(fp->edit_map[curr].start <= offset);
        assert(offset <= fp->edit_map[curr].end);

        // Work out and get bytes in current range
        bytes = fp->edit_map[curr].end - offset;
        if (bytes > nbytes - total) bytes = nbytes - total;

        got = crypt4gh_read_unedited(fp, buffer + total, bytes,
                                     offset + fp->edit_map[curr].offset);
        if (got < 0) return got;

        total += got;
        offset += got;
        if (got < bytes) return total;  // EOF
        if (offset < fp->edit_map[curr].end) break;

        // Discard data to get to the next range
        if (curr == fp->edit_map_len - 1) return total;  // Edit list sets EOF

        assert(fp->edit_map[curr + 1].offset >= fp->edit_map[curr].offset);
        bytes = fp->edit_map[curr + 1].offset - fp->edit_map[curr].offset;
        got = crypt4gh_read_unedited(fp, NULL, bytes,
                                     offset + fp->edit_map[curr].offset);
        if (got < 0) return got;
        curr++;
        fp->curr_map++;
        if (got < bytes) return total; // Fell off end of file
    }
    return total;
}

static ssize_t crypt4gh_write(hFILE *fpv, const void *buffer, size_t nbytes) {
    hFILE_crypt4gh *fp = (hFILE_crypt4gh *) fpv;
    uint8_t *buf = (uint8_t *) buffer;
    ssize_t bytes = 0;
    size_t iv_len = get_iv_length(fp);
    size_t encrypt_len = 0;

    if (!fp->parent) {
        errno = EIO;
        return EOF;
    }

    while (bytes < nbytes) {
        // Copy up to CRYPTO_BLOCK_LENGTH into fp->crypt_in
        size_t to_copy = CRYPTO_BLOCK_LENGTH - fp->crypt_buf_used;
        if (to_copy > nbytes - bytes) to_copy = nbytes - bytes;
        memcpy(fp->crypt_in + fp->crypt_buf_used, buf + bytes, to_copy);
        fp->crypt_buf_used += to_copy;
        bytes += to_copy;

        // If there's a full block, write it
        if (fp->crypt_buf_used == CRYPTO_BLOCK_LENGTH) {
            increment_iv(fp->iv, iv_len);
            memcpy(fp->crypt_out, fp->iv, iv_len);
            if (chacha20_encrypt(fp->crypt_out + iv_len, &encrypt_len,
                                 fp->crypt_in, CRYPTO_BLOCK_LENGTH,
                                 fp->iv, fp->key) != 0) {
                errno = EIO;
                return EOF;
            }
            if (write_to_backend(fp, encrypt_len + iv_len) != 0) return EOF;
            fp->crypt_buf_used = 0;
        }
    }

    return bytes;
}

static inline off_t get_encrypted_block_pos(hFILE_crypt4gh *fp, off_t pos) {
    if (pos < 0) return -1;
    switch (fp->type) {
    case chacha20_ietf_poly1305:
        return ((pos / CRYPTO_BLOCK_LENGTH) * CC20_P1305_BLOCK_LEN
                + fp->real_data_start);
    default:
        return -1;
    }
}

static inline off_t get_unencrypted_pos(hFILE_crypt4gh *fp, off_t pos, int at_end) {
    if (pos < fp->real_data_start) return -1;
    pos -= fp->real_data_start;
    switch (fp->type) {
    case chacha20_ietf_poly1305: {
        off_t block = pos / CC20_P1305_BLOCK_LEN;
        off_t remain = pos - block * CC20_P1305_BLOCK_LEN - CC20_IV_LEN;
        if (at_end) remain -= P1305_MAC_LEN;
        return (block * CRYPTO_BLOCK_LENGTH
                + (remain < 0
                   ? 0
                   : (remain < CRYPTO_BLOCK_LENGTH
                      ? remain
                      : CRYPTO_BLOCK_LENGTH)));
    }
    default:
        return -1;
    }
}

static off_t crypt4gh_seek(hFILE *fpv, off_t offset, int whence) {
    hFILE_crypt4gh *fp = (hFILE_crypt4gh *) fpv;
    off_t pos, block_pos = -1, unencrypted_pos;
    ssize_t got;
    size_t block_len, iv_len, mac_len, decrypt_len;

    if (!fp->base.readonly) {
        errno = ESPIPE;
        return -1;
    }

    switch (whence) {
    case SEEK_CUR: {
        off_t curr = fp->base.offset + (fp->base.end - fp->base.buffer);
        offset += curr;
        block_pos = get_encrypted_block_pos(fp, offset);
        break;
    }
    case SEEK_END: {
        // This is a bit inefficicent as we have to find where the end of
        // the underlying file is in order to work out the absolute offset
        off_t end = hseek(fp->parent, 0, SEEK_END);
        off_t unencrypted_end;
        if (end < 0) return end;
        if (offset > 0) offset = 0;
        unencrypted_end = get_unencrypted_pos(fp, end, 1);
        offset = unencrypted_end > -offset ? unencrypted_end + offset : -1;
    }
        // Fall through here
    case SEEK_SET:
        block_pos = get_encrypted_block_pos(fp, offset);
        break;
    default:
        break;
    }

    if (block_pos < 0) {
        errno = EINVAL;
        return -1;
    }

    pos = hseek(fp->parent, block_pos, SEEK_SET);
    if (pos < 0) return pos;

    // Work out where we actually ended up.
    unencrypted_pos = get_unencrypted_pos(fp, pos, pos < block_pos ? 1 : 0);
    if (unencrypted_pos < 0) {
        errno = EIO;
        return -1;
    }

    if (pos < block_pos) {
        // This should only happen when trying to seek past EOF.
        // If this is the case then unencrypted_pos should be the EOF position
        fp->crypt_buf_used = 0;
        fp->curr_offset = unencrypted_pos;
        return unencrypted_pos;
    }

    // Need to do a backend read here to find out how much data is available
    // This is necessary because we don't know if the next block is a short
    // one at the end of the file.

    block_len = get_block_length(fp);
    iv_len = get_iv_length(fp);
    mac_len = get_mac_length(fp);
    got = hread(fp->parent, fp->crypt_in, block_len);
    if (got < 0) return -1;
    if (got < iv_len + mac_len) got = 0;
    if (got) {
        if (chacha20_decrypt(fp->crypt_out, &decrypt_len,
                             fp->crypt_in + iv_len, got - iv_len,
                             fp->crypt_in, fp->key) != 0) {
            errno = EIO;
            return -1;
        }
    } else {
        decrypt_len = 0;
    }
    fp->crypt_buf_used = decrypt_len;
    fp->curr_offset = unencrypted_pos;
    fp->base.offset = offset < unencrypted_pos + decrypt_len ? offset : unencrypted_pos + decrypt_len;
    return fp->base.offset;
}

static int crypt4gh_flush(hFILE *fpv) {
    hFILE_crypt4gh *fp = (hFILE_crypt4gh *) fpv;

    if (!fp->parent) {
        errno = EIO;
        return EOF;
    }

    if (!fp->parent->backend->flush) return 0;

    return fp->parent->backend->flush(fp->parent);
}

static int crypt4gh_close(hFILE *fpv) {
    hFILE_crypt4gh *fp = (hFILE_crypt4gh *) fpv;
    int retval = 0;
    size_t iv_len = get_iv_length(fp);
    size_t encrypt_len = 0;

    // Encrypt and write any remaining data
    if (!fp->base.readonly && fp->crypt_buf_used > 0) {
        increment_iv(fp->iv, iv_len);
        memcpy(fp->crypt_out, fp->iv, iv_len);
        if (chacha20_encrypt(fp->crypt_out + iv_len, &encrypt_len,
                                 fp->crypt_in, fp->crypt_buf_used,
                                 fp->iv, fp->key) != 0) {
            retval = -1;
        }
        if (write_to_backend(fp, encrypt_len + iv_len) != 0) retval = -1;
    }

    if (fp->crypt_out) {
        secure_zero(fp->crypt_out, CRYPTO_BLOCK_LENGTH + CC20_P1305_BLOCK_LEN);
        free(fp->crypt_out);
    }
    if (fp->key) {
        secure_zero(fp->key, fp->keylen * fp->nkeys);
        free(fp->key);
    }
    free(fp->iv);
    if (fp->parent) {
        if (hclose(fp->parent) < 0) retval = -1;
    }
    return retval;
}

static const struct hFILE_backend crypt4gh_backend = {
    crypt4gh_read, crypt4gh_write, crypt4gh_seek, crypt4gh_flush, crypt4gh_close
};

static hFILE *init_for_write(hFILE *hfile, const char *mode) {
    hFILE_crypt4gh *fp;

    fp = (hFILE_crypt4gh *) hfile_init(sizeof(hFILE_crypt4gh), mode, 0);
    if (fp == NULL) return NULL;
    fp->base.backend = &crypt4gh_backend;

    fp->crypt_out = calloc(CC20_P1305_BLOCK_LEN + CRYPTO_BLOCK_LENGTH, 1);
    if (!fp->crypt_out) goto fail;
    fp->crypt_in = fp->crypt_out + CC20_P1305_BLOCK_LEN;
    fp->parent = hfile;
    fp->real_data_start = 0;
    fp->crypt_buf_used = 0;
    fp->curr_offset = 0;
    fp->type = chacha20_ietf_poly1305;
    fp->keylen = CC20_KEY_LEN;
    fp->ivlen = CC20_IV_LEN;
    fp->nkeys = 1;
    fp->curr_key = 0;
    fp->blocklen = 0;
    fp->shift = 0;
    fp->key = malloc(fp->keylen);
    if (!fp->key) goto fail;
    fp->iv = malloc(fp->ivlen);
    if (!fp->iv) goto fail;
    fp->edit_map = NULL;
    fp->edit_map_len = 0;
    fp->curr_map = 0;

    if (get_random_bytes(fp->key, fp->keylen) != 0
        || get_random_bytes(fp->iv, fp->ivlen) != 0) {
        goto fail;
    }

    if (write_encryption_header(fp) != 0) goto fail;

    return &fp->base;

 fail:
    hfile_destroy((hFILE *) fp);
    return NULL;
}

static hFILE *init_for_read(hFILE *hfile, const char *mode) {
    hFILE_crypt4gh *fp;

    fp = (hFILE_crypt4gh *) hfile_init(sizeof(hFILE_crypt4gh), mode, 0);
    if (fp == NULL) return NULL;

    fp->crypt_out = calloc(CRYPTO_BLOCK_LENGTH + CC20_P1305_BLOCK_LEN, 1);
    if (!fp->crypt_out) goto fail;
    fp->crypt_in = fp->crypt_out + CRYPTO_BLOCK_LENGTH;
    fp->key = fp->iv = NULL;
    fp->parent = hfile;
    fp->real_data_start = 0;
    fp->crypt_buf_used = 0;
    fp->curr_offset = 0;
    fp->type = 0;
    fp->keylen = CC20_KEY_LEN;
    fp->nkeys = 0;
    fp->curr_key = 0;
    fp->ivlen = CC20_IV_LEN;
    fp->blocklen = 0;
    fp->shift = 0;

    fp->key = calloc(fp->keylen, 1);
    if (!fp->key) goto fail;
    fp->iv = calloc(fp->ivlen, 1);
    if (!fp->iv) goto fail;
    fp->edit_map = NULL;
    fp->edit_map_len = 0;
    fp->curr_map = 0;

    if (read_encryption_header(fp) != 0) goto fail;

    fp->base.backend = &crypt4gh_backend;
    return &fp->base;

 fail:
    hfile_destroy((hFILE *) fp);
    return NULL;
}


static void disclaimer() {
    static int disclaimed = 0;
    if (disclaimed) return;
    fprintf(stderr,
            "WARNING:  hfile_crypt4gh is for EXPERIMENTAL use only.  The file "
            "format is liable\n"
            "to change.  Do not expect future versions to be able to read "
            "anything written\n"
            "by this one.   Files encrypted by this module should not "
            "be assumed secure.\n");
    disclaimed = 1;
}

static hFILE *hopen_crypt4gh_wrapper(hFILE *hfile, const char *mode) {
    disclaimer();
    if (strchr(mode, 'r')) {
        return init_for_read(hfile, mode);
    } else {
        return init_for_write(hfile, mode);
    }
}

static hFILE *hopen_crypt4gh(const char *url, const char *mode) {
    hFILE *parent = NULL;
    const char *scheme = "crypt4gh:";
    size_t len = strlen(scheme);
    if (0 != strncmp(url, scheme, len)) {
        errno = ENOTSUP;
        return NULL;
    }

    parent = hopen(url + len, mode);
    if (!parent) return NULL;

    return hopen_crypt4gh_wrapper(parent, mode);
}

static hFILE *vhopen_crypt4gh(const char *url, const char *mode, va_list args) {
    const char *argtype;
    if ((argtype = va_arg(args, const char *)) != NULL) {
        if (strcmp(argtype, "parent") == 0) {
            hFILE *parent = va_arg(args, hFILE *);
            if (parent) {
                return hopen_crypt4gh_wrapper(parent, mode);
            }
        }
    }
    return hopen_crypt4gh(url, mode);
}

static void crypt4gh_exit() {
}

static int crypt4gh_is_remote(const char *fname) {
    const char *scheme = "crypt4gh:";
    size_t len = strlen(scheme);
    if (0 == strncmp(fname, scheme, len)) {
        return hisremote(fname + len);
    }
    return hisremote(fname); // FIXME: possible infinite recursion?
}

int PLUGIN_GLOBAL(hfile_plugin_init,_crypt4gh)(struct hFILE_plugin *self) {
    static const struct hFILE_scheme_handler handler =
        { hopen_crypt4gh, crypt4gh_is_remote, "hfile_crypt4gh",
          2000 + 50, vhopen_crypt4gh };

#ifdef ENABLE_PLUGINS
    // Embed version string for examination via strings(1) or what(1)
    static const char id[] = "@(#)hfile_crypt4gh plugin (htslib)\t" PLUGINS_VERSION;
    if (hts_verbose >= 9) {
        fprintf(stderr, "[M::hfile_crypt4gh.init] version %s\n",
                strchr(id, '\t')+1);
    }
#endif

    self->name = "hfile_crypt4gh";
    self->destroy = crypt4gh_exit;

    hfile_add_scheme_handler("crypt4gh", &handler);
    return 0;
}
