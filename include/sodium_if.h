/*  sodium_if.h -- libsodium interface

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

#include <stdint.h>
#include <sodium.h>

#ifndef HTS_CRYPTO_INTERFACE
#define HTS_CRYPTO_INTERFACE

/// Length of chacha20 initialisation vector
#define CC20_IV_LEN        crypto_aead_chacha20poly1305_IETF_NPUBBYTES

/// Length of poly1305 message authentication code
#define P1305_MAC_LEN      crypto_aead_chacha20poly1305_IETF_ABYTES

/// Length of chacha20 key
#define CC20_KEY_LEN       crypto_aead_chacha20poly1305_IETF_KEYBYTES

/// Length of X25519 public key
#define X25519_PK_LEN      crypto_kx_PUBLICKEYBYTES

/// Length of X25519 secret key
#define X25519_SK_LEN      crypto_kx_SECRETKEYBYTES

/// Length of X25519 session key
#define X25519_SESSION_LEN crypto_kx_SESSIONKEYBYTES

/// Initialize cryptographic functions
/** @return 0 on success; non-zero on failure
 */
static inline int crypto_init() {
    return sodium_init();
}

/// Securely zero out memory
/** @param ptr    Memory to zero
    @param len    Length

This function should not be optimized out, even if used just before
returning from the calling function.
*/
static inline void secure_zero(void *ptr, size_t len) {
    sodium_memzero(ptr, len);
}

/// Allocate mlock-ed memory
/** @param count   Number of items to allocate
    @param size    Size of item
    @return pointer to allocated memory

    Memory must be freed using secure_free()
*/
static inline void * secure_alloc(size_t count, size_t size) {
    return sodium_allocarray(count, size);
}

/// Free mlock-ed memory
/** @param  ptr    Location to free
 */
static inline void secure_free(void *ptr) {
    sodium_free(ptr);
}

/// Make memory inaccessible
/** @param ptr   Pointer to memory region allocated with secure_alloc
    @return 0 on success; non-zero on error
 */
static inline int prevent_access(void *ptr) {
    int ret = sodium_mprotect_noaccess(ptr);
    if (ret != 0 && errno == ENOSYS) return 0;
    return ret;
}

/// Make memory accessible
/** @param ptr      Pointer to memory region allocated with secure_alloc
    @param readonly Only allow reads
    @return 0 on success; non-zero on error
 */
static inline int allow_access(void *ptr, int readonly) {
    int ret;
    if (readonly)
        ret = sodium_mprotect_readonly(ptr);
    else
        ret = sodium_mprotect_readwrite(ptr);
    if (ret != 0 && errno == ENOSYS) return 0;
    return ret;
}

/// Increment an arbitrary-length number in constant time
/** @param buf    Buffer containing number
    @param len    Length

The number is incremented as if little-endian.
*/
static inline void constant_time_increment(uint8_t *buf, size_t len) {
    sodium_increment(buf, len);
}

/// Get cryptographically-secure random bytes
/** @param[out] buf    Location to store random bytes
    @param      len    Number of bytes to generate
*/
static inline int get_random_bytes(uint8_t *buf, size_t len) {
    randombytes_buf(buf, len);
    return 0;
}

/// Derive X25519 public key from a given secret one
/** @param[out]  public_out    Derived public key
    @param[in]   secret_in     Secret key
    @return 0 on success; non-zero on failure
*/
static inline
int derive_X25519_public_key(uint8_t public_out[X25519_PK_LEN],
                             const uint8_t secret_in[X25519_SK_LEN]) {
    return crypto_scalarmult_base(public_out, secret_in);
}

/// Get an X25519 key pair
/** @param[out] pk    Generated public key
    @param[out] sk    Generated secret key
    @return 0 on success; non-zero on failure
*/
static inline int get_X25519_keypair(uint8_t pk[X25519_PK_LEN],
                                     uint8_t sk[X25519_SK_LEN]) {
    if (crypto_kx_keypair(pk, sk) != 0) return -1;
    return 0;
}

/// Get X25519 server session keys
/** @param[out]    rx   Recieve session key
    @param[out]    tx   Transmit session key
    @param[in]     server_pk  Server's public key
    @param[in]     server_sk  Server's secret key
    @param[in]     client_pk  Client's public key
*/
static inline
int get_X25519_server_session_keys(uint8_t rx[X25519_SESSION_LEN],
                                   uint8_t tx[X25519_SESSION_LEN],
                                   const uint8_t server_pk[X25519_PK_LEN],
                                   const uint8_t server_sk[X25519_PK_LEN],
                                   const uint8_t client_pk[X25519_PK_LEN]) {
    if (crypto_kx_server_session_keys(rx, tx,
                                      server_pk, server_sk, client_pk) != 0) {
        return -1;
    }
    return 0;
}

/// Get X25519 client session keys
/** @param[out]    rx   Recieve session key
    @param[out]    tx   Transmit session key
    @param[in]     client_pk  Client's public key
    @param[in]     client_sk  Client's secret key
    @param[in]     server_pk  Server's public key
*/
static inline
int get_X25519_client_session_keys(uint8_t rx[X25519_SESSION_LEN],
                                   uint8_t tx[X25519_SESSION_LEN],
                                   const uint8_t client_pk[X25519_PK_LEN],
                                   const uint8_t client_sk[X25519_PK_LEN],
                                   const uint8_t server_pk[X25519_PK_LEN]) {
    if (crypto_kx_client_session_keys(rx, tx,
                                      client_pk, client_sk, server_pk) != 0) {
        return -1;
    }
    return 0;
}

/// Get an X25519 session key (for writing)
/** @param      reader_pk    Reader's public key
    @param[out] writer_pk    Writer's public key
    @param[out] session_key  Derived session key
    @return 0 on success; non-zero on failure
*/
static inline
int get_X25519_hdr_key_w(const uint8_t reader_pk[X25519_PK_LEN],
                         uint8_t writer_pk[X25519_PK_LEN],
                         uint8_t session_key[X25519_SESSION_LEN]) {
    uint8_t writer_sk[X25519_SK_LEN];
    uint8_t ignored[X25519_SESSION_LEN];
    int retval = -1;

    if (crypto_kx_keypair(writer_pk, writer_sk) != 0) goto out;
    if (crypto_kx_server_session_keys(ignored, session_key,
                                      writer_pk, writer_sk, reader_pk) != 0) {
        goto out;
    }
    retval = 0;

 out:
    secure_zero(writer_sk, sizeof(writer_sk));
    secure_zero(ignored, sizeof(ignored));
    return retval;
}

/// Get an X25519 session key (for reading)
/** @param      writer_pk    Writer's public key
    @param      reader_pk    Reader's public key
    @param      reader_sk    Reader's secret key
    @param[out] session_key  Derived session key
    @return 0 on success; non-zero on failure
*/
static inline
int get_X25519_hdr_key_r(const uint8_t writer_pk[X25519_PK_LEN],
                         const uint8_t reader_pk[X25519_PK_LEN],
                         const uint8_t reader_sk[X25519_PK_LEN],
                         uint8_t session_key[X25519_SESSION_LEN]) {
    uint8_t ignored[X25519_SESSION_LEN];

    if (crypto_kx_client_session_keys(session_key, ignored,
                                      reader_pk, reader_sk, writer_pk) != 0) {
        return -1;
    }

    secure_zero(ignored, sizeof(ignored));
    return 0;
}

/// Encrypt using chacha20/poly1305
/** @param[out]  out      Encrypted data
    @param[out]  out_len  Encrypted data length
    @param[in]   msg      Data to encrypt
    @param[in]   msg_len  Length of @p msg
    @param[in]   iv       Initialisation vector
    @param[in]   key      Encryption key
    @return 0 on success; non-zero on failure
 */
static inline int chacha20_encrypt(uint8_t *out, size_t *out_len,
                                   const uint8_t *msg, size_t msg_len,
                                   const uint8_t *iv, const uint8_t *key) {
    unsigned long long len = 0;
    int ret = crypto_aead_chacha20poly1305_ietf_encrypt(out, &len,
                                                        msg, msg_len,
                                                        NULL, 0, NULL,
                                                        iv, key);
    if (out_len) *out_len = len;
    return ret;
}

/// Decrypt using chacha20/poly1305
/** @param[out]  out      Decrypted data
    @param[out]  out_len  Decrypted data length
    @param[in]   in       Data to decrypt
    @param[in]   in_len   Length of @p in
    @param[in]   iv       Initialisation vector
    @param[in]   key      Encryption key
    @return 0 on success; non-zero on failure
 */
static inline int chacha20_decrypt(uint8_t *out, size_t *out_len,
                                   const uint8_t *in, size_t in_len,
                                   const uint8_t *iv, const uint8_t *key) {
    unsigned long long len = 0;
    int ret = crypto_aead_chacha20poly1305_ietf_decrypt(out, &len, NULL,
                                                        in, in_len,
                                                        NULL, 0,
                                                        iv, key);
    if (out_len) *out_len = len;
    return ret;
}

/// Derive a key from a passphrase
/** @param[out]  key_out     Location to store derived key
    @param       key_len     Length of @p key_out
    @param       passwd      Input passphrase
    @param       passwd_len  Length of passphrase
    @param       salt        Input salt
    @param       salt_len    Length of salt
    @return 0 on success; non-zero on failure
*/
static inline int salsa_kdf(uint8_t *key_out, size_t key_len,
                            const uint8_t *passwd, size_t passwd_len,
                            const uint8_t *salt, size_t salt_len) {
    if (crypto_pwhash_scryptsalsa208sha256_ll(passwd, passwd_len,
                                              salt, salt_len,
                                              1<<14, 8, 1,
                                              key_out, key_len) != 0) {
        return -1;
    }
    return 0;
}

#endif /* HTS_CRYPTO_INTERFACE */
