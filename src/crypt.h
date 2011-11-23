/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef CRYPT_H
#define CRYPT_H

#define SHA256_LEN 32
#define AES_BLOCK_LEN 16
#define GCM_TAG_LEN 16

/* Stream cipher state */
typedef struct crypt_t crypt_t;
/* Digest state */
typedef struct digest_t digest_t;

/** Initialize global crypto state.  Returrn 0 on success, -1 on failure */
int initialize_crypto(void);
/** Clean up global crypto state */
void cleanup_crypto(void);

/** Return a newly allocated digest state. */
digest_t *digest_new(void);
/** Add n bytes from b to the digest state. */
void digest_update(digest_t *, const uint8_t *b, size_t n);
/** Get a digest from the digest state.  Put it in up the first n bytes of the
buffer b.  Return the number of bytes actually written.*/
size_t digest_getdigest(digest_t *, uint8_t *b, size_t n);
/** Clear and free a digest state */
void digest_free(digest_t *);

/** Return a new AES/GCM cipher state using 'key' (of length 'keylen')
 * as the symmetric key.  'keylen' must be 16, 24, or 32 bytes. */
crypt_t *crypt_new(const uint8_t *key, size_t keylen);

/** Encrypt 'inlen' bytes of data in the buffer 'in', writing the
    result plus a MAC to the buffer 'out', whose length must be at
    least 'inlen'+16 bytes.  Use 'nonce' (of length 'nlen') as the
    encryption nonce; 'nlen' must be at least 12 bytes.  */
void crypt_encrypt(crypt_t *state,
                   uint8_t *out, const uint8_t *in, size_t inlen,
                   const uint8_t *nonce, size_t nlen);

/** Decrypt 'inlen' bytes of data in the buffer 'in'; the last 16 bytes
    of this buffer are assumed to be the MAC.  Write the result to the
    buffer 'out', whose length must be at least 'inlen'-16 bytes.  Use
    'nonce' (of length 'nlen') as the encryption nonce; as above, 'nlen'
    must be at least 12 bytes.  Returns 0 if successful, -1 if the MAC
    did not validate. */
int crypt_decrypt(crypt_t *state,
                  uint8_t *out, const uint8_t *in, size_t inlen,
                  const uint8_t *nonce, size_t nlen);

/** Decrypt 'inlen' bytes of data in the buffer 'in' WITHOUT CHECKING
    THE MAC.  Arguments same as crypt_decrypt.  This should be used only
    to decode just enough of an incoming superencrypted block to know
    how long it's going to be and therefore where the MAC begins. */
void crypt_decrypt_unchecked(crypt_t *state,
                             uint8_t *out, const uint8_t *in, size_t inlen,
                             const uint8_t *nonce, size_t nlen);

/** Clear and free a cipher state. */
void crypt_free(crypt_t *);

/** Set b to contain n random bytes. */
int random_bytes(uint8_t *b, size_t n);

/** Return a random integer in the range [0, max).
 * 'max' must be between 1 and INT_MAX+1, inclusive.
 */
int random_int(unsigned int max);

/** Return a random integer in the range [min, max).
 *  'max' must be at least one greater than 'min' and no greater than
 *  INT_MAX+1.
 */
int random_range(unsigned int min, unsigned int max);

#endif
