/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#ifndef CRYPT_H
#define CRYPT_H

#define AES_BLOCK_LEN 16
#define GCM_TAG_LEN 16

/* Cipher state */
struct crypt_t;

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

#endif
