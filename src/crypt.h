/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef CRYPT_H
#define CRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_LENGTH 32
#define AES_BLOCK_SIZE 16

/* Stream cipher state */
typedef struct crypt_t crypt_t;
/* Digest state */
typedef struct digest_t digest_t;

/** Initialize global crypto state.  Returrn 0 on success, -1 on failure */
int initialize_crypto(void);
/** Clean up global crypto state */
void cleanup_crypto(void);

/** Return a newly allocated digest state; cannot fail. */
digest_t *digest_new(void);
/** Add n bytes from b to the digest state. */
void digest_update(digest_t *, const uint8_t *b, size_t n);
/** Get a digest from the digest state.  Put it in up the first n bytes of the
buffer b.  Return the number of bytes actually written.*/
size_t digest_getdigest(digest_t *, uint8_t *b, size_t n);
/** Clear and free a digest state */
void digest_free(digest_t *);

/** Return a new stream cipher state using 'key' as the symmetric key.
 * The data length must be exactly 16 bytes. Cannot fail. */
crypt_t *crypt_new(const uint8_t *key, size_t);
/* Set the IV of a stream-cipher state.  Cannot fail. */
void crypt_set_iv(crypt_t *, const uint8_t *iv, size_t ivlen);

/** Encrypt n bytes of data in the buffer b, in place. */
void stream_crypt(crypt_t *, uint8_t *b, size_t n);
/** Clear and free a stream cipher state. */
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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
