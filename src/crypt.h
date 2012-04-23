/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */
#ifndef CRYPT_H
#define CRYPT_H

const size_t AES_BLOCK_LEN = 16;
const size_t GCM_TAG_LEN   = 16;
const size_t SHA256_LEN    = 32;

struct key_generator;

struct ecb_encryptor
{
  ecb_encryptor() {}
  virtual ~ecb_encryptor();

  /** Return a new AES/ECB encryption state using 'key' (of length 'keylen')
      as the symmetric key.  'keylen' must be 16, 24, or 32 bytes. */
  static ecb_encryptor *create(const uint8_t *key, size_t keylen);

  /** Return a new AES/ECB encryption state, generating a key of
      length 'keylen' from the key generator 'gen'.  'keylen' must be
      16, 24, or 32 bytes. */
  static ecb_encryptor *create(key_generator *gen, size_t keylen);

  /** Encrypt exactly AES_BLOCK_LEN bytes of data in the buffer 'in' and
      write the result to 'out'.  */
  virtual void encrypt(uint8_t *out, const uint8_t *in) = 0;

private:
  ecb_encryptor(const ecb_encryptor&);
  ecb_encryptor& operator=(const ecb_encryptor&);
};

struct ecb_decryptor
{
  ecb_decryptor() {}
  virtual ~ecb_decryptor();

  /** Return a new AES/ECB decryption state using 'key' (of length 'keylen')
      as the symmetric key.  'keylen' must be 16, 24, or 32 bytes. */
  static ecb_decryptor *create(const uint8_t *key, size_t keylen);

  /** Return a new AES/ECB decryption state, generating a key of
      length 'keylen' from the key generator 'gen'.  'keylen' must be
      16, 24, or 32 bytes. */
  static ecb_decryptor *create(key_generator *gen, size_t keylen);

  /** Decrypt exactly AES_BLOCK_LEN bytes of data in the buffer 'in' and
      write the result to 'out'.  */
  virtual void decrypt(uint8_t *out, const uint8_t *in) = 0;

private:
  ecb_decryptor(const ecb_decryptor&) DELETE_METHOD;
  ecb_decryptor& operator=(const ecb_decryptor&) DELETE_METHOD;
};


struct gcm_encryptor
{
  gcm_encryptor() {}
  virtual ~gcm_encryptor();

  /** Return a new AES/GCM encryption state using 'key' (of length 'keylen')
      as the symmetric key.  'keylen' must be 16, 24, or 32 bytes. */
  static gcm_encryptor *create(const uint8_t *key, size_t keylen);

  /** Return a new AES/GCM encryption state, generating a key of
      length 'keylen' from the key generator 'gen'.  'keylen' must be
      16, 24, or 32 bytes. */
  static gcm_encryptor *create(key_generator *gen, size_t keylen);

  /** Encrypt 'inlen' bytes of data in the buffer 'in', writing the
      result plus an authentication tag to the buffer 'out', whose
      length must be at least 'inlen'+16 bytes.  Use 'nonce'
      (of length 'nlen') as the encryption nonce; 'nlen' must be at
      least 12 bytes.  */
  virtual void encrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                       const uint8_t *nonce, size_t nlen) = 0;

private:
  gcm_encryptor(const gcm_encryptor&);
  gcm_encryptor& operator=(const gcm_encryptor&);
};

struct gcm_decryptor
{
  gcm_decryptor() {}
  virtual ~gcm_decryptor();

  /** Return a new AES/GCM decryption state using 'key' (of length 'keylen')
      as the symmetric key.  'keylen' must be 16, 24, or 32 bytes. */
  static gcm_decryptor *create(const uint8_t *key, size_t keylen);

  /** Return a new AES/GCM decryption state, generating a key of
      length 'keylen' from the key generator 'gen'.  'keylen' must be
      16, 24, or 32 bytes. */
  static gcm_decryptor *create(key_generator *gen, size_t keylen);

  /** Decrypt 'inlen' bytes of data in the buffer 'in'; the last 16
      bytes of this buffer are assumed to be the authentication tag.
      Write the result to the buffer 'out', whose length must be at
      least 'inlen'-16 bytes.  Use 'nonce' (of length 'nlen') as the
      encryption nonce; as above, 'nlen' must be at least 12 bytes.
      Returns 0 if successful, -1 if the authentication check fails. */
  virtual int decrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                      const uint8_t *nonce, size_t nlen) = 0;

private:
  gcm_decryptor(const gcm_decryptor&) DELETE_METHOD;
  gcm_decryptor& operator=(const gcm_decryptor&) DELETE_METHOD;
};

/** Generate keying material from an initial key of some kind, a salt
    value, and a context value, all of which are formally bitstrings.
    See http://tools.ietf.org/html/rfc5869 for the requirements on the
    salt and the context.  'from_random_secret' uses HKDF as described
    in that document, and therefore requires the initial key to be a
    high-entropy random value; 'from_password' stretches a low-entropy
    passphrase with PBKDF2 first.  Either way, we use HKDF-Expand as
    the actual pseudo-random function.  */

struct key_generator
{
  /** Construct a key generator from a genuinely random secret, plus a
      salt value (should be as random as possible, does not have to be
      secret) and a context value (whatever you've got that uniquely
      identifies the application context; doesn't have to be random
      _or_ secret).  */
  static key_generator *from_random_secret(const uint8_t *key,  size_t klen,
                                           const uint8_t *salt, size_t slen,
                                           const uint8_t *ctxt, size_t clen);

  /** Construct a key generator from a passphrase.  The salt and context
      arguments are the same as for from_random_secret. */
  static key_generator *from_passphrase(const uint8_t *phra, size_t plen,
                                        const uint8_t *salt, size_t slen,
                                        const uint8_t *ctxt, size_t clen);

  /** Write LEN bytes of key material to BUF.  May be called
      repeatedly.  Note that HKDF has a hard upper limit on the total
      amount of key material it can generate.  The return value is
      therefore the amount of data actually written to BUF, and it
      will be no greater than LEN, but may be as short as zero. */
  virtual size_t generate(uint8_t *buf, size_t len) = 0;

  virtual ~key_generator();
  key_generator() {}
private:
  key_generator(const key_generator&) DELETE_METHOD;
  key_generator& operator=(const key_generator&) DELETE_METHOD;
};

#endif
