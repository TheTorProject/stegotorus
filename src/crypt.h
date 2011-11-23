/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#ifndef CRYPT_H
#define CRYPT_H

const size_t AES_BLOCK_LEN = 16;
const size_t GCM_TAG_LEN   = 16;

struct encryptor
{
  /** Return a new AES/GCM encryption state using 'key' (of length 'keylen')
      as the symmetric key.  'keylen' must be 16, 24, or 32 bytes. */
  static encryptor *create(const uint8_t *key, size_t keylen);

  /** Encrypt 'inlen' bytes of data in the buffer 'in', writing the
      result plus a MAC to the buffer 'out', whose length must be at
      least 'inlen'+16 bytes.  Use 'nonce' (of length 'nlen') as the
      encryption nonce; 'nlen' must be at least 12 bytes.  */
  virtual void encrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                       const uint8_t *nonce, size_t nlen) = 0;

  virtual ~encryptor();

  encryptor() {}
private:
  encryptor(const encryptor&);
  encryptor& operator=(const encryptor&);
};

struct decryptor
{
  /** Return a new AES/GCM decryption state using 'key' (of length 'keylen')
      as the symmetric key.  'keylen' must be 16, 24, or 32 bytes. */
  static decryptor *create(const uint8_t *key, size_t keylen);

  /** Decrypt 'inlen' bytes of data in the buffer 'in'; the last 16 bytes
      of this buffer are assumed to be the MAC.  Write the result to the
      buffer 'out', whose length must be at least 'inlen'-16 bytes.  Use
      'nonce' (of length 'nlen') as the encryption nonce; as above, 'nlen'
      must be at least 12 bytes.  Returns 0 if successful, -1 if the MAC
      did not validate. */
  virtual int decrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                      const uint8_t *nonce, size_t nlen) = 0;

  /** Decrypt 'inlen' bytes of data in the buffer 'in' WITHOUT CHECKING
      THE MAC.  Arguments same as decrypt().  This should be used only to
      decode just enough of an incoming block to know how long it's going
      to be and therefore where the MAC begins. */
  virtual void decrypt_unchecked(uint8_t *out, const uint8_t *in, size_t inlen,
                                 const uint8_t *nonce, size_t nlen) = 0;

  virtual ~decryptor();

  decryptor() {}
private:
  decryptor(const decryptor&);
  decryptor& operator=(const decryptor&);
};

#endif
