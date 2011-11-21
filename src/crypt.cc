/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "crypt.h"

/* Note: this file wraps a C++ library into an otherwise-C program and must
   insulate that program from C++ semantics it is not prepared to handle;
   most importantly, all exceptions must be converted to error codes. */

#include <stdexcept>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

#define CATCH_ALL_EXCEPTIONS(rv)                                \
  catch (std::exception& e) {                                   \
    log_warn("%s: %s", __func__, e.what());                     \
  } catch (...) {                                               \
    log_warn("%s: exception of abnormal type", __func__);       \
  }                                                             \
  return rv /* deliberate absence of semicolon */

static CryptoPP::AutoSeededRandomPool *rng;

/**
   Initializes the crypto subsystem.
*/
int
initialize_crypto(void)
{
  try {
    rng = new CryptoPP::AutoSeededRandomPool;
    return 0;
  }
  CATCH_ALL_EXCEPTIONS(-1);
}

/**
   Cleans up the crypto subsystem.
*/
void
cleanup_crypto(void)
{
  delete rng;
  rng = 0;
}

/* =====
   Digests
   ===== */

struct digest_t {
  CryptoPP::SHA256 ctx;
};

/**
   Returns a new SHA256 digest container.
*/
digest_t *
digest_new(void)
{
  try {
    return new digest_t;
  }
  CATCH_ALL_EXCEPTIONS(0);
}

/**
   Updates the contents of the SHA256 container 'd' with the first
   'len' bytes of 'buf'.
*/
void
digest_update(digest_t *d, const uint8_t *buf, size_t len)
{
  try {
    d->ctx.Update(buf, len);
  }
  CATCH_ALL_EXCEPTIONS();
}

/**
   Returns the digest stored in 'd' into 'buf' of length 'len'.
*/
size_t
digest_getdigest(digest_t *d, uint8_t *buf, size_t len)
{
  try {
    log_assert(d->ctx.DigestSize() == SHA256_LENGTH);
    if (len >= SHA256_LENGTH) {
      d->ctx.Final(buf);
      return SHA256_LENGTH;
    } else {
      uint8_t tmp[SHA256_LENGTH];
      d->ctx.Final(tmp);
      memcpy(buf, tmp, len);
      memset(tmp, 0, SHA256_LENGTH);
      return len;
    }
  }
  CATCH_ALL_EXCEPTIONS(0);
}

void
digest_free(digest_t *d)
{
  delete d;
}

/* =====
   Stream crypto
   ===== */

static const uint8_t dummy_iv[16] = {};

struct crypt_t {
  CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption ctx;
  crypt_t(const uint8_t *key) : ctx(key, AES_BLOCK_SIZE, dummy_iv) {}
};

/**
   Initializes the AES cipher with 'key'.
*/
crypt_t *
crypt_new(const uint8_t *key, size_t keylen)
{
  log_assert(keylen == AES_BLOCK_SIZE);

  try {
    return new crypt_t(key);
  }
  CATCH_ALL_EXCEPTIONS(0);
}

/**
   Sets the IV of 'c' to 'iv'.
*/
void
crypt_set_iv(crypt_t *c, const uint8_t *iv, size_t ivlen)
{
  log_assert(ivlen == AES_BLOCK_SIZE);
  try {
    c->ctx.Resynchronize(iv, ivlen);
  }
  CATCH_ALL_EXCEPTIONS();
}

/*
  In-place encrypts 'buf' with 'c'.
*/
void
stream_crypt(crypt_t *c, uint8_t *buf, size_t len)
{
  try {
    c->ctx.ProcessData(buf, buf, len);
  }
  CATCH_ALL_EXCEPTIONS();
}

/**
   Deallocates 'c'.
*/
void
crypt_free(crypt_t *c)
{
  delete c;
}

/* =====
   PRNG
   ===== */

/**
   Fills 'buf' with 'buflen' random bytes and returns 0 on success.
   Returns -1 on failure.
*/
int
random_bytes(uint8_t *buf, size_t buflen)
{
  log_assert(rng);
  try {
    rng->GenerateBlock(buf, buflen);
    return 0;
  }
  CATCH_ALL_EXCEPTIONS(-1);
}


/** Return a pseudorandom integer, chosen uniformly from the values
 * between 0 and <b>max</b>-1 inclusive.  <b>max</b> must be between 1 and
 * INT_MAX+1, inclusive. */
int
random_int(unsigned int max)
{
  log_assert(rng);
  log_assert(max <= ((unsigned int)INT_MAX)+1);
  log_assert(max > 0); /* don't div by 0 */

  try {
    return rng->GenerateWord32(0, max-1);
  }
  CATCH_ALL_EXCEPTIONS(-1);
}

/** Return a pseudorandom integer, chosen uniformly from the values
 * between 'min' and 'max-1', inclusive.  'max' must be between
 * 'min+1' and 'INT_MAX+1', inclusive. */
int
random_range(unsigned int min, unsigned int max)
{
  log_assert(rng);
  log_assert(max <= ((unsigned int)INT_MAX)+1);
  log_assert(max > min);

  try {
    return rng->GenerateWord32(min, max-1);
  }
  CATCH_ALL_EXCEPTIONS(-1);
}
