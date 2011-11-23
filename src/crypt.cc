/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "crypt.h"

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>

/* Note: this file wraps a C++ library into a C-style program and must
   insulate that program from C++ semantics it is not prepared to handle;
   most importantly, all exceptions must be converted to error codes. */

#define CATCH_ALL_EXCEPTIONS(rv)                                \
  catch (std::exception& e) {                                   \
    log_warn("%s: %s", __func__, e.what());                     \
  } catch (...) {                                               \
    log_warn("%s: exception of abnormal type", __func__);       \
  }                                                             \
  return rv /* deliberate absence of semicolon */

// We don't know which way this will be used, so we need both
// encryption and decryption contexts.
struct crypt_t {
  CryptoPP::GCM<CryptoPP::AES>::Encryption e;
  CryptoPP::GCM<CryptoPP::AES>::Decryption d;
};

crypt_t *
crypt_new(const uint8_t *key, size_t keylen)
{
  // Crypto++ doesn't let us set a key without also setting an IV,
  // even though we will always override the IV later.
  static const uint8_t dummy_iv[16] = {};

  try {
    crypt_t *state = new crypt_t;

    // sadly, these are not checkable at compile time
    log_assert(state->e.DigestSize() == 16);
    log_assert(state->d.DigestSize() == 16);
    log_assert(!state->e.NeedsPrespecifiedDataLengths());
    log_assert(!state->d.NeedsPrespecifiedDataLengths());

    state->e.SetKeyWithIV(key, keylen, dummy_iv, sizeof dummy_iv);
    state->d.SetKeyWithIV(key, keylen, dummy_iv, sizeof dummy_iv);
    return state;
  }
  CATCH_ALL_EXCEPTIONS(0);
}

void
crypt_encrypt(crypt_t *state,
              uint8_t *out, const uint8_t *in, size_t inlen,
              const uint8_t *nonce, size_t nlen)
{
  try {
    state->e.EncryptAndAuthenticate(out, out + inlen, 16,
                                    nonce, nlen, 0, 0, in, inlen);
  }
  CATCH_ALL_EXCEPTIONS();
}

int
crypt_decrypt(crypt_t *state,
              uint8_t *out, const uint8_t *in, size_t inlen,
              const uint8_t *nonce, size_t nlen)
{
  try {
    return state->d.DecryptAndVerify(out,
                                     in + inlen - 16, 16,
                                     nonce, nlen, 0, 0, in, inlen - 16)
      ? 0 : -1; // caller will log decryption failure
  }
  CATCH_ALL_EXCEPTIONS(-1);
}

void
crypt_decrypt_unchecked(crypt_t *state,
                        uint8_t *out, const uint8_t *in, size_t inlen,
                        const uint8_t *nonce, size_t nlen)
{
  try {
    // there is no convenience function for this
    state->d.Resynchronize(nonce, nlen);
    state->d.ProcessData(out, in, inlen);
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
