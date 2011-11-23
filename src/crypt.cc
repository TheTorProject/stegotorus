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

struct encryptor_impl : encryptor
{
  CryptoPP::GCM<CryptoPP::AES>::Encryption ctx;
  virtual void encrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                       const uint8_t *nonce, size_t nlen);
  virtual ~encryptor_impl();
};

struct decryptor_impl : decryptor
{
  CryptoPP::GCM<CryptoPP::AES>::Decryption ctx;
  virtual int decrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                      const uint8_t *nonce, size_t nlen);
  virtual void decrypt_unchecked(uint8_t *out, const uint8_t *in, size_t inlen,
                                 const uint8_t *nonce, size_t nlen);
  virtual ~decryptor_impl();
};

// Crypto++ doesn't let us set a key without also setting an IV,
// even though we will always override the IV later.
static const uint8_t dummy_iv[16] = {};

encryptor *
encryptor::create(const uint8_t *key, size_t keylen)
{
  try {
    encryptor_impl *enc = new encryptor_impl;
    // sadly, these are not checkable at compile time
    log_assert(enc->ctx.DigestSize() == 16);
    log_assert(!enc->ctx.NeedsPrespecifiedDataLengths());
    enc->ctx.SetKeyWithIV(key, keylen, dummy_iv, sizeof dummy_iv);
    return enc;
  }
  CATCH_ALL_EXCEPTIONS(0);
}

decryptor *
decryptor::create(const uint8_t *key, size_t keylen)
{
  try {
    decryptor_impl *dec = new decryptor_impl;
    // sadly, these are not checkable at compile time
    log_assert(dec->ctx.DigestSize() == 16);
    log_assert(!dec->ctx.NeedsPrespecifiedDataLengths());
    dec->ctx.SetKeyWithIV(key, keylen, dummy_iv, sizeof dummy_iv);
    return dec;
  }
  CATCH_ALL_EXCEPTIONS(0);
}

encryptor::~encryptor() {}
encryptor_impl::~encryptor_impl() {}
decryptor::~decryptor() {}
decryptor_impl::~decryptor_impl() {}

void
encryptor_impl::encrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                        const uint8_t *nonce, size_t nlen)
{
  try {
    this->ctx.EncryptAndAuthenticate(out, out + inlen, 16,
                                     nonce, nlen, 0, 0, in, inlen);
  }
  CATCH_ALL_EXCEPTIONS();
}

int
decryptor_impl::decrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                        const uint8_t *nonce, size_t nlen)
{
  try {
    return this->ctx.DecryptAndVerify(out,
                                      in + inlen - 16, 16,
                                      nonce, nlen, 0, 0, in, inlen - 16)
      ? 0 : -1; // caller will log decryption failure
  }
  CATCH_ALL_EXCEPTIONS(-1);
}

void
decryptor_impl::decrypt_unchecked(uint8_t *out,
                                  const uint8_t *in, size_t inlen,
                                  const uint8_t *nonce, size_t nlen)
{
  try {
    // there is no convenience function for this
    this->ctx.Resynchronize(nonce, nlen);
    this->ctx.ProcessData(out, in, inlen);
  }
  CATCH_ALL_EXCEPTIONS();
}
