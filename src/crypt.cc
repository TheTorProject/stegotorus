/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "crypt.h"

// temporary, I hope, kludge
#ifdef __APPLE_CC__
#define CRYPTOPP_DISABLE_X86ASM
#endif

#include <cryptopp/aes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/gcm.h>
#include <cryptopp/sha.h>

// work around a bug in crypto++ 5.6.0's pwdbased.h
#if CRYPTOPP_VERSION < 561
namespace CryptoPP {
class Integer {
public:
  Integer& operator++();
  Integer& operator+(Integer const&);
  void Encode(...);
};
}
#endif

#include <cryptopp/pwdbased.h>

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

// Crypto++ doesn't let us set a key without also setting an IV,
// even though we will always override the IV later.
static const uint8_t dummy_iv[16] = {};

namespace {
  struct ecb_encryptor_impl : ecb_encryptor
  {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption ctx;
    virtual ~ecb_encryptor_impl();
    virtual void encrypt(uint8_t *out, const uint8_t *in);
  };

  struct ecb_decryptor_impl : ecb_decryptor
  {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption ctx;
    virtual ~ecb_decryptor_impl();
    virtual void decrypt(uint8_t *out, const uint8_t *in);
  };
}

ecb_encryptor *
ecb_encryptor::create(const uint8_t *key, size_t keylen)
{
  try {
    ecb_encryptor_impl *enc = new ecb_encryptor_impl;
    enc->ctx.SetKey(key, keylen);
    return enc;
  }
  CATCH_ALL_EXCEPTIONS(0);
}

ecb_decryptor *
ecb_decryptor::create(const uint8_t *key, size_t keylen)
{
  try {
    ecb_decryptor_impl *dec = new ecb_decryptor_impl;
    dec->ctx.SetKey(key, keylen);
    return dec;
  }
  CATCH_ALL_EXCEPTIONS(0);
}

ecb_encryptor::~ecb_encryptor() {}
ecb_encryptor_impl::~ecb_encryptor_impl() {}
ecb_decryptor::~ecb_decryptor() {}
ecb_decryptor_impl::~ecb_decryptor_impl() {}

void
ecb_encryptor_impl::encrypt(uint8_t *out, const uint8_t *in)
{
  try {
    this->ctx.ProcessData(out, in, AES_BLOCK_LEN);
  }
  CATCH_ALL_EXCEPTIONS();
}

void
ecb_decryptor_impl::decrypt(uint8_t *out, const uint8_t *in)
{
  try {
    this->ctx.ProcessData(out, in, AES_BLOCK_LEN);
  }
  CATCH_ALL_EXCEPTIONS();
}

namespace {
  struct gcm_encryptor_impl : gcm_encryptor
  {
    CryptoPP::GCM<CryptoPP::AES>::Encryption ctx;
    virtual ~gcm_encryptor_impl();
    virtual void encrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                         const uint8_t *nonce, size_t nlen);
  };

  struct gcm_decryptor_impl : gcm_decryptor
  {
    CryptoPP::GCM<CryptoPP::AES>::Decryption ctx;
    virtual ~gcm_decryptor_impl();
    virtual int decrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                        const uint8_t *nonce, size_t nlen);
    virtual void decrypt_unchecked(uint8_t *out,
                                   const uint8_t *in, size_t inlen,
                                   const uint8_t *nonce, size_t nlen);
  };
}

gcm_encryptor *
gcm_encryptor::create(const uint8_t *key, size_t keylen)
{
  try {
    gcm_encryptor_impl *enc = new gcm_encryptor_impl;
    // sadly, these are not checkable at compile time
    log_assert(enc->ctx.DigestSize() == GCM_TAG_LEN);
    log_assert(!enc->ctx.NeedsPrespecifiedDataLengths());
    enc->ctx.SetKeyWithIV(key, keylen, dummy_iv, sizeof dummy_iv);
    return enc;
  }
  CATCH_ALL_EXCEPTIONS(0);
}

gcm_decryptor *
gcm_decryptor::create(const uint8_t *key, size_t keylen)
{
  try {
    gcm_decryptor_impl *dec = new gcm_decryptor_impl;
    // sadly, these are not checkable at compile time
    log_assert(dec->ctx.DigestSize() == GCM_TAG_LEN);
    log_assert(!dec->ctx.NeedsPrespecifiedDataLengths());
    dec->ctx.SetKeyWithIV(key, keylen, dummy_iv, sizeof dummy_iv);
    return dec;
  }
  CATCH_ALL_EXCEPTIONS(0);
}

gcm_encryptor::~gcm_encryptor() {}
gcm_encryptor_impl::~gcm_encryptor_impl() {}
gcm_decryptor::~gcm_decryptor() {}
gcm_decryptor_impl::~gcm_decryptor_impl() {}

void
gcm_encryptor_impl::encrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                            const uint8_t *nonce, size_t nlen)
{
  try {
    this->ctx.EncryptAndAuthenticate(out, out + inlen, 16,
                                     nonce, nlen, 0, 0, in, inlen);
  }
  CATCH_ALL_EXCEPTIONS();
}

int
gcm_decryptor_impl::decrypt(uint8_t *out, const uint8_t *in, size_t inlen,
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
gcm_decryptor_impl::decrypt_unchecked(uint8_t *out,
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

typedef CryptoPP::HMAC<CryptoPP::SHA256> HMAC_SHA256;
typedef CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> PBKDF2_SHA256;
const size_t SHA256_LEN = CryptoPP::SHA256::DIGESTSIZE;

namespace {
  struct key_generator_impl : key_generator
  {
    HMAC_SHA256 expander;
    CryptoPP::SecByteBlock prevT;
    CryptoPP::SecByteBlock info;
    uint8_t counter;
    uint8_t leftover;
    bool dead : 1;

    virtual ~key_generator_impl();
    virtual size_t generate(uint8_t *buf, size_t len);

    key_generator_impl(const uint8_t *prk,
                       const uint8_t *info, size_t ilen)
      : expander(prk, SHA256_LEN),
        prevT(0),
        info(info, ilen),
        counter(1),
        leftover(0),
        dead(false)
    {}
  };
}

key_generator *
key_generator::from_random_secret(const uint8_t *key,  size_t klen,
                                  const uint8_t *salt, size_t slen,
                                  const uint8_t *ctxt, size_t clen)
{
  try {
    HMAC_SHA256 extractor;
    static const uint8_t nosalt[SHA256_LEN] = {};
    uint8_t prk[SHA256_LEN];

    if (slen == 0) {
      salt = nosalt;
      slen = SHA256_LEN;
    }

    extractor.SetKey(salt, slen);
    extractor.CalculateDigest(prk, key, klen);

    key_generator *r = new key_generator_impl(prk, ctxt, clen);
    memset(prk, 0, SHA256_LEN);
    return r;
  }
  CATCH_ALL_EXCEPTIONS(0);
}

key_generator *
key_generator::from_passphrase(const uint8_t *phra, size_t plen,
                               const uint8_t *salt, size_t slen,
                               const uint8_t *ctxt, size_t clen)
{
  try {
    PBKDF2_SHA256 extractor;
    static const uint8_t nosalt[SHA256_LEN] = {};
    uint8_t prk[SHA256_LEN];

    if (slen == 0) {
      salt = nosalt;
      slen = SHA256_LEN;
    }

    // The PBKDF2-HMAC<hash> construction, ignoring the iteration
    // process, is very similar to the HKDF-Extract<hash> construction;
    // the biggest difference is that you key the HMAC with the
    // passphrase rather than the salt.  I *think* it is appropriate
    // to just feed its output directly to the HKDF-Expand phase; an
    // alternative would be to run PBKDF2 on the passphrase without a
    // salt, then put the result through HKDF-Extract with the salt.
    //
    // 1000 iterations or 50 ms, whichever is more
    extractor.DeriveKey(prk, SHA256_LEN, 0, phra, plen, salt, slen, 1000, 0.05);

    key_generator *r = new key_generator_impl(prk, ctxt, clen);
    memset(prk, 0, SHA256_LEN);
    return r;
  }
  CATCH_ALL_EXCEPTIONS(0);
}

size_t
key_generator_impl::generate(uint8_t *buf, size_t len)
{
  if (dead) {
    memset(buf, 0, len);
    return 0;
  }
  try {
    size_t n = 0;
    if (leftover >= len) {
      memcpy(buf, prevT.end() - leftover, len);
      leftover -= len;
      return len;
    } else if (leftover) {
      memcpy(buf, prevT.end() - leftover, leftover);
      n += leftover;
      leftover = 0;
    }
    while (n < len) {
      // generate the next block
      expander.Update(prevT, prevT.size());
      expander.Update(info, info.size());
      expander.Update(&counter, 1);
      counter++;
      prevT.New(SHA256_LEN);
      expander.Final(prevT);

      if (n + SHA256_LEN < len) {
        memcpy(buf + n, prevT, SHA256_LEN);
        n += SHA256_LEN;
      } else {
        leftover = SHA256_LEN - (len - n);
        memcpy(buf + n, prevT, len - n);
        n = len;
      }
      if (counter == 0) {
        if (n < len)
          memset(buf + n, 0, len - n);
        dead = true;
        break;
      }
    }
    return n;
  }
  CATCH_ALL_EXCEPTIONS((memset(buf, 0, len), 0));
}

key_generator::~key_generator() {}
key_generator_impl::~key_generator_impl() {}
