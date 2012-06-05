/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "crypt.h"

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>

static bool crypto_initialized = false;
static bool crypto_errs_initialized = false;

#define REQUIRE_INIT_CRYPTO() \
  log_assert(crypto_initialized)

void
init_crypto()
{
  log_assert(!crypto_initialized);

  crypto_initialized = true;
  CRYPTO_set_mem_functions(xmalloc, xrealloc, free);
  ENGINE_load_builtin_engines();
  ENGINE_register_all_complete();

  // we don't need to call OpenSSL_add_all_algorithms, since we never
  // look up ciphers by textual name.
}

void
free_crypto()
{
  // we don't need to call EVP_cleanup, since we never called
  // OpenSSL_add_all_algorithms.

  if (crypto_initialized)
    ENGINE_cleanup();
  if (crypto_errs_initialized)
    ERR_free_strings();
}

static void
log_crypto()
{
  if (!crypto_errs_initialized) {
    crypto_errs_initialized = true;
    ERR_load_crypto_strings();
  }

  unsigned long err;
  while ((err = ERR_get_error()) != 0)
    log_warn("%s: %s: %s",
             ERR_lib_error_string(err),
             ERR_func_error_string(err),
             ERR_reason_error_string(err));
}

void ATTR_NORETURN
log_crypto_abort(const char *msg)
{
  log_crypto();
  log_abort("libcrypto error in %s", msg);
}

int
log_crypto_warn(const char *msg)
{
  log_crypto();
  log_warn("libcrypto error in %s", msg);
  return -1;
}

static const EVP_CIPHER *
aes_ecb_by_size(size_t keylen)
{
  switch (keylen) {
  case 16: return EVP_aes_128_ecb();
  case 24: return EVP_aes_192_ecb();
  case 32: return EVP_aes_256_ecb();
  default:
    log_abort("AES only supports 16, 24, or 32-byte keys");
  }
}

static const EVP_CIPHER *
aes_gcm_by_size(size_t keylen)
{
  switch (keylen) {
  case 16: return EVP_aes_128_gcm();
  case 24: return EVP_aes_192_gcm();
  case 32: return EVP_aes_256_gcm();
  default:
    log_abort("AES only supports 16, 24, or 32-byte keys");
  }
}

namespace {

  // loosely based on crypto++'s SecByteBlock
  class MemBlock {
  public:
    explicit MemBlock(size_t l) : data(new uint8_t[l]), len(l)
    { memset(data, 0, l); }

    MemBlock(const uint8_t *d, size_t l) : data(new uint8_t[l]), len(l)
    { if (d) memcpy(data, d, l); else memset(data, 0, l); }

    ~MemBlock()
    { memset(data, 0, len); delete [] data; }

    operator const void*() const
    { return data; }
    operator void*()
    { return data; }

    operator const uint8_t*() const
    { return data; }
    operator uint8_t*()
    { return data; }

    const uint8_t *begin() const
    { return data; }
    uint8_t *begin()
    { return data; }

    const uint8_t *end() const
    { return data+len; }
    uint8_t *end()
    { return data+len; }

    size_t size() const { return len; }

  private:
    MemBlock(MemBlock const&) DELETE_METHOD;

    uint8_t *data;
    size_t len;
  };

  struct ecb_encryptor_impl : ecb_encryptor
  {
    EVP_CIPHER_CTX ctx;
    ecb_encryptor_impl() { EVP_CIPHER_CTX_init(&ctx); }
    virtual ~ecb_encryptor_impl();
    virtual void encrypt(uint8_t *out, const uint8_t *in);
  };

  struct ecb_decryptor_impl : ecb_decryptor
  {
    EVP_CIPHER_CTX ctx;
    ecb_decryptor_impl() { EVP_CIPHER_CTX_init(&ctx); }
    virtual ~ecb_decryptor_impl();
    virtual void decrypt(uint8_t *out, const uint8_t *in);
  };
}

ecb_encryptor *
ecb_encryptor::create(const uint8_t *key, size_t keylen)
{
  REQUIRE_INIT_CRYPTO();

  ecb_encryptor_impl *enc = new ecb_encryptor_impl;
  if (!EVP_EncryptInit_ex(&enc->ctx, aes_ecb_by_size(keylen), 0, key, 0))
    log_crypto_abort("ecb_encryptor::create");
  if (!EVP_CIPHER_CTX_set_padding(&enc->ctx, 0))
    log_crypto_abort("ecb_encryptor::disable padding");

  return enc;
}

ecb_encryptor *
ecb_encryptor::create(key_generator *gen, size_t keylen)
{
  REQUIRE_INIT_CRYPTO();

  MemBlock key(keylen);
  size_t got = gen->generate(key, keylen);
  log_assert(got == keylen);

  ecb_encryptor_impl *enc = new ecb_encryptor_impl;
  if (!EVP_EncryptInit_ex(&enc->ctx, aes_ecb_by_size(keylen), 0, key, 0))
    log_crypto_abort("ecb_encryptor::create");
  if (!EVP_CIPHER_CTX_set_padding(&enc->ctx, 0))
    log_crypto_abort("ecb_encryptor::disable padding");

  return enc;
}

ecb_decryptor *
ecb_decryptor::create(const uint8_t *key, size_t keylen)
{
  REQUIRE_INIT_CRYPTO();

  ecb_decryptor_impl *dec = new ecb_decryptor_impl;
  if (!EVP_DecryptInit_ex(&dec->ctx, aes_ecb_by_size(keylen), 0, key, 0))
    log_crypto_abort("ecb_decryptor::create");
  if (!EVP_CIPHER_CTX_set_padding(&dec->ctx, 0))
    log_crypto_abort("ecb_decryptor::disable padding");

  return dec;
}

ecb_decryptor *
ecb_decryptor::create(key_generator *gen, size_t keylen)
{
  REQUIRE_INIT_CRYPTO();

  MemBlock key(keylen);
  size_t got = gen->generate(key, keylen);
  log_assert(got == keylen);

  ecb_decryptor_impl *dec = new ecb_decryptor_impl;
  if (!EVP_DecryptInit_ex(&dec->ctx, aes_ecb_by_size(keylen), 0, key, 0))
    log_crypto_abort("ecb_decryptor::create");
  if (!EVP_CIPHER_CTX_set_padding(&dec->ctx, 0))
    log_crypto_abort("ecb_decryptor::disable padding");

  return dec;
}

ecb_encryptor::~ecb_encryptor() {}
ecb_encryptor_impl::~ecb_encryptor_impl()
{ EVP_CIPHER_CTX_cleanup(&ctx); }

ecb_decryptor::~ecb_decryptor() {}
ecb_decryptor_impl::~ecb_decryptor_impl()
{ EVP_CIPHER_CTX_cleanup(&ctx); }

void
ecb_encryptor_impl::encrypt(uint8_t *out, const uint8_t *in)
{
  int olen;
  if (!EVP_EncryptUpdate(&ctx, out, &olen, in, AES_BLOCK_LEN) ||
      size_t(olen) != AES_BLOCK_LEN)
    log_crypto_abort("ecb_encryptor::encrypt");
}

void
ecb_decryptor_impl::decrypt(uint8_t *out, const uint8_t *in)
{
  int olen;
  if (!EVP_DecryptUpdate(&ctx, out, &olen, in, AES_BLOCK_LEN) ||
      size_t(olen) != AES_BLOCK_LEN)
    log_crypto_abort("ecb_decryptor::decrypt");
}

namespace {
  struct gcm_encryptor_impl : gcm_encryptor
  {
    EVP_CIPHER_CTX ctx;
    gcm_encryptor_impl() { EVP_CIPHER_CTX_init(&ctx); }
    virtual ~gcm_encryptor_impl();
    virtual void encrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                         const uint8_t *nonce, size_t nlen);
  };

  struct gcm_decryptor_impl : gcm_decryptor
  {
    EVP_CIPHER_CTX ctx;
    gcm_decryptor_impl() { EVP_CIPHER_CTX_init(&ctx); }
    virtual ~gcm_decryptor_impl();
    virtual int decrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                        const uint8_t *nonce, size_t nlen);
  };
}

// It *appears* (from inspecting the guts of libcrypto, *not* from the
// documentation) that - at least for AES-GCM - it is legitimate to
// call EVP_EncryptInit once with a key but no IV, and then once per
// block with an IV but no key.  If this doesn't turn out to work,
// there are also some (completely undocumented, feh) EVP_CTRL_* ops
// that might help, but in the worst case we may have to save the key
// at creation time, and delay the EVP_EncryptInit call to when we
// know both key and IV, i.e. at block-encryption time.  This would be
// unfortunate since it would entail doing AES key expansion once per
// block instead of once per key.

// It also *appears* (again, from inspecting the guts of libcrypto)
// that we do not have to worry about EVP_EncryptFinal trying to do
// PKCS padding when GCM is in use.  If this is wrong we will have to
// find some way to make it not happen, which might entail ditching
// EVP.  Feh, I say, feh.

gcm_encryptor *
gcm_encryptor::create(const uint8_t *key, size_t keylen)
{
  REQUIRE_INIT_CRYPTO();

  gcm_encryptor_impl *enc = new gcm_encryptor_impl;
  if (!EVP_EncryptInit_ex(&enc->ctx, aes_gcm_by_size(keylen), 0, key, 0))
    log_crypto_abort("gcm_encryptor::create");

  return enc;
}

gcm_encryptor *
gcm_encryptor::create(key_generator *gen, size_t keylen)
{
  REQUIRE_INIT_CRYPTO();

  MemBlock key(keylen);
  size_t got = gen->generate(key, keylen);
  log_assert(got == keylen);

  gcm_encryptor_impl *enc = new gcm_encryptor_impl;
  if (!EVP_EncryptInit_ex(&enc->ctx, aes_gcm_by_size(keylen), 0, key, 0))
    log_crypto_abort("gcm_encryptor::create");

  return enc;
}

gcm_decryptor *
gcm_decryptor::create(const uint8_t *key, size_t keylen)
{
  REQUIRE_INIT_CRYPTO();

  gcm_decryptor_impl *dec = new gcm_decryptor_impl;
  if (!EVP_DecryptInit_ex(&dec->ctx, aes_gcm_by_size(keylen), 0, key, 0))
    log_crypto_abort("gcm_decryptor::create");

  return dec;
}

gcm_decryptor *
gcm_decryptor::create(key_generator *gen, size_t keylen)
{
  REQUIRE_INIT_CRYPTO();

  MemBlock key(keylen);
  size_t got = gen->generate(key, keylen);
  log_assert(got == keylen);

  gcm_decryptor_impl *dec = new gcm_decryptor_impl;
  if (!EVP_DecryptInit_ex(&dec->ctx, aes_gcm_by_size(keylen), 0, key, 0))
    log_crypto_abort("gcm_decryptor::create");

  return dec;
}

gcm_encryptor::~gcm_encryptor() {}
gcm_encryptor_impl::~gcm_encryptor_impl()
{ EVP_CIPHER_CTX_cleanup(&ctx); }
gcm_decryptor::~gcm_decryptor() {}
gcm_decryptor_impl::~gcm_decryptor_impl()
{ EVP_CIPHER_CTX_cleanup(&ctx); }

void
gcm_encryptor_impl::encrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                            const uint8_t *nonce, size_t nlen)
{
  log_assert(inlen <= size_t(INT_MAX));

  if (nlen != size_t(EVP_CIPHER_CTX_iv_length(&ctx)))
    if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, nlen, 0))
      log_crypto_abort("gcm_encryptor::reset nonce length");

  if (!EVP_EncryptInit_ex(&ctx, 0, 0, 0, nonce))
    log_crypto_abort("gcm_encryptor::set nonce");

  int olen;
  if (!EVP_EncryptUpdate(&ctx, 0, &olen, (const uint8_t *)"", 0) || olen != 0)
    log_crypto_abort("gcm_encryptor::set null AAD");

  if (!EVP_EncryptUpdate(&ctx, out, &olen, in, inlen) || size_t(olen) != inlen)
    log_crypto_abort("gcm_encryptor::encrypt");

  if (!EVP_EncryptFinal_ex(&ctx, out + inlen, &olen) || olen != 0)
    log_crypto_abort("gcm_encryptor::finalize");

  if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, 16, out + inlen))
    log_crypto_abort("gcm_encryptor::write tag");
}

int
gcm_decryptor_impl::decrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                            const uint8_t *nonce, size_t nlen)
{
  log_assert(inlen <= size_t(INT_MAX));

  if (nlen != size_t(EVP_CIPHER_CTX_iv_length(&ctx)))
    if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, nlen, 0))
      log_crypto_abort("gcm_decryptor::reset nonce length");

  if (!EVP_DecryptInit_ex(&ctx, 0, 0, 0, nonce))
    return log_crypto_warn("gcm_decryptor::set nonce");

  if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, 16,
                           (void *)(in + inlen - 16)))
    return log_crypto_warn("gcm_decryptor::set tag");

  int olen;
  if (!EVP_DecryptUpdate(&ctx, 0, &olen, (const uint8_t *)"", 0) || olen != 0)
    return log_crypto_warn("gcm_decryptor::set null AAD");

  inlen -= 16;
  if (!EVP_DecryptUpdate(&ctx, out, &olen, in, inlen) || size_t(olen) != inlen)
    return log_crypto_warn("gcm_encryptor::decrypt");

  if (!EVP_DecryptFinal_ex(&ctx, out + inlen, &olen) || olen != 0) {
    /* don't warn for simple MAC failures */
    if (!ERR_peek_error())
      return -1;
    return log_crypto_warn("gcm_decryptor::check tag");
  }

  return 0;
}

// We use the slightly lower-level EC_* / ECDH_* routines for
// ecdh_message, instead of the EVP_PKEY_* routines, because we don't
// need algorithmic agility, and it means we only have to puzzle out
// one layer of completely undocumented APIs instead of two.
namespace {
  struct ecdh_message_impl : ecdh_message
  {
    EC_KEY *priv;
    BN_CTX *ctx;
    ecdh_message_impl(); // generate keypair from randomness

    virtual ~ecdh_message_impl();
    virtual void encode(uint8_t *xcoord_out) const;
    virtual int combine(const uint8_t *other, uint8_t *secret_out) const;
  };
}

ecdh_message_impl::ecdh_message_impl()
  : priv(EC_KEY_new_by_curve_name(NID_secp224r1)),
    ctx(BN_CTX_new())
{
  if (!priv || !ctx)
    log_crypto_abort("ecdh_message::allocate data");
  if (!EC_KEY_generate_key(priv))
    log_crypto_abort("ecdh_message::generate priv");
}

/* static */ ecdh_message *
ecdh_message::generate()
{
  REQUIRE_INIT_CRYPTO();
  return new ecdh_message_impl();
}

ecdh_message::~ecdh_message() {}
ecdh_message_impl::~ecdh_message_impl()
{
  EC_KEY_free(priv);
  BN_CTX_free(ctx);
}

void
ecdh_message_impl::encode(uint8_t *xcoord_out) const
{
  const EC_POINT *pub = EC_KEY_get0_public_key(priv);
  const EC_GROUP *grp = EC_KEY_get0_group(priv);
  if (!pub || !grp)
    log_crypto_abort("ecdh_message_encode::extract pubkey");

  BIGNUM *x = BN_new();
  if (!x)
    log_crypto_abort("ecdh_message_encode::allocate data");

  if (!EC_POINT_get_affine_coordinates_GFp(grp, pub, x, 0, ctx))
    log_crypto_abort("ecdh_message_encode::extract x-coordinate");

  size_t sbytes = BN_num_bytes(x);
  log_assert(sbytes <= EC_P224_LEN);
  if (sbytes < EC_P224_LEN) {
    memset(xcoord_out, 0, EC_P224_LEN - sbytes);
    sbytes += EC_P224_LEN - sbytes;
  }
  size_t wbytes = BN_bn2bin(x, xcoord_out);
  log_assert(sbytes == wbytes);

  BN_free(x);
}

int
ecdh_message_impl::combine(const uint8_t *xcoord_other,
                           uint8_t *secret_out) const
{
  const EC_GROUP *grp = EC_KEY_get0_group(priv);
  EC_POINT *pub = EC_POINT_new(grp);
  if (!grp || !pub)
    log_crypto_abort("ecdh_message_combine::allocate data");

  int rv = -1;
  BIGNUM *x = BN_bin2bn(xcoord_other, EC_P224_LEN, 0);
  if (!x) {
    log_crypto_warn("ecdh_message_combine::decode their x-coordinate");
    goto done;
  }

  if (!EC_POINT_set_compressed_coordinates_GFp(grp, pub, x, 0, ctx)) {
    log_crypto_warn("ecdh_message_combine::recover their point");
    goto done;
  }

  if (!ECDH_compute_key(secret_out, EC_P224_LEN, pub, priv, 0)) {
    log_crypto_warn("ecdh_message_combine::compute shared secret");
    goto done;
  }

    rv = 0;
 done:
  BN_free(x);
  EC_POINT_free(pub);
  return rv;
}

namespace {
  struct key_generator_impl : key_generator
  {
    HMAC_CTX expander;
    MemBlock prevT;
    MemBlock info;

    uint8_t counter;
    uint8_t leftover;
    bool dead;

    virtual ~key_generator_impl();
    virtual size_t generate(uint8_t *buf, size_t len);

    key_generator_impl(const uint8_t *prk, const uint8_t *info, size_t ilen)
      : prevT(SHA256_LEN),
        info(info, ilen),
        counter(1),
        leftover(0),
        dead(false)
    {
      HMAC_CTX_init(&expander);
      if (!HMAC_Init_ex(&expander, prk, SHA256_LEN, EVP_sha256(), 0))
        log_crypto_abort("key_generator_impl::construction");
    }
  };
}

static const uint8_t nosalt[SHA256_LEN] = {};

key_generator *
key_generator::from_random_secret(const uint8_t *key,  size_t klen,
                                  const uint8_t *salt, size_t slen,
                                  const uint8_t *ctxt, size_t clen)
{
  log_assert(klen <= INT_MAX && slen < INT_MAX && clen < INT_MAX);
  REQUIRE_INIT_CRYPTO();

  MemBlock prk(SHA256_LEN);

  if (slen == 0) {
    salt = nosalt;
    slen = SHA256_LEN;
  }

  if (HMAC(EVP_sha256(), salt, slen, key, klen, prk, 0) == 0)
    log_crypto_abort("key_generator::from_random_secret");

  return new key_generator_impl(prk, ctxt, clen);
}

key_generator *
key_generator::from_ecdh(const ecdh_message *mine, const uint8_t *theirs,
                         const uint8_t *salt, size_t slen,
                         const uint8_t *ctxt, size_t clen)
{
  MemBlock ss(EC_P224_LEN);
  if (mine->combine(theirs, ss))
    return 0;

  return from_random_secret(ss, EC_P224_LEN, salt, slen, ctxt, clen);
}

key_generator *
key_generator::from_passphrase(const uint8_t *phra, size_t plen,
                               const uint8_t *salt, size_t slen,
                               const uint8_t *ctxt, size_t clen)
{
  // The PBKDF2-HMAC<hash> construction, ignoring the iteration
  // process, is very similar to the HKDF-Extract<hash> construction;
  // the biggest difference is that you key the HMAC with the
  // passphrase rather than the salt.  I *think* it is appropriate
  // to just feed its output directly to the HKDF-Expand phase; an
  // alternative would be to run PBKDF2 on the passphrase without a
  // salt, then put the result through HKDF-Extract with the salt.

  log_assert(plen <= INT_MAX && slen < INT_MAX);
  REQUIRE_INIT_CRYPTO();

  MemBlock prk(SHA256_LEN);

  if (slen == 0) {
    salt = nosalt;
    slen = SHA256_LEN;
  }

  if (!PKCS5_PBKDF2_HMAC((const char *)phra, plen, salt, slen,
                         10000, EVP_sha256(), SHA256_LEN, prk))
    log_crypto_abort("key_generator::from_passphrase");

  return new key_generator_impl(prk, ctxt, clen);
}

size_t
key_generator_impl::generate(uint8_t *buf, size_t len)
{
  if (dead) {
    memset(buf, 0, len);
    return 0;
  }

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
    // compute the next block
    if (!HMAC_Update(&expander, info, info.size()))
      log_crypto_abort("generate::apply info");
    if (!HMAC_Update(&expander, &counter, 1))
      log_crypto_abort("generate::apply counter");
    if (!HMAC_Final(&expander, prevT, 0))
      log_crypto_abort("generate::extract");

    if (n + SHA256_LEN < len) {
      memcpy(buf + n, prevT, SHA256_LEN);
      n += SHA256_LEN;
    } else {
      leftover = SHA256_LEN - (len - n);
      memcpy(buf + n, prevT, len - n);
      n = len;
    }

    // prepare to compute the next+1 block
    counter++;
    if (counter == 0) {
      if (n < len)
        memset(buf + n, 0, len - n);
      dead = true;
      break;
    }

    if (!HMAC_Init_ex(&expander, 0, 0, 0, 0))
      log_crypto_abort("generate::reset hmac");
    if (!HMAC_Update(&expander, prevT, prevT.size()))
      log_crypto_abort("generate::feedback");
  }

  return n;
}

key_generator::~key_generator() {}
key_generator_impl::~key_generator_impl()
{ HMAC_CTX_cleanup(&expander); }
