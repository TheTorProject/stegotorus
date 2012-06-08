/* Copyright 2012 SRI International
 * Based on the public-domain reference implementation of Moeller 2004
 * to be found at http://github.com/zackw/moeller-ref/
 * See LICENSE for other credits and copying information
 */

#ifndef MKEM_H
#define MKEM_H

/* NOTE: The APIs defined in this header should not be used directly.
   Use the crypt.h 'mke_generator' and 'mke_decoder' objects instead. */

#include <openssl/bn.h>
#include <openssl/ec.h>

struct MKEMParams
{
  BN_CTX *ctx;

  const BIGNUM *m;
  const BIGNUM *b;
  const BIGNUM *a0;
  const BIGNUM *a1;
  const BIGNUM *p0;
  const BIGNUM *p1;
  const BIGNUM *n0;
  const BIGNUM *n1;
  const BIGNUM *maxu;

  const EC_GROUP *c0;
  const EC_GROUP *c1;

  const EC_POINT *g0;
  const EC_POINT *g1;

  size_t  msgsize;
  unsigned int pad_bits;
  uint8_t pad_mask;
  uint8_t curve_bit;

  MKEMParams(BN_CTX *ctx);
  ~MKEMParams();

private:
  MKEMParams(const MKEMParams&) DELETE_METHOD;
  MKEMParams& operator=(const MKEMParams&) DELETE_METHOD;
};

// needed to distinguish two constructor overloads
struct MKEMPrivateKeyLoad {};
const struct MKEMPrivateKeyLoad PRIVATE_KEY = {};

struct MKEM
{
  const MKEMParams *params;
  const BIGNUM *s0;
  const BIGNUM *s1;
  const EC_POINT *p0;
  const EC_POINT *p1;

  ~MKEM();

  /** Generate a brand new keypair from randomness. */
  MKEM(const MKEMParams *params);

  /** Load a secret key expressed as two integers (s0, s1), and
      regenerate the public key from it. */
  MKEM(const MKEMParams *params,
       const uint8_t *s0, size_t s0l,
       const uint8_t *s1, size_t s1l,
       const struct MKEMPrivateKeyLoad&);

  /** Load a public key expressed as two elliptic curve points (p0, p1).
      Since the secret key is not available, MKEM_export_secret_key and
      MKEM_decode_message will fail if called on this MKEM. */
  MKEM(const MKEMParams *params,
       const uint8_t *p0, size_t p0l,
       const uint8_t *p1, size_t p1l);

  /** Export the public key as a pair of points. The byte buffers
      must each point to at least params->msgsize+1 bytes of storage. */
  int export_public_key(uint8_t *p1, uint8_t *p2) const;

  /** Export the secret key as a pair of integers. The byte buffers
      must each point to at least params->msgsize bytes of storage. */
  int export_secret_key(uint8_t *s0, uint8_t *s1) const;

  /** Generate secret material K and encrypted message kk from randomness.
      This does NOT carry out key derivation; the "secret" output is what
      the paper describes as $\mathfrak{k} || encode(x_R)$, not KDF of that.
      The 'message' argument must point to at least params->msgsize
      bytes of storage, and the 'secret' argument must point to twice
      that much storage.  */
  int generate(uint8_t *secret, uint8_t *message) const;

  /** Same, but work from a preselected integer 'u', which must be in
      the closed interval [1, params->maxu], and an extra byte's worth
      of random bits for padding.

      This is exposed only for the sake of known-answer tests.  Use of
      non-random 'u' or 'pad' invalidates system properties, as does
      reuse of either value. */
  int generate(const BIGNUM *u, uint8_t pad,
               uint8_t *secret, uint8_t *message) const;

  /* Decode an encrypted message.  As with MKEM_generate_message, the
     result is NOT run through a KDF. */
  int decode(uint8_t *secret, const uint8_t *message) const;

private:
  void load_secret_key();

  MKEM(const MKEM&) DELETE_METHOD;
  MKEM& operator=(const MKEM&) DELETE_METHOD;
};

#endif
