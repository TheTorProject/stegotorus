/* Copyright 2012 SRI International
 * Based on the public-domain reference implementation of Moeller 2004
 * to be found at http://github.com/zackw/moeller-ref/
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "crypt.h"
#include "mkem.h"

#include <openssl/rand.h>

/* Encapsulation of a set of elliptic curve parameters. */

struct mk_curve_params
{
  /* generating polynomial, aka reducing polynomial, aka modulus: bignum */
  const uint8_t *m;
  size_t       L_m;

  /* elliptic curve coefficient 'b': bignum */
  const uint8_t *b;
  size_t       L_b;

  /* curve group large primes: bignum */
  const uint8_t *p0;
  size_t       L_p0;
  const uint8_t *p1;
  size_t       L_p1;

  /* curve group sizes: bignum */
  const uint8_t *n0;
  size_t       L_n0;
  const uint8_t *n1;
  size_t       L_n1;

  /* curve group generators: points (SEC1 compressed format) */
  const uint8_t *g0;
  size_t       L_g0;
  const uint8_t *g1;
  size_t       L_g1;
};

/* MK_CURVE_nbits_index constants correspond to particular curves
   for which this algorithm is defined.  Currently there is only one. */

enum MKEMCurve {
  MK_CURVE_163_0  /* original 163-bit curve from Moeller 2004 */
};


/* All the known curves that can be used with this algorithm are
   defined by mk_curve_params objects in this array. */

/* work around lack of compound literals in C89 */
#define S_(c) #c
#define S(c) S_(\x##c)

/* 21-byte hexadecimal bignum */
#define N21(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u)          \
  (const uint8_t *)(S(a) S(b) S(c) S(d) S(e) S(f) S(g)          \
                    S(h) S(i) S(j) S(k) S(l) S(m) S(n)          \
                    S(o) S(p) S(q) S(r) S(s) S(t) S(u)), 21

/* 21+1-byte compressed hexadecimal curve point */
#define P21(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u)          \
  (const uint8_t *)(S(02)                                       \
                    S(a) S(b) S(c) S(d) S(e) S(f) S(g)          \
                    S(h) S(i) S(j) S(k) S(l) S(m) S(n)          \
                    S(o) S(p) S(q) S(r) S(s) S(t) S(u)), 22

const mk_curve_params mk_curves[] = {
/* MK_CURVE_163_0:
   p0 = 2923003274661805836407371179614143033958162426611, n0 = p0*4
   p1 = 5846006549323611672814736302501978089331135490587, n1 = p1*2  */
{
  N21(08,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,c9), /* m  */
  N21(05,84,6d,0f,da,25,53,61,60,67,11,bf,7a,99,b0,72,2e,2e,c8,f7,6b), /* b  */

  N21(02,00,00,00,00,00,00,00,00,00,01,40,a3,f2,a0,c6,ce,d9,ce,ea,f3), /* p0 */
  N21(03,ff,ff,ff,ff,ff,ff,ff,ff,ff,fd,7e,b8,1a,be,72,62,4c,62,2a,1b), /* p1 */

  N21(08,00,00,00,00,00,00,00,00,00,05,02,8f,ca,83,1b,3b,67,3b,ab,cc), /* n0 */
  N21(07,ff,ff,ff,ff,ff,ff,ff,ff,ff,fa,fd,70,35,7c,e4,c4,98,c4,54,36), /* n1 */

  P21(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01), /* g0 */
  P21(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,02)  /* g1 */
},

};

#undef S_
#undef S
#undef N21
#undef P21

#define FAILZ(expr) if ((expr) == 0) goto fail;

MKEMParams::MKEMParams(BN_CTX *ctx)
  : ctx(ctx),
    m(0), b(0), a0(0), a1(0), p0(0), p1(0), n0(0), n1(0), maxu(0),
    c0(0), c1(0), g0(0), g1(0),
    msgsize(0), pad_bits(0), pad_mask(0), curve_bit(0)
{
  const mk_curve_params *p = &mk_curves[MK_CURVE_163_0];
  size_t bitsize, bytesize, bitcap, k;

  FAILZ(m  = BN_bin2bn(p->m,  p->L_m,  0));
  FAILZ(b  = BN_bin2bn(p->b,  p->L_b,  0));
  FAILZ(a0 = BN_new()); FAILZ(BN_zero((BIGNUM *)a0));
  FAILZ(a1 = BN_value_one());
  FAILZ(p0 = BN_bin2bn(p->p0, p->L_p0, 0));
  FAILZ(p1 = BN_bin2bn(p->p1, p->L_p1, 0));
  FAILZ(n0 = BN_bin2bn(p->n0, p->L_n0, 0));
  FAILZ(n1 = BN_bin2bn(p->n1, p->L_n1, 0));

  FAILZ(c0 = EC_GROUP_new_curve_GF2m(m, a0, b, ctx));
  FAILZ(c1 = EC_GROUP_new_curve_GF2m(m, a1, b, ctx));

  FAILZ(g0 = EC_POINT_new(c0));
  FAILZ(EC_POINT_oct2point(c0, (EC_POINT *)g0, p->g0, p->L_g0, ctx));
  FAILZ(g1 = EC_POINT_new(c1));
  FAILZ(EC_POINT_oct2point(c1, (EC_POINT *)g1, p->g1, p->L_g1, ctx));

  /* Calculate the upper limit for the random integer U input to
     MKEM_generate_message_u.

     The paper calls for us to choose between curve 0 and curve 1 with
     probability proportional to the number of points on that curve, and
     then choose a random integer in the range 0 < u < n{curve}.  The
     easiest way to do this accurately is to choose a random integer in the
     range [1, n0 + n1 - 2].  If it is less than n0, MKEM_generate_message_u
     will use it unmodified with curve 0.  If it is greater than or equal
     to n0, MKEM_generate_message_u will subtract n0-1, leaving a number in
     the range [1, n1-1], and use that with curve 1. */

  BIGNUM *mu;
  FAILZ(mu = BN_dup(n0));
  FAILZ(BN_add(mu, mu, n1));
  FAILZ(BN_sub(mu, mu, BN_value_one()));
  FAILZ(BN_sub(mu, mu, BN_value_one()));
  maxu = mu;

  /* Calculate the maximum size of a message and the padding mask applied
     to the high byte of each message.  See MKEM_generate_message_u for
     further exposition. */
  bitsize = EC_GROUP_get_degree(c0);
  if ((size_t)EC_GROUP_get_degree(c1) != bitsize)
    goto fail;

  bytesize = (bitsize + 7) / 8;
  bitcap = bytesize * 8;
  k = bitcap - bitsize;
  if (k == 0)
    goto fail;

  msgsize   = bytesize;
  pad_bits  = k - 1;
  pad_mask  = ~((1 << (8 - pad_bits)) - 1);
  curve_bit = 1 << (8 - k);
  return;

 fail:
  log_crypto_abort("MKEMParams constructor");
}

MKEMParams::~MKEMParams()
{
  /* None of the values in an MKEMParams are secret, so don't bother
     clearing them. */

  /* We do not own 'ctx'.  */

  if (m)    BN_free((BIGNUM *)m);
  if (b)    BN_free((BIGNUM *)b);
  if (a0)   BN_free((BIGNUM *)a0);
  /* a1 is the static BN_value_one() constant and should not be freed. */
  if (p0)   BN_free((BIGNUM *)p0);
  if (p1)   BN_free((BIGNUM *)p1);
  if (n0)   BN_free((BIGNUM *)n0);
  if (n1)   BN_free((BIGNUM *)n1);
  if (maxu) BN_free((BIGNUM *)maxu);

  if (c0)   EC_GROUP_free((EC_GROUP *)c1);
  if (c1)   EC_GROUP_free((EC_GROUP *)c1);

  if (g0)   EC_POINT_free((EC_POINT *)g0);
  if (g1)   EC_POINT_free((EC_POINT *)g1);

  memset(this, 0, sizeof(*this));
}


MKEM::~MKEM()
{
  /* s0 and s1 are secret. p0 and p1 are not secret, but clear them
     anyway. */
  if (s0) BN_clear_free((BIGNUM *)s0);
  if (s1) BN_clear_free((BIGNUM *)s1);

  if (p0) EC_POINT_clear_free((EC_POINT *)p0);
  if (p1) EC_POINT_clear_free((EC_POINT *)p1);

  memset(this, 0, sizeof(*this));
}

/* The secret integers s0 and s1 must be in the range 0 < s < n for
   some n, and must be relatively prime to that n.  We know a priori
   that n is of the form 2**k * p for some small integer k and prime
   p.  Therefore, it suffices to choose a random integer in the range
   [0, n/2), multiply by two and add one (enforcing oddness), and then
   reject values which are divisible by p.  */
static BIGNUM *
random_s(const BIGNUM *n, const BIGNUM *p, BN_CTX *c)
{
  BIGNUM h, m, *r;

  BN_init(&h);
  BN_init(&m);
  FAILZ(r = BN_new());
  FAILZ(BN_copy(&h, n));
  FAILZ(BN_rshift1(&h, &h));

  do {
    FAILZ(BN_rand_range(r, &h));
    FAILZ(BN_lshift1(r, r));
    FAILZ(BN_add(r, r, BN_value_one()));
    FAILZ(BN_nnmod(&m, r, p, c));
  } while (BN_is_zero(&m));

  BN_clear(&h);
  BN_clear(&m);
  return r;

 fail:
  BN_clear(&h);
  BN_clear(&m);
  if (r) BN_clear_free(r);
  return 0;
}

void
MKEM::load_secret_key()
{
  FAILZ(params); FAILZ(s0); FAILZ(s1);

  FAILZ(p0 = EC_POINT_new(params->c0));
  FAILZ(p1 = EC_POINT_new(params->c1));
  FAILZ(EC_POINT_mul(params->c0, (EC_POINT *)p0, 0, params->g0, s0,
                     params->ctx));
  FAILZ(EC_POINT_mul(params->c1, (EC_POINT *)p1, 0, params->g1, s1,
                     params->ctx));
  return;

 fail:
  log_crypto_abort("MKEM::MKEM(secret)");
}

MKEM::MKEM(const MKEMParams *params,
           const uint8_t *s0v, size_t s0l,
           const uint8_t *s1v, size_t s1l,
           const struct MKEMPrivateKeyLoad&)
  : params(params),
    s0(BN_bin2bn(s0v, s0l, 0)),
    s1(BN_bin2bn(s1v, s1l, 0)),
    p0(0), p1(0)
{
  load_secret_key();
}

MKEM::MKEM(const MKEMParams *params)
  : params(params),
    s0(random_s(params->n0, params->p0, params->ctx)),
    s1(random_s(params->n1, params->p1, params->ctx)),
    p0(0), p1(0)
{
  load_secret_key();
}

MKEM::MKEM(const MKEMParams *params,
           const uint8_t *p0v, size_t p0l,
           const uint8_t *p1v, size_t p1l)
  : params(params), s0(0), s1(0), p0(0), p1(0)
{
  EC_POINT *pp0 = EC_POINT_new(params->c0);
  EC_POINT *pp1 = EC_POINT_new(params->c1);

  FAILZ(pp0); FAILZ(pp1);
  FAILZ(EC_POINT_oct2point(params->c0, pp0, p0v, p0l, params->ctx));
  FAILZ(EC_POINT_oct2point(params->c1, pp1, p1v, p1l, params->ctx));

  p0 = pp0;
  p1 = pp1;
  return;

 fail:
  log_crypto_abort("MKEM::MKEM(public)");
}

int
MKEM::export_public_key(uint8_t *p0o, uint8_t *p1o) const
{
  size_t vsize = params->msgsize + 1;

  if (EC_POINT_point2oct(params->c0, p0, POINT_CONVERSION_COMPRESSED,
                         p0o, vsize, params->ctx) != vsize ||
      EC_POINT_point2oct(params->c1, p1, POINT_CONVERSION_COMPRESSED,
                         p1o, vsize, params->ctx) != vsize)
    return -1;
  return 0;
}

/* Write the BIGNUM 'b' to 'to', padded at the high end so that the
   result occupies _exactly_ 'sz' bytes.  If 'b' requires more than
   'sz' bytes it is an error. */
static size_t
bn2bin_padhi(const BIGNUM *b, uint8_t *to, size_t sz)
{
  size_t n = BN_num_bytes(b);
  if (n > sz)
    return 0;
  if (n < sz) {
    memset(to, 0, sz - n);
    to += sz - n;
  }
  return BN_bn2bin(b, to) + (sz - n);
}

int
MKEM::export_secret_key(uint8_t *s0o, uint8_t *s1o) const
{
  if (!s0 || !s1) return -1;

  if (bn2bin_padhi(s0, s0o, params->msgsize) != params->msgsize ||
      bn2bin_padhi(s1, s1o, params->msgsize) != params->msgsize)
    return -1;
  return 0;
}

int
MKEM::generate(uint8_t *secret, uint8_t *message) const
{
  BIGNUM u;
  uint8_t pad;
  int rv = -1;
  BN_init(&u);
  if (BN_rand_range(&u, params->maxu) &&
      BN_add(&u, &u, BN_value_one()) &&
      RAND_bytes(&pad, 1) &&
      !generate(&u, pad, secret, message))
    rv = 0;

  BN_clear(&u);
  return rv;
}

int
MKEM::generate(const BIGNUM *uraw, uint8_t pad,
               uint8_t *secret, uint8_t *message) const
{
  BIGNUM u, x, y;
  int use_curve0 = (BN_cmp(uraw, params->n0) < 0);
  const EC_GROUP *ca;
  const EC_POINT *ga;
  const EC_POINT *pa;
  EC_POINT *q = 0, *r = 0;
  size_t mlen = params->msgsize;
  int rv;

  BN_init(&u);
  BN_init(&x);
  BN_init(&y);

  if (use_curve0) {
    ca = params->c0;
    ga = params->g0;
    pa = p0;
    FAILZ(BN_copy(&u, uraw));
  } else {
    ca = params->c1;
    ga = params->g1;
    pa = p1;
    FAILZ(BN_sub(&u, uraw, params->n0));
    FAILZ(BN_add(&u, &u, BN_value_one()));
  }

  FAILZ(q = EC_POINT_new(ca));
  FAILZ(r = EC_POINT_new(ca));
  FAILZ(EC_POINT_mul(ca, q, 0, ga, &u, params->ctx));
  FAILZ(EC_POINT_mul(ca, r, 0, pa, &u, params->ctx));

  FAILZ(EC_POINT_get_affine_coordinates_GF2m(ca, q, &x, &y, params->ctx));
  if (bn2bin_padhi(&x, message, mlen) != mlen)
    goto fail;
  if (message[0] & (params->pad_mask|params->curve_bit)) /* see below */
    goto fail;
  memcpy(secret, message, mlen);

  FAILZ(EC_POINT_get_affine_coordinates_GF2m(ca, r, &x, &y, params->ctx));
  if (bn2bin_padhi(&x, secret + mlen, mlen) != mlen)
    goto fail;

  /* K high bits of the message will be zero.  Fill in the high K-1
     of them with random bits from the pad, and use the lowest bit
     to identify the curve in use.  That bit will have a bias on the
     order of 2^{-d/2} where d is the bit-degree of the curve; 2^{-81}
     for the only curve presently implemented.  This is acceptably
     small since an elliptic curve of d bits gives only about d/2 bits
     of security anyway, and is much better than allowing a timing
     attack via the recipient having to attempt point decompression
     twice for curve 1 but only once for curve 0 (or, alternatively,
     doubling the time required for all decryptions).  */

  pad &= params->pad_mask;
  pad |= (use_curve0 ? 0 : params->curve_bit);
  message[0] |= pad;

  rv = 0;
 done:
  BN_clear(&u);
  BN_clear(&x);
  BN_clear(&y);
  if (q) EC_POINT_clear_free(q);
  if (r) EC_POINT_clear_free(r);
  return rv;

 fail:
  log_crypto_warn("MKEM::generate");
  memset(message, 0, mlen);
  memset(secret, 0, mlen * 2);
  rv = -1;
  goto done;
}

int
MKEM::decode(uint8_t *secret, const uint8_t *message) const
{
  int use_curve0 = !(message[0] & params->curve_bit);
  const EC_GROUP *ca = use_curve0 ? params->c0 : params->c1;
  const BIGNUM *sa = use_curve0 ? s0 : s1;
  EC_POINT *q = 0, *r = 0;
  uint8_t *unpadded = 0;
  BIGNUM x, y;
  size_t mlen = params->msgsize;
  int rv;

  if (!s0 || !s1) /* secret key not available */
    return -1;

  BN_init(&x);
  BN_init(&y);
  FAILZ(q = EC_POINT_new(ca));
  FAILZ(r = EC_POINT_new(ca));
  FAILZ(unpadded = (uint8_t *)xmalloc(mlen + 1));

  /* Copy the message, erase the padding bits, and put an 0x02 byte on
     the front so we can use EC_POINT_oct2point to recover the
     y-coordinate. */
  unpadded[0] = 0x02;
  unpadded[1] = (message[0] & ~(params->pad_mask|params->curve_bit));
  memcpy(&unpadded[2], &message[1], mlen - 1);

  FAILZ(EC_POINT_oct2point(ca, q, unpadded, mlen + 1,
                           params->ctx));
  FAILZ(EC_POINT_mul(ca, r, 0, q, sa, params->ctx));

  FAILZ(EC_POINT_get_affine_coordinates_GF2m(ca, q, &x, &y, params->ctx));
  if (bn2bin_padhi(&x, secret, mlen) != mlen)
    goto fail;

  FAILZ(EC_POINT_get_affine_coordinates_GF2m(ca, r, &x, &y, params->ctx));
  if (bn2bin_padhi(&x, secret + mlen, mlen) != mlen)
    goto fail;

  rv = 0;
 done:
  if (unpadded) {
    memset(unpadded, 0, mlen + 1);
    free(unpadded);
  }
  if (q) EC_POINT_clear_free(q);
  if (r) EC_POINT_clear_free(r);
  BN_clear(&x);
  BN_clear(&y);
  return rv;

 fail:
  log_crypto_warn("MKEM::decode");
  rv = -1;
  memset(secret, 0, mlen * 2);
  goto done;
}
