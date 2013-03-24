/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "rng.h"

#include <cmath>
#include <algorithm>

#include <openssl/rand.h>

/* OpenSSL's rng is global, automatically seeds itself, and does not
   appear to need to be torn down explicitly. */

/**
 * Fills 'buf' with 'buflen' random bytes.  Cannot fail.
 */
void
rng_bytes(uint8_t *buf, size_t buflen)
{
  log_assert(buflen < INT_MAX);
  int rv = RAND_bytes(buf, (int)buflen);
  log_assert(rv);
}

/**
 * Return a pseudorandom integer, chosen uniformly from the values
 * in the range [0, max). 'max' must be in the range [1, INT_MAX).
 */
int
rng_int(unsigned int max)
{
  log_assert(max > 0 && max <= ((unsigned int)INT_MAX)+1);

  /* rng_bytes will only give us a whole number of bytes, so to get a
     uniformly random number in [0, max) we need to rejection-sample.
     To minimize the number of rejections, we do the following: Find
     the least k ("nbits") such that 2**k >= max, and the least b
     ("nbytes") such that b*CHAR_BIT >= k.  Generate b random bytes,
     and rearrange them into an integer.  Mask off all but the least k
     bits.  Accept the result if it is less than max.  This way, the
     probability of accepting each candidate result is always greater
     than 0.5.  */

  unsigned int nbytes, nbits, mask, rv;
  unsigned char buf[sizeof(int)];

#if __GNUC__ >= 4
  nbits = CHAR_BIT*sizeof(int) - __builtin_clz(max);
#else
#error "Need fallback for __builtin_clz"
#endif
  nbytes = (nbits / CHAR_BIT) + 1;
  mask = (1U << nbits) - 1;

  for (;;) {
    rng_bytes(buf, nbytes);

    rv = 0;
    for (unsigned int i = 0; i < nbytes; i++)
      rv = (rv << CHAR_BIT) | buf[i];

    rv &= mask;

    if (rv < max)
      return rv;
  }
}

/**
 * Return a pseudorandom integer, chosen uniformly from the values
 * between 'min' and 'max-1', inclusive.  'max' must be between
 * 'min+1' and 'INT_MAX+1', inclusive.
 */
int
rng_range(unsigned int min, unsigned int max)
{
  log_assert(max <= ((unsigned int)INT_MAX)+1);
  log_assert(max > min);

  return min + rng_int(max - min);
}

/**
 * Internal use only (can be externalized if someone has a good use
 * for it): generate a random double-precision floating-point number
 * in the range (0.0, 1.0] (note that this is _not_ the usual convention,
 * but it saves a call to nextafter() in the sole current user).
 *
 * For what we use this for, it is important that we can, at least
 * potentially, generate _every_ representable real number in the
 * desired interval, with genuine uniformity.  The usual tactic of
 * generating a random integer and dividing does not do this, because
 * the rational numbers produced by random()/MAX are evenly spaced on
 * the real line, but floating point numbers close to zero are *not*.
 *
 * For the same reason, the trick for avoiding division suggested
 * e.g. by "Common Lisp, the Language", generating a random number in
 * [1.0, 2.0) by overwriting the mantissa of a 1.0 and then
 * subtracting 1.0, does not help -- you can do the first step
 * precisely because the representable binary floating point numbers
 * between 1.0 and 2.0 *are* evenly spaced on the real line.
 *
 * The more complicated, but correct, algorithm here was developed by
 * Allen B. Downey: http://allendowney.com/research/rand/
 */
static double
rng_double()
{
  class rngbit {
  public:
    rngbit(uint32_t bits, unsigned int n) : bits(bits), n(n) {}

    bool get()
    {
      if (n == 0) {
        rng_bytes((uint8_t *)&bits, 1);
        n = CHAR_BIT;
      }
      bool rv = bits & 1;
      bits >>= 1;
      n -= 1;
      return rv;
    }
  private:
    uint32_t bits;
    unsigned int n;
  };

  static_assert(sizeof(double) == sizeof(uint64_t),
                "this code works only with 64-bit, IEEE double");

  union ieee754_double {
    double d;
    uint64_t i;
  };

  /* It is convenient to generate the mantissa first, contra Downey,
     and use the leftover bits to seed the bit-generator that we use
     for the exponent; this does not change the algorithm
     fundamentally, because only the final adjustment step depends
     on both. */

  uint64_t mantissa = 0;
  rng_bytes((uint8_t *)&mantissa, sizeof(mantissa));

  rngbit bits(uint32_t(mantissa >> 52), 12);
  mantissa &= UINT64_C(0x000FFFFFFFFFFFFF);

  /* This is the core of Downey's algorithm: 50% of the time we
     should generate the highest exponent of a number in (0,1) (note
     that _neither_ endpoint is included right now).  25% of the
     time, we should generate the second highest exponent, 12.5% of
     the time, we should generate the third highest, and so on.  In
     other words, we should start with the highest exponent, flip a
     coin, and keep subtracting 1 until either we hit zero or the
     coin comes up heads.

     If anyone knows how to do this in _constant_ time, instead of
     variable time bounded by a constant, please tell me.
  */

  uint32_t exponent = 0x3FE; /* 1111111110 = 2^{-1} */
  do {
    if (bits.get()) break;
  } while (--exponent);

  /* Finally a slight adjustment: if the mantissa is zero, then
     half the time we should increment the exponent by one.
     Do this unconditionally if the exponent is also zero
     (so we never generate 0.0). */
  if (mantissa == 0 && (exponent == 0 || bits.get()))
    exponent++;

  /* Assemble and return the number. */
  union ieee754_double n;
  n.i = (uint64_t(exponent) << 52) | mantissa;
  return n.d;
}

/**
 * Return a random integer in the range [0, hi),
 * from a truncated geometric distribution whose expected value
 * (prior to truncation) is 'xv'.
 * (The rate parameter 'lambda' that's usually used to characterize
 * the geometric/exponential distribution is equal to 1/xv.)
 * 'hi' must be no more than INT_MAX+1, as for 'rng_range'.
 * 'xv' must be greater than 0 and less than 'hi'.
 */
int
rng_range_geom(unsigned int hi, unsigned int xv)
{
  using std::exp;
  using std::log;
  using std::floor;
  using std::min;
  using std::max;

  log_assert(hi <= ((unsigned int)INT_MAX)+1);
  log_assert(0 < xv);// && xv < hi); //the expected value is xv so if it's 
  //bigger than max, it does not seems to cause mathematical problem
  //as xv is the expected value for the untruncated variable. Refere to
  //the same http://math.stackexchange.com/questions/97733

  double U = rng_double();

  /* The exponential distribution with expected value
         xe = 1/log(1 + 1/xv)
     can be converted to the desired geometric distribution by
     floor(). See http://math.stackexchange.com/questions/97733 */
  double xe = 1./log(1. + 1./xv);

  /* To truncate in constant time, adjust U to be in the range
     ( e^{-hi/xe}, 1 ]. Doing this with arithmetic introduces
     a slight nonuniformity, but we really want to avoid rejection
     sampling here. */
  double ulo = exp(-double(hi)/xe);
  U = ulo + U * (1-ulo);

  /* Inverse transform sampling gives us a value for the exponential
     distribution with expected value 'xe'. */
  double T = -log(U) * xe;

  /* Round down for the geometric distribution, and clamp to [0, hi)
     for great defensiveness. */
  return min(hi-1, max(0U, (unsigned int)floor(T)));
}
