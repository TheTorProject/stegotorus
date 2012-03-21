/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "rng.h"

#include <limits>
#include <math.h>
#include <cryptopp/osrng.h>

/* not sure why, but on OSX we only see std::isnan, not ::isnan */
using std::isnan;

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

static CryptoPP::AutoSeededRandomPool *rng;

static void
rng_teardown()
{
  delete rng;
  rng = 0;
}

static void
rng_init()
{
  if (!rng) {
    rng = new CryptoPP::AutoSeededRandomPool;
    if (!rng)
      throw std::bad_alloc();
    atexit(rng_teardown);
  }
}

/**
   Fills 'buf' with 'buflen' random bytes and returns 0 on success.
   Returns -1 on failure.
*/
int
rng_bytes(uint8_t *buf, size_t buflen)
{
  try {
    rng_init();
    rng->GenerateBlock(buf, buflen);
    return 0;
  }
  CATCH_ALL_EXCEPTIONS(-1);
}


/** Return a pseudorandom integer, chosen uniformly from the values
 * between 0 and <b>max</b>-1 inclusive.  <b>max</b> must be between 1 and
 * INT_MAX+1, inclusive. */
int
rng_int(unsigned int max)
{
  log_assert(max <= ((unsigned int)INT_MAX)+1);
  log_assert(max > 0); /* don't div by 0 */

  try {
    rng_init();
    return rng->GenerateWord32(0, max-1);
  }
  CATCH_ALL_EXCEPTIONS(-1);
}

/** Return a pseudorandom integer, chosen uniformly from the values
 * between 'min' and 'max-1', inclusive.  'max' must be between
 * 'min+1' and 'INT_MAX+1', inclusive. */
int
rng_range(unsigned int min, unsigned int max)
{
  log_assert(max <= ((unsigned int)INT_MAX)+1);
  log_assert(max > min);

  try {
    rng_init();
    return rng->GenerateWord32(min, max-1);
  }
  CATCH_ALL_EXCEPTIONS(-1);
}

/** Internal use only (can be externalized if someone has a good use
 *  for it): generate a random double-precision floating-point number
 *  in the range (0.0, 1.0] (note that this is _not_ the usual convention,
 *  but it saves a call to nextafter() in the sole current user).
 *
 *  For what we use this for, it is important that we can, at least
 *  potentially, generate _every_ representable real number in the
 *  desired interval, with genuine uniformity.  The usual tactic of
 *  generating a random integer and dividing does not do this, because
 *  the rational numbers produced by random()/MAX are evenly spaced on
 *  the real line, but floating point numbers close to zero are *not*.
 *
 *  For the same reason, the trick for avoiding division suggested
 *  e.g. by "Common Lisp, the Language", generating a random number in
 *  [1.0, 2.0) by overwriting the mantissa of a 1.0 and then
 *  subtracting 1.0, does not help -- you can do the first step
 *  precisely because the representable binary floating point numbers
 *  between 1.0 and 2.0 *are* evenly spaced on the real line.
 *
 *  The more complicated, but correct, algorithm here was developed by
 *  Allen B. Downey: http://allendowney.com/research/rand/
 *
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
        bits = rng->GenerateByte();
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

  union ieee754_double {
    double d;
    uint64_t i;
  };

  try {
    rng_init();

    /* Because of how the Crypto++ RNG works, it is convenient to
       generate the mantissa first, contra Downey, and use the
       leftover bits to seed the bit-generator that we use for the
       exponent; this does not change the algorithm fundamentally,
       because only the final adjustment step depends on both. */

    uint64_t mantissa = rng->GenerateWord32();
    uint32_t b = rng->GenerateWord32();

    mantissa |= uint64_t(b & 0x000FFFFF) << 32;

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

    rngbit bits((b & 0xFFF00000) >> 20, 12);
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
  CATCH_ALL_EXCEPTIONS(std::numeric_limits<double>::quiet_NaN());
}

/** Return a random integer in the range [0, hi),
 *  from a truncated geometric distribution whose expected value
 *  (prior to truncation) is 'xv'.
 *  (The rate parameter 'lambda' that's usually used to characterize
 *  the geometric/exponential distribution is equal to 1/xv.)
 *  'hi' must be no more than INT_MAX+1, as for 'rng_range'.
 *  'xv' must be greater than 0 and less than 'hi'.
 */
int
rng_range_geom(unsigned int hi, unsigned int xv)
{
  log_assert(hi <= ((unsigned int)INT_MAX)+1);
  log_assert(0 < xv && xv < hi);

  double U = rng_double();
  if (isnan(U))
    return -1;

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
  return std::min(hi-1, std::max(0U, (unsigned int)floor(T)));
}
