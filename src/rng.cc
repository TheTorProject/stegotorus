/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "rng.h"

#include <limits>
#include <math.h>
#include <cryptopp/osrng.h>

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
 *  in the range [0.0, 1.0).  Implementation tactic from "Common Lisp
 *  the Language, 2nd Edition", section 12.9.  Assumes IEEE754.
 */
static double
rng_double()
{
  union ieee754_double {
    double d;
    uint64_t i;
  };

  union ieee754_double n;

  /* This may waste up to 12 bits of randomness on each call,
     depending on how clever GenerateWord32 is internally; but the
     implementation is much simpler than if we used GenerateBlock. */
  try {
    rng_init();
    n.i = (0x3FF0000000000000ULL |
           (uint64_t(rng->GenerateWord32(0, 0x000FFFFFu)) << 32) |
           uint64_t(rng->GenerateWord32()));
  } CATCH_ALL_EXCEPTIONS(std::numeric_limits<double>::quiet_NaN());

  return n.d - 1.0;
}

/** Return a random integer in the range [0, hi), geometrically
 *  distributed over that range, with expected value 'xv'.
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

  /* Inverse transform sampling:
     T = (-ln U)/lambda; lambda=1/(xv-lo); therefore T = (xv-lo) * -ln(U).
     Minor wrinkle: rng_double() produces [0, 1) but we want (0, 1] to
     avoid hitting the undefined log(0).  This is what nextafter() is for. */

  double T = -log(nextafter(U, 2.0)) * xv;

  /* Technically we should rejection-sample here instead of clamping, but
     that would make this not a constant-time operation. */
  return std::min(hi-1, std::max(0U, (unsigned int)floor(T)));
}
