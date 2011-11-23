/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "rng.h"

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
