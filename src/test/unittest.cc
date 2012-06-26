/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "crypt.h"
#include "unittest.h"

int
main(int argc, const char **argv)
{
  int rv;
  char *logminsev;

  logminsev = getenv("TT_LOG");
  if (logminsev) {
    log_set_method(LOG_METHOD_STDERR, 0);
    log_set_min_severity(logminsev);
  } else {
    log_set_method(LOG_METHOD_NULL, 0);
  }

  init_crypto();

  rv = tinytest_main(argc, argv, unittest_groups);

  free_crypto();

  return rv;
}
