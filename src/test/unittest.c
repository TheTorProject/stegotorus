/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/
#include <stdlib.h>

#include "tinytest.h"
#include "../crypt.h"

extern struct testcase_t crypt_tests[];
extern struct testcase_t protocol_tests[];
extern struct testcase_t socks_tests[];

struct testgroup_t groups[] = {
  { "crypt/", crypt_tests },
  { "proto/", protocol_tests },
  { "socks/", socks_tests },
  END_OF_GROUPS
};

int
main(int argc, const char **argv)
{
  initialize_crypto();
  return tinytest_main(argc, argv, groups);
}
