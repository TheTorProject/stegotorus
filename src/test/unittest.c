
#include <stdlib.h>

#include "tinytest.h"
#include "../crypt.h"

extern struct testcase_t crypt_tests[];
extern struct testcase_t protocol_tests[];


struct testgroup_t groups[] = {
  { "crypt/", crypt_tests },
  { "proto/", protocol_tests },
  END_OF_GROUPS
};

int
main(int argc, const char **argv)
{
  initialize_crypto();
  return tinytest_main(argc, argv, groups);
}
