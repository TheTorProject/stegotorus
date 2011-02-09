#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tinytest.h"
#include "tinytest_macros.h"

#include "../crypt.h"

/* Test vectors for sha256 */
static void
test_crypt_hashvec(void *data)
{
  digest_t *d;
  uchar output[32];
  d = digest_new();
  digest_update(d, (unsigned char*)"", 0);
  digest_getdigest(d, output, 32);
  tt_int_op(0, ==, memcmp(output,
                          "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8"
                          "\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c"
                          "\xa4\x95\x99\x1b\x78\x52\xb8\x55", 32));
  /* XXX try more test vectors */
  /* XXX add a base16-decode function so we can implement a tt_mem_op or
     something */

 end:
  if (d)
    digest_free(d);
}

#define T(name, flags) \
  { #name, test_crypt_##name, (flags), NULL, NULL }

struct testcase_t crypt_tests[] = {
  T(hashvec, 0),
  END_OF_TESTCASES
};


