
#include <stdio.h>

#include "tinytest.h"
#include "tinytest_macros.h"

#include "../crypt_protocol.h"

/* Make sure we can successfully set up a protocol state */
static void
test_proto_setup(void *data)
{
  protocol_state_t *proto1, *proto2;
  proto1 = protocol_state_new(1);
  proto2 = protocol_state_new(0);
  tt_assert(proto1);
  tt_assert(proto2);
 end:
  if (proto1)
    protocol_state_free(proto1);
  if (proto2)
    protocol_state_free(proto2);

}

#define T(name, flags) \
  { #name, test_proto_##name, (flags), NULL, NULL }

struct testcase_t protocol_tests[] = {
  T(setup, 0),
  END_OF_TESTCASES
};
