#include "stdlib.h"
#include "stdio.h"

#include "module.h"
#include "crypt_protocol.h"
#include "crypt.h"
#include "network.h"

/**
    This function returns a protocol_t structure based on the mode
    of obfsproxy
*/
struct protocol_t *
set_up_module(int protocol) {
  struct protocol_t *proto = calloc(1, sizeof(struct protocol_t));

  if (protocol == BRL_PROTOCOL) {
    proto->new = &new_brl;
    proto->new(proto);
    printf("Protocol constructed\n");

    if (initialize_crypto() < 0) {
      fprintf(stderr, "Can't initialize crypto; failing\n");
      return NULL;
    }
  }
  /* elif { other protocols } */

  return proto;
}

