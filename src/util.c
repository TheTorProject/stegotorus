/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <event2/util.h>

int
resolve_address_port(const char *address,
                     int nodns, int passive,
                     struct sockaddr_storage *addr_out,
                     int *addrlen_out,
                     const char *default_port)
{
  struct evutil_addrinfo *ai = NULL;
  struct evutil_addrinfo ai_hints;
  int result = -1, ai_res;
  char *a = strdup(address), *cp;
  const char *portstr;
  if (!a)
    return -1;

  if ((cp = strchr(a, ':'))) {
    portstr = cp+1;
    cp = '\0';
  } else {
    portstr = default_port;
  }

  memset(&ai_hints, 0, sizeof(ai_hints));
  ai_hints.ai_family = AF_UNSPEC;
  ai_hints.ai_socktype = SOCK_STREAM;
  ai_hints.ai_flags = EVUTIL_AI_ADDRCONFIG | EVUTIL_AI_NUMERICSERV;
  if (passive)
    ai_hints.ai_flags |= EVUTIL_AI_PASSIVE;
  if (nodns)
    ai_hints.ai_flags |= EVUTIL_AI_NUMERICHOST;

  if ((ai_res = evutil_getaddrinfo(a, portstr, &ai_hints, &ai))) {
    fprintf(stderr, "Error resolving %s: %s\n",
            address, evutil_gai_strerror(ai_res));
    goto done;
  }
  if (ai == NULL) {
    fprintf(stderr, "No result for address %s\n", address);
    goto done;
  }
  if (ai->ai_addrlen > sizeof(struct sockaddr_storage)) {
    fprintf(stderr, "Result for address %s too long\n", address);
    goto done;
  }

  memcpy(addr_out, ai->ai_addr, ai->ai_addrlen);
  *addrlen_out = (int) ai->ai_addrlen;
  result = 0;

 done:
  free(a);
  if (ai)
    evutil_freeaddrinfo(ai);
  return result;
}
