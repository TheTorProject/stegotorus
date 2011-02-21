/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <event2/event.h>
#include "crypt.h"
#include "network.h"
#include "util.h"

#ifndef __GNUC__
#define __attribute__(x)
#endif

static void usage(void) __attribute__((noreturn));

static void
usage(void)
{
  fprintf(stderr,
    "Usage: obfsproxy {client/server} listenaddr[:port] targetaddr:port\n"
    "  (Default listen port is 48988 for client; 11253 for server)\n"
          );
  exit(1);
}

static void
handle_signal_cb(evutil_socket_t fd, short what, void *arg)
{
  struct event_base *base = arg;
  /* int signum = (int) fd; */

  event_base_loopexit(base, NULL);
}

int
main(int argc, const char **argv)
{
  int is_client;
  struct sockaddr_storage ss_listen, ss_target;
  int sl_listen, sl_target;
  const char *defport;

  struct event_base *base;
  struct event *sigevent;
  listener_t *listener;

  /* XXXXX the interface is crap.  Fix that. XXXXX */
  if (argc != 4)
    usage();
  if (!strcmp(argv[1], "client"))
    is_client = 1;
  else if (!strcmp(argv[1], "server"))
    is_client = 0;
  else
    usage();

  /* figure out what port(s) to listen on as client/server */
  defport = is_client ? "48988" : "11253";
  if (resolve_address_port(argv[2], 1, 1, &ss_listen, &sl_listen, defport) < 0)
    usage();

  /* figure out what place to connect to as a client/server. */
  /* XXXX when we add socks support, clients will not have a fixed "target"
   * XXXX address but will instead connect to a client-selected address. */
  if (resolve_address_port(argv[3], 1, 0, &ss_target, &sl_target, NULL) < 0)
    usage();

  /* Initialize crypto */
  if (initialize_crypto() < 0) {
    fprintf(stderr, "Can't initialize crypto; failing\n");
    return 2;
  }

  /* Initialize libevent */
  base = event_base_new();
  if (base == NULL) {
    fprintf(stderr, "Can't initialize Libevent; failing\n");
    return 2;
  }

  /* Handle signals */
  signal(SIGPIPE, SIG_IGN);
  sigevent = evsignal_new(base, SIGINT, handle_signal_cb, (void*) base);

  /* start an evconnlistener on the appropriate port(s) */
  listener = listener_new(base,
                          is_client ? LSN_SIMPLE_CLIENT : LSN_SIMPLE_SERVER,
                          (struct sockaddr *)&ss_listen, sl_listen,
                          (struct sockaddr *)&ss_target, sl_target,
                          NULL, 0);
  if (! listener) {
    printf("Couldn't create listener!\n");
    return 0;
  }

  /* run the event loop */
  event_base_dispatch(base);

  listener_free(listener);

  return 0;
}
