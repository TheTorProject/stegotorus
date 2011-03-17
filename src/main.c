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
#include "protocol.h"

#ifndef __GNUC__
#define __attribute__(x)
#endif

static void usage(void) __attribute__((noreturn));

static void
usage(void)
{
  fprintf(stderr,
    "Usage: obfsproxy {client/server/socks} listenaddr[:port] targetaddr:port\n"
    "  (Default listen port is 48988 for client; 23548 for socks; 11253 for server)\n"
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
  int is_client, is_socks = 0, mode;
  struct sockaddr_storage ss_listen, ss_target;
  struct sockaddr *sa_target=NULL;
  int sl_listen, sl_target=0;
  const char *defport;

  struct event_base *base;
  struct event *sigevent;
  listener_t *listener;

  /* XXXXX the interface is crap.  Fix that. XXXXX */
  if (argc < 3)
    usage();
  if (!strcmp(argv[1], "client")) {
    is_client = 1;
    defport = "48988"; /* bf5c */
    mode = LSN_SIMPLE_CLIENT;
  } else if (!strcmp(argv[1], "socks")) {
    is_client = 1;
    is_socks = 1;
    defport = "23548"; /* 5bf5 */
    mode = LSN_SOCKS_CLIENT;
  } else if (!strcmp(argv[1], "server")) {
    is_client = 0;
    defport = "11253"; /* 2bf5 */
    mode = LSN_SIMPLE_SERVER;
  } else {
    usage();
  }

  /* figure out what port(s) to listen on as client/server */
  if (resolve_address_port(argv[2], 1, 1, &ss_listen, &sl_listen, defport) < 0)
    usage();

  if (is_socks) {
    if (argc != 3)
      usage();
  } else {
    if (argc != 4)
      usage();

    /* figure out what place to connect to as a client/server. */
    /* XXXX when we add socks support, clients will not have a fixed "target"
     * XXXX address but will instead connect to a client-selected address. */
    if (resolve_address_port(argv[3], 1, 0, &ss_target, &sl_target, NULL) < 0)
      usage();
    sa_target = (struct sockaddr *)&ss_target;
  }

  /* Initialize libevent */
  base = event_base_new();
  if (base == NULL) {
    fprintf(stderr, "Can't initialize Libevent; failing\n");
    return 2;
  }

  if (is_socks && init_evdns_base(base) < 0) {
    fprintf(stderr, "Can't initialize evdns; failing\n");
    return 3;
  }

  /* Handle signals */
  signal(SIGPIPE, SIG_IGN);
  sigevent = evsignal_new(base, SIGINT, handle_signal_cb, (void*) base);

  /* start an evconnlistener on the appropriate port(s) */
  /* ASN We hardcode BRL_PROTOCOL for now. */
  listener = listener_new(base,
                          mode, BRL_PROTOCOL,
                          (struct sockaddr *)&ss_listen, sl_listen,
                          sa_target, sl_target,
                          NULL, 0);
  if (! listener) {
    printf("Couldn't create listener!\n");
    return 4;
  }

  /* run the event loop */
  event_base_dispatch(base);

  listener_free(listener);

  return 0;
}
