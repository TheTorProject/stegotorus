/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "unittest.h"
#include "main.h"

#include "crypt.h"
#include "connections.h"
#include "protocol.h"

#include <event2/event.h>
#include <event2/bufferevent.h>

/* Generic test fixture for protocol tests (currently used by transfer). */

static void *
setup_proto_test_state(const struct testcase_t *tcase)
{
  struct proto_test_state *s =
    (struct proto_test_state *)xzalloc(sizeof(struct proto_test_state));
  const struct proto_test_args *args =
    (struct proto_test_args *)tcase->setup_data;
  struct bufferevent *pairs[3][2];
  int i;

  s->args = args;
  s->base = event_base_new();

  for (i = 0; i < 3; i++) {
    bufferevent_pair_new(s->base, 0, pairs[i]);
    bufferevent_enable(pairs[i][0], EV_READ|EV_WRITE);
    bufferevent_enable(pairs[i][1], EV_READ|EV_WRITE);
  }

  s->cfg_client = config_create(args->nopts_client, args->opts_client);
  s->cfg_server = config_create(args->nopts_server, args->opts_server);
  s->cfg_client->base = s->base;
  s->cfg_server->base = s->base;

  s->conn_client = conn_create(s->cfg_client, 0, pairs[0][0],
                               xstrdup("to-server"));
  s->conn_server = conn_create(s->cfg_server, 0, pairs[0][1],
                               xstrdup("to-client"));

  s->buf_client = pairs[1][0];
  s->buf_server = pairs[2][0];

  s->ckt_client = circuit_create(s->cfg_client, 0);
  s->ckt_server = circuit_create(s->cfg_server, 0);

  circuit_add_upstream(s->ckt_client, pairs[1][1],
                       xstrdup("to-harness-client"));
  circuit_add_upstream(s->ckt_server, pairs[2][1],
                       xstrdup("to-harness-server"));

  s->ckt_client->add_downstream(s->conn_client);
  s->ckt_server->add_downstream(s->conn_server);

  return s;
}

static int
cleanup_proto_test_state(const struct testcase_t *, void *state)
{
  struct proto_test_state *s = (struct proto_test_state *)state;

  /* We don't want to trigger circuit_*_shutdown, so dissociate the circuits
     from their connections and close each separately. */
  s->ckt_client->drop_downstream(s->conn_client);
  s->ckt_server->drop_downstream(s->conn_server);

  delete s->conn_client;
  delete s->conn_server;

  delete s->cfg_client;
  delete s->cfg_server;

  bufferevent_free(s->buf_client);
  bufferevent_free(s->buf_server);
  event_base_free(s->base);

  free(state);
  return 1;
}

const struct testcase_setup_t proto_test_fixture =
  { setup_proto_test_state, cleanup_proto_test_state };

void
finish_shutdown(void)
{
}

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

  /* Ugly method to fix a Windows problem:
     http://archives.seul.org/libevent/users/Oct-2010/msg00049.html */
#ifdef _WIN32
  {
    WSADATA wsaData;
    WSAStartup(0x101, &wsaData);
  }
#endif

  rv = tinytest_main(argc, argv, unittest_groups);
  conn_start_shutdown(1);

  return rv;
}
