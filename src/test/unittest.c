/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "crypt.h"
#include "connections.h"
#include "protocol.h"
#include "tinytest.h"
#include "unittest.h"

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <openssl/rand.h>

extern struct testcase_t container_tests[];
extern struct testcase_t crypt_tests[];
extern struct testcase_t socks_tests[];
extern struct testcase_t dummy_tests[];
extern struct testcase_t obfs2_tests[];
extern struct testcase_t transfer_tests[];

static const struct testgroup_t groups[] = {
  { "container/", container_tests },
  { "crypt/", crypt_tests },
  { "socks/", socks_tests },
  { "dummy/", dummy_tests },
  { "obfs2/", obfs2_tests },
  { "transfer/", transfer_tests },
  END_OF_GROUPS
};

static void *
setup_proto_test_state(const struct testcase_t *tcase)
{
  struct proto_test_state *s = xzalloc(sizeof(struct proto_test_state));
  const struct proto_test_args *args = tcase->setup_data;

  s->args = args;
  s->base = event_base_new();

  struct bufferevent *pairs[3][2];
  int i;
  for (i = 0; i < 3; i++) {
    bufferevent_pair_new(s->base, 0, pairs[i]);
    bufferevent_enable(pairs[i][0], EV_READ|EV_WRITE);
    bufferevent_enable(pairs[i][1], EV_READ|EV_WRITE);
  }

  s->cfg_client = config_create(args->nopts_client, args->opts_client);
  s->cfg_server = config_create(args->nopts_server, args->opts_server);

  s->conn_client = conn_create(s->cfg_client, pairs[0][0], xstrdup("to-server"));
  s->conn_server = conn_create(s->cfg_server, pairs[0][1], xstrdup("to-client"));

  s->buf_client = pairs[1][0];
  s->buf_server = pairs[2][0];

  s->ckt_client = circuit_create(s->cfg_client);
  s->ckt_server = circuit_create(s->cfg_server);

  circuit_add_upstream(s->ckt_client, pairs[1][1], xstrdup("to-harness-client"));
  circuit_add_upstream(s->ckt_server, pairs[2][1], xstrdup("to-harness-server"));

  circuit_add_downstream(s->ckt_client, s->conn_client);
  circuit_add_downstream(s->ckt_server, s->conn_server);

  return s;
}

static int
cleanup_proto_test_state(const struct testcase_t *tcase, void *state)
{
  struct proto_test_state *s = state;

  /* We don't want to trigger circuit_*_shutdown, so dissociate the circuits
     from their connections and close each separately. */
  s->ckt_client->downstream = NULL;
  s->ckt_server->downstream = NULL;
  s->conn_client->circuit = NULL;
  s->conn_server->circuit = NULL;

  conn_close(s->conn_client);
  conn_close(s->conn_server);

  circuit_close(s->ckt_client);
  circuit_close(s->ckt_server);

  config_free(s->cfg_client);
  config_free(s->cfg_server);

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
  if (logminsev)
    log_set_min_severity(logminsev);

  /* Ugly method to fix a Windows problem:
     http://archives.seul.org/libevent/users/Oct-2010/msg00049.html */
#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(0x101, &wsaData);
#endif

  initialize_crypto();
  conn_initialize();
  rv = tinytest_main(argc, argv, groups);
  conn_start_shutdown(1);
  cleanup_crypto();

  return rv;
}
