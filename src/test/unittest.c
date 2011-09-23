/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "unittest.h"

#include "crypt.h"
#include "connections.h"
#include "protocol.h"

#include <event2/event.h>
#include <event2/bufferevent.h>

#include <openssl/rand.h>

/* Predictable RAND_* implementation, for tests that encrypt stuff and
   check what winds up on the wire.

   USE OF THIS RNG DEFEATS SECURITY, BECAUSE THE SEED IS FIXED AND THE
   ALGORITHM IS NOT CRYPTOGRAPHICALLY SOUND.
   It should ONLY be used for unit testing.

   Algorithm from http://www.iro.umontreal.ca/~lecuyer/myftp/papers/tausme.ps
   OpenSSL glue from http://stackoverflow.com/questions/7437177/
   Fixed seed from RFC 3526 (a convenient source of arbitrary constants).

   XXX Theoretically this should be using ENGINEs instead of RAND_METHODs,
   but the OpenSSL documentation on how to write an ENGINE is ... inadequate.
*/

struct taus_state
{
  uint32_t s1, s2, s3;
};

static struct taus_state ut_state;
static const struct taus_state ut_state0 = {
  0xC90FDAA2, 0x2168C234, 0xC4C6628B
};

static void ut_rand_seed(const void *buf, int num)
{
  memcpy(&ut_state, &ut_state0, sizeof(struct taus_state));
}

static uint32_t taus88(struct taus_state *s)
{
  s->s1 = ((s->s1 & 0xFFFFFFFEu) << 12) ^ (((s->s1 << 13) ^ s->s1) >> 19);
  s->s2 = ((s->s2 & 0xFFFFFFF8u) <<  4) ^ (((s->s2 <<  2) ^ s->s2) >> 25);
  s->s3 = ((s->s3 & 0xFFFFFFF0u) << 17) ^ (((s->s3 <<  3) ^ s->s3) >> 11);

  return s->s1 ^ s->s2 ^ s->s3;
}

static int ut_rand_bytes(unsigned char *buf, int num)
{
  int i = 0;
  uint32_t x;
  /* if we haven't been seeded yet, do it now */
  if (ut_state.s1 == 0 && ut_state.s2 == 0 && ut_state.s3 == 0)
    ut_rand_seed(NULL, 0);

  for (;;) {
    x = taus88(&ut_state);
    buf[i] = x & 0xFF; x >>= 8; i++;
    if (i >= num) break;
    buf[i] = x & 0xFF; x >>= 8; i++;
    if (i >= num) break;
    buf[i] = x & 0xFF; x >>= 8; i++;
    if (i >= num) break;
    buf[i] = x & 0xFF; x >>= 8; i++;
    if (i >= num) break;
  }
  return 1;
}

static const RAND_METHOD ut_rng = {
  ut_rand_seed, ut_rand_bytes, NULL, NULL, NULL, NULL
};

static const RAND_METHOD *prev_rng;

void
ut_enable_predictable_rng(void)
{
  char dummy;
  prev_rng = RAND_get_rand_method();
  RAND_set_rand_method(&ut_rng);
  RAND_seed(&dummy, 1);
}

void
ut_disable_predictable_rng(void)
{
  RAND_set_rand_method(prev_rng);
}

/* Generic test fixture for protocol tests (currently used by obfs2
   and transfer). */

static void *
setup_proto_test_state(const struct testcase_t *tcase)
{
  struct proto_test_state *s = xzalloc(sizeof(struct proto_test_state));
  const struct proto_test_args *args = tcase->setup_data;

  s->args = args;
  s->base = event_base_new();

  ut_enable_predictable_rng();

  struct bufferevent *pairs[3][2];
  int i;
  for (i = 0; i < 3; i++) {
    bufferevent_pair_new(s->base, 0, pairs[i]);
    bufferevent_enable(pairs[i][0], EV_READ|EV_WRITE);
    bufferevent_enable(pairs[i][1], EV_READ|EV_WRITE);
  }

  s->cfg_client = config_create(args->nopts_client, args->opts_client);
  s->cfg_server = config_create(args->nopts_server, args->opts_server);
  s->cfg_client->base = s->base;
  s->cfg_server->base = s->base;

  s->conn_client = conn_create(s->cfg_client, pairs[0][0],
                               xstrdup("to-server"));
  s->conn_server = conn_create(s->cfg_server, pairs[0][1],
                               xstrdup("to-client"));

  s->buf_client = pairs[1][0];
  s->buf_server = pairs[2][0];

  s->ckt_client = circuit_create(s->cfg_client);
  s->ckt_server = circuit_create(s->cfg_server);

  circuit_add_upstream(s->ckt_client, pairs[1][1],
                       xstrdup("to-harness-client"));
  circuit_add_upstream(s->ckt_server, pairs[2][1],
                       xstrdup("to-harness-server"));

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

  ut_disable_predictable_rng();

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
  rv = tinytest_main(argc, argv, unittest_groups);
  conn_start_shutdown(1);
  cleanup_crypto();

  return rv;
}
