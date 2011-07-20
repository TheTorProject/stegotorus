/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "../util.h"
#include "../protocol.h"
#include "tinytest_macros.h"

#include <event2/buffer.h>

static void
test_dummy_option_parsing(void *unused)
{
  struct option_parsing_case {
    struct protocol_params_t *result;
    short should_succeed;
    short n_opts;
    const char *const opts[4];
  };
  static struct option_parsing_case cases[] = {
    /* wrong number of options */
    { 0, 0, 1, {"dummy"} },
    { 0, 0, 2, {"dummy", "client"} },
    { 0, 0, 4, {"dummy", "client", "127.0.0.1:5552", "oops"} },
    { 0, 0, 4, {"dummy", "--frobozz", "client", "127.0.0.1:5552"} },
    /* unrecognized mode */
    { 0, 0, 3, {"dummy", "floodcontrol", "127.0.0.1:5552" } },
    /* bad address */
    { 0, 0, 3, {"dummy", "client", "@:5552"} },
    { 0, 0, 3, {"dummy", "client", "127.0.0.1:notanumber"} },
    /* should succeed */
    { 0, 1, 3, {"dummy", "client", "127.0.0.1:5552" } },
    { 0, 1, 3, {"dummy", "client", "127.0.0.1" } },
    { 0, 1, 3, {"dummy", "server", "127.0.0.1:5552" } },
    { 0, 1, 3, {"dummy", "socks", "127.0.0.1:5552" } },

    { 0, 0, 0, {0} }
  };

  /* Suppress logs for the duration of this function. */
  log_set_method(LOG_METHOD_NULL, NULL);

  struct option_parsing_case *c;
  for (c = cases; c->n_opts; c++) {
    c->result = proto_params_init(c->n_opts, c->opts);
    if (c->should_succeed)
      tt_ptr_op(c->result, !=, NULL);
    else
      tt_ptr_op(c->result, ==, NULL);
  }

 end:
  for (c = cases; c->n_opts; c++)
    if (c->result)
      proto_params_free(c->result);

  /* Unsuspend logging */
  log_set_method(LOG_METHOD_STDOUT, NULL);
}

/* All the tests below use this test environment: */
struct test_dummy_state
{
  struct protocol_params_t *proto_params_client;
  struct protocol_params_t *proto_params_server;
  struct protocol_t *client_proto;
  struct protocol_t *server_proto;
  struct evbuffer *output_buffer;
  struct evbuffer *dummy_buffer;
};

static int
cleanup_dummy_state(const struct testcase_t *unused, void *state)
{
  struct test_dummy_state *s = (struct test_dummy_state *)state;

  if (s->client_proto)
      proto_destroy(s->client_proto);
  if (s->server_proto)
      proto_destroy(s->server_proto);

  if (s->proto_params_client)
    proto_params_free(s->proto_params_client);
  if (s->proto_params_server)
    proto_params_free(s->proto_params_server);

  if (s->output_buffer)
    evbuffer_free(s->output_buffer);
  if (s->dummy_buffer)
    evbuffer_free(s->dummy_buffer);

  free(state);
  return 1;
}

#define ALEN(x) (sizeof x/sizeof x[0])

static const char *const options_client[] =
  {"dummy", "socks", "127.0.0.1:1800"};

static const char *const options_server[] =
  {"dummy", "server", "127.0.0.1:1800"};

static void *
setup_dummy_state(const struct testcase_t *unused)
{
  struct test_dummy_state *s = xzalloc(sizeof(struct test_dummy_state));

  s->proto_params_client =
    proto_params_init(ALEN(options_client), options_client);
  tt_assert(s->proto_params_client);

  s->proto_params_server =
    proto_params_init(ALEN(options_server), options_server);
  tt_assert(s->proto_params_server);

  s->client_proto = proto_create(s->proto_params_client);
  tt_assert(s->client_proto);

  s->server_proto = proto_create(s->proto_params_server);
  tt_assert(s->server_proto);

  s->output_buffer = evbuffer_new();
  tt_assert(s->output_buffer);

  s->dummy_buffer = evbuffer_new();
  tt_assert(s->dummy_buffer);

  return s;

 end:
  cleanup_dummy_state(NULL, s);
  return NULL;
}

static const struct testcase_setup_t dummy_fixture =
  { setup_dummy_state, cleanup_dummy_state };

static void
test_dummy_transfer(void *state)
{
  struct test_dummy_state *s = (struct test_dummy_state *)state;
  int n;
  struct evbuffer_iovec v[2];

  /* Call the handshake method to satisfy the high-level contract,
     even though dummy doesn't use a handshake */
  tt_int_op(proto_handshake(s->client_proto, s->output_buffer), >=, 0);

  /* That should have put nothing into the output buffer */
  tt_int_op(evbuffer_get_length(s->output_buffer), ==, 0);

  /* Ditto on the server side */
  tt_int_op(proto_handshake(s->server_proto, s->output_buffer), >=, 0);
  tt_int_op(evbuffer_get_length(s->output_buffer), ==, 0);

  const char *msg1 = "this is a 54-byte message passed from client to server";
  const char *msg2 = "this is a 55-byte message passed from server to client!";

  /* client -> server */
  evbuffer_add(s->dummy_buffer, msg1, 54);
  proto_send(s->client_proto, s->dummy_buffer, s->output_buffer);

  tt_assert(RECV_GOOD == proto_recv(s->server_proto, s->output_buffer,
                                    s->dummy_buffer));

  n = evbuffer_peek(s->dummy_buffer, -1, NULL, &v[0], 2);
  tt_int_op(n, ==, 1); /* expect contiguous data */
  tt_int_op(0, ==, strncmp(msg1, v[0].iov_base, 54));

  /* emptying dummy_buffer before next test  */
  size_t buffer_len = evbuffer_get_length(s->dummy_buffer);
  tt_int_op(0, ==, evbuffer_drain(s->dummy_buffer, buffer_len));

  /* client <- server */
  evbuffer_add(s->dummy_buffer, msg2, 55);
  tt_int_op(0, <=, proto_send(s->server_proto, s->dummy_buffer,
                              s->output_buffer));

  tt_assert(RECV_GOOD == proto_recv(s->client_proto, s->output_buffer,
                                    s->dummy_buffer));

  n = evbuffer_peek(s->dummy_buffer, -1, NULL, &v[1], 2);
  tt_int_op(n, ==, 1); /* expect contiguous data */
  tt_int_op(0, ==, strncmp(msg2, v[1].iov_base, 55));

 end:;
}

#define T(name) \
  { #name, test_dummy_##name, 0, NULL, NULL }

#define TF(name) \
  { #name, test_dummy_##name, 0, &dummy_fixture, NULL }

struct testcase_t dummy_tests[] = {
  T(option_parsing),
  TF(transfer),
  END_OF_TESTCASES
};
