/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#include "crypt_protocol.h"
#include "network.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/event.h>

struct listener_t {
  struct evconnlistener *listener;
  struct sockaddr_storage target_address;
  int target_address_len;
  int mode;
  char shared_secret[SHARED_SECRET_LENGTH];
  unsigned int have_shared_secret : 1;
};

typedef struct conn_t {
  protocol_state_t *state;
  int mode;
  struct bufferevent *input;
  struct bufferevent *output;
  unsigned int flushing : 1;
  unsigned int is_open : 1;
} conn_t;


static void simple_listener_cb(struct evconnlistener *evcl,
   evutil_socket_t fd, struct sockaddr *sourceaddr, int socklen, void *arg);

static void conn_free(conn_t *conn);

static void close_conn_on_flush(struct bufferevent *bev, void *arg);
static void input_read_cb(struct bufferevent *bev, void *arg);
static void output_read_cb(struct bufferevent *bev, void *arg);
static void input_event_cb(struct bufferevent *bev, short what, void *arg);
static void output_event_cb(struct bufferevent *bev, short what, void *arg);

listener_t *
listener_new(struct event_base *base,
             int mode,
             const struct sockaddr *on_address, int on_address_len,
             const struct sockaddr *target_address, int target_address_len,
             const char *shared_secret, size_t shared_secret_len)
{
  const unsigned flags =
    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE;
  listener_t *lsn = calloc(1, sizeof(listener_t));

  /* (SOCKS not implemented yet) */
  assert(mode == LSN_SIMPLE_CLIENT || mode == LSN_SIMPLE_SERVER);
  lsn->mode = mode;

  if (target_address) {
    assert(target_address_len <= sizeof(struct sockaddr_storage));
    memcpy(&lsn->target_address, target_address, target_address_len);
    lsn->target_address_len = target_address_len;
  }
  assert(shared_secret == NULL || shared_secret_len == SHARED_SECRET_LENGTH);
  if (shared_secret) {
    memcpy(lsn->shared_secret, shared_secret, SHARED_SECRET_LENGTH);
    lsn->have_shared_secret = 1;
  }

  lsn->listener = evconnlistener_new_bind(base, simple_listener_cb, lsn,
                                          flags,
                                          -1,
                                          on_address,
                                          on_address_len);
  if (!lsn->listener) {
    listener_free(lsn);
    return NULL;
  }

  return lsn;
}

void
listener_free(listener_t *lsn)
{
  if (lsn->listener)
    evconnlistener_free(lsn->listener);
  memset(lsn, 0xb0, sizeof(listener_t));
  free(lsn);
}

static void
simple_listener_cb(struct evconnlistener *evcl,
    evutil_socket_t fd, struct sockaddr *sourceaddr, int socklen, void *arg)
{
  listener_t *lsn = arg;
  struct event_base *base;
  conn_t *conn = calloc(1, sizeof(conn_t));
  if (!conn)
    goto err;

  conn->mode = lsn->mode;

  /* Construct protocol state. */
  conn->state = protocol_state_new(lsn->mode != LSN_SIMPLE_SERVER);
  if (!conn->state)
    goto err;
  if (lsn->have_shared_secret) {
    protocol_state_set_shared_secret(conn->state,
                                     lsn->shared_secret,
                                     sizeof(lsn->shared_secret));
  }

  /* New bufferevent to wrap socket we received. */
  base = evconnlistener_get_base(lsn->listener);
  conn->input = bufferevent_socket_new(base,
                                       fd,
                                       BEV_OPT_CLOSE_ON_FREE);
  if (!conn->input)
    goto err;
  fd = -1; /* prevent double-close */

  bufferevent_setcb(conn->input,
                    input_read_cb, NULL, input_event_cb, conn);
  /* No reading or writing yet. */
  bufferevent_disable(conn->input, EV_READ|EV_WRITE);

  /* New bufferevent to connect to target address. */
  conn->output = bufferevent_socket_new(base,
                                        -1,
                                        BEV_OPT_CLOSE_ON_FREE);
  if (!conn->output)
    goto err;
  bufferevent_setcb(conn->output,
                    output_read_cb, NULL, output_event_cb, conn);

  /* Queue output */
  if (proto_send_initial_message(conn->state,
                                 bufferevent_get_output(conn->output))<0)
    goto err;

  /* Launch the connect attempt. */
  if (bufferevent_socket_connect(conn->output,
                                 (struct sockaddr *) &lsn->target_address,
                                 lsn->target_address_len)<0)
    goto err;
  bufferevent_enable(conn->output, EV_READ|EV_WRITE);

  return;
 err:
  if (conn)
    conn_free(conn);
  if (fd >= 0);
  evutil_closesocket(fd);
}

static void
conn_free(conn_t *conn)
{
  /*XXXX*/
}

static void
close_conn_on_flush(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;

  if (0 == evbuffer_get_length(bufferevent_get_output(bev)))
    conn_free(conn);
}

static void
input_read_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  assert(bev == conn->input);
  if (proto_send(conn->state,
                 bufferevent_get_input(conn->input),
                 bufferevent_get_output(conn->output)) < 0)
    conn_free(conn);
}
static void
output_read_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  assert(bev == conn->output);
  if (proto_recv(conn->state,
                 bufferevent_get_input(conn->output),
                 bufferevent_get_output(conn->input)) < 0)
    conn_free(conn);
}

static void
error_or_eof(conn_t *conn,
             struct bufferevent *bev_err, struct bufferevent *bev_flush)
{
  if (conn->flushing || ! conn->is_open ||
      0 == evbuffer_get_length(bufferevent_get_output(bev_flush))) {
    conn_free(conn);
    return;
  }

  conn->flushing = 1;
  /* Stop reading and writing; wait for the other side to flush if it has
   * data. */
  bufferevent_disable(bev_err, EV_READ|EV_WRITE);
  bufferevent_disable(bev_flush, EV_READ);

  bufferevent_setcb(conn->output, NULL,
                    close_conn_on_flush, output_event_cb, conn);
  bufferevent_enable(bev_flush, EV_WRITE);
}

static void
input_event_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = arg;
  assert(bev == conn->input);

  if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
    error_or_eof(conn, bev, conn->output);
  }
  /* XXX we don't expect any other events */
}

static void
output_event_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = arg;
  assert(bev == conn->output);

  if (conn->flushing || (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR))) {
    error_or_eof(conn, bev, conn->input);
    return;
  }
  if (what & BEV_EVENT_CONNECTED) {
    /* woo, we're connected.  Now the input buffer can start reading. */
    conn->is_open = 1;
    bufferevent_enable(conn->input, EV_READ|EV_WRITE);
  }
  /* XXX we don't expect any other events */
}
