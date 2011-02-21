/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#define NETWORK_PRIVATE
#include "crypt_protocol.h"
#include "network.h"
#include "util.h"
#include "socks.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/event.h>

#include <errno.h>
#include <event2/util.h>

struct listener_t {
  struct evconnlistener *listener;
  struct sockaddr_storage target_address;
  int target_address_len;
  int mode;
  char shared_secret[SHARED_SECRET_LENGTH];
  unsigned int have_shared_secret : 1;
};

static void simple_listener_cb(struct evconnlistener *evcl,
   evutil_socket_t fd, struct sockaddr *sourceaddr, int socklen, void *arg);

static void conn_free(conn_t *conn);

static void close_conn_on_flush(struct bufferevent *bev, void *arg);
static void plaintext_read_cb(struct bufferevent *bev, void *arg);
static void socks_read_cb(struct bufferevent *bev, void *arg);
static void encrypted_read_cb(struct bufferevent *bev, void *arg);
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

  dbg(("Got a connection\n"));

  conn->mode = lsn->mode;
  
  if (conn->mode == LSN_SIMPLE_SERVER) {
    conn->proto_state = protocol_state_new(lsn->mode != LSN_SIMPLE_SERVER);
    if (!conn->proto_state)
      goto err;
  }

  if (conn->mode == LSN_SIMPLE_CLIENT) {  
    /* Construct SOCKS state. */
    conn->socks_state = socks_state_new();
    if (!conn->socks_state)
      goto err;
  }
  
  /* New bufferevent to wrap socket we received. */
  base = evconnlistener_get_base(lsn->listener);
  conn->input = bufferevent_socket_new(base,
                                       fd,
                                       BEV_OPT_CLOSE_ON_FREE);
  if (!conn->input)
    goto err;
  fd = -1; /* prevent double-close */

  if (conn->mode == LSN_SIMPLE_SERVER)
    bufferevent_setcb(conn->input,
                      encrypted_read_cb, NULL, input_event_cb, conn);
  else
    bufferevent_setcb(conn->input,
                      socks_read_cb, NULL, input_event_cb, conn);
  
  bufferevent_enable(conn->input, EV_READ|EV_WRITE);  

  conn->output = bufferevent_socket_new(base,
                                        -1,
                                        BEV_OPT_CLOSE_ON_FREE);
  if (!conn->output)
    goto err;
  
  if (conn->mode == LSN_SIMPLE_SERVER)
    bufferevent_setcb(conn->output,
                      plaintext_read_cb, NULL, output_event_cb, conn);
  else
    bufferevent_setcb(conn->output,
                      encrypted_read_cb, NULL, output_event_cb, conn);
    
  /* Queue output */
  if (conn->mode == LSN_SIMPLE_SERVER) {  
    if (proto_send_initial_message(conn->proto_state,
                                   bufferevent_get_output(conn->input))<0)
    goto err;
    
    /* Launch the connect attempt. */
    if (bufferevent_socket_connect(conn->output,
                                   (struct sockaddr *) &lsn->target_address,
                                   lsn->target_address_len)<0)
      goto err;
    
    bufferevent_enable(conn->output, EV_READ|EV_WRITE);
  }

  return;
 err:
  if (conn)
    conn_free(conn);
  if (fd >= 0)
    evutil_closesocket(fd);
}

static void
conn_free(conn_t *conn)
{
  if (conn->proto_state)
    protocol_state_free(conn->proto_state);
  if (conn->socks_state)
    socks_state_free(conn->socks_state);
  if (conn->input)
    bufferevent_free(conn->input);
  if (conn->output)
    bufferevent_free(conn->output);
  memset(conn, 0x99, sizeof(conn_t));
  free(conn);
}

static void
close_conn_on_flush(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;

  if (0 == evbuffer_get_length(bufferevent_get_output(bev)))
    conn_free(conn);
}

/** This is only used in the input bufferevent of clients. */
static void
socks_read_cb(struct bufferevent *bev, void *arg) {
  conn_t *conn = arg;
  struct bufferevent *other;
  other = (bev == conn->input) ? conn->output : conn->input;

  //dbg(("Got data on the socks side (%d) \n", conn->socks_state->state));
  
  if (bev == conn->input &&
      socks_state_get_status(conn->socks_state) != ST_OPEN) { /* SOCKS data */
    if (handle_socks(bufferevent_get_input(bev),
                     bufferevent_get_output(bev), conn->socks_state, conn) < 0)
      conn_free(conn);
  } else { /* pipe it over */
    assert(conn->proto_state);
    
    if (proto_send(conn->proto_state,
                   bufferevent_get_input(bev),
                   bufferevent_get_output(other)) < 0)
      conn_free(conn);
  }
}

int
set_up_protocol(conn_t *conn)
{
  /* Construct protocol state. */
  conn->proto_state = protocol_state_new(1);
  if (!conn->proto_state)
    return -1;
  
  /* Queue output */
  if (proto_send_initial_message(conn->proto_state,
                                 bufferevent_get_output(conn->output))<0)
    return -1;

  bufferevent_enable(conn->output, EV_READ|EV_WRITE);
  
  return 1;
}
  
  
static void
plaintext_read_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  struct bufferevent *other;
  other = (bev == conn->input) ? conn->output : conn->input;

  dbg(("Got data on plaintext side\n"));
  if (proto_send(conn->proto_state,
                 bufferevent_get_input(bev),
                 bufferevent_get_output(other)) < 0)
    conn_free(conn);
}

static void
encrypted_read_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  struct bufferevent *other;
  other = (bev == conn->input) ? conn->output : conn->input;

  dbg(("Got data on encrypted side\n"));
  if (proto_recv(conn->proto_state,
                 bufferevent_get_input(bev),
                 bufferevent_get_output(other)) < 0)
    conn_free(conn);
}

static void
error_or_eof(conn_t *conn,
             struct bufferevent *bev_err, struct bufferevent *bev_flush)
{
  dbg(("error_or_eof\n"));

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
    dbg(("Connection done\n"));
    bufferevent_enable(conn->input, EV_READ|EV_WRITE);
  }
  /* XXX we don't expect any other events */
}
