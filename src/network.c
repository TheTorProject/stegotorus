/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#define NETWORK_PRIVATE
#include "network.h"
#include "util.h"
#include "socks.h"
#include "protocol.h"
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
  int proto; /* Protocol that this listener can speak. */
  protocol_params_t *proto_params;
};

static void simple_listener_cb(struct evconnlistener *evcl,
   evutil_socket_t fd, struct sockaddr *sourceaddr, int socklen, void *arg);

static void conn_free(conn_t *conn);

static void close_conn_on_flush(struct bufferevent *bev, void *arg);
static void plaintext_read_cb(struct bufferevent *bev, void *arg);
static void socks_read_cb(struct bufferevent *bev, void *arg);
/* ASN Changed encrypted_read_cb() to obfuscated_read_cb(), it sounds
   a bit more obfsproxy generic. I still don't like it though. */
static void obfuscated_read_cb(struct bufferevent *bev, void *arg);
static void input_event_cb(struct bufferevent *bev, short what, void *arg);
static void output_event_cb(struct bufferevent *bev, short what, void *arg);

listener_t *
listener_new(struct event_base *base,
             int mode, int protocol,
             const struct sockaddr *on_address, int on_address_len,
             const struct sockaddr *target_address, int target_address_len,
             const char *shared_secret, size_t shared_secret_len)
{
  const unsigned flags =
    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE;
  listener_t *lsn = calloc(1, sizeof(listener_t));

  assert(mode == LSN_SIMPLE_CLIENT || mode == LSN_SIMPLE_SERVER ||
         mode == LSN_SOCKS_CLIENT);

  if (set_up_protocol(protocol)<0) {
    printf("This is just terrible. We can't even set up a protocol! Exiting.\n");
    exit(1);
  }

  lsn->proto = protocol;
  lsn->mode = mode;

  protocol_params_t *proto_params = calloc(1, sizeof(protocol_params_t));
  proto_params->is_initiator = mode != LSN_SIMPLE_SERVER;
  proto_params->shared_secret = shared_secret; 
  proto_params->shared_secret_len = shared_secret_len;

  lsn->proto_params = proto_params;

  if (target_address) {
    assert(target_address_len <= sizeof(struct sockaddr_storage));
    memcpy(&lsn->target_address, target_address, target_address_len);
    lsn->target_address_len = target_address_len;
  } else {
    assert(lsn->mode == LSN_SOCKS_CLIENT);
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

static void
protocol_params_free(protocol_params_t *params)
{
  assert(params);
  if (params->shared_secret)
    free(&params->shared_secret);
  free(params);
}

void
listener_free(listener_t *lsn)
{
  if (lsn->listener)
    evconnlistener_free(lsn->listener);
  if (lsn->proto_params)
    protocol_params_free(lsn->proto_params);
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

  conn->proto = proto_new(lsn->proto,
                          lsn->proto_params);
  if (!conn->proto) {
    printf("Creation of protocol object failed! Closing connection.\n");
    goto err;
  }

  if (conn->mode == LSN_SOCKS_CLIENT) {
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

  if (conn->mode == LSN_SIMPLE_SERVER) {
    bufferevent_setcb(conn->input,
                      obfuscated_read_cb, NULL, input_event_cb, conn);
  } else if (conn->mode == LSN_SIMPLE_CLIENT) {
    bufferevent_setcb(conn->input,
                      plaintext_read_cb, NULL, input_event_cb, conn);
  } else {
    assert(conn->mode == LSN_SOCKS_CLIENT);
    bufferevent_setcb(conn->input,
                      socks_read_cb, NULL, input_event_cb, conn);
  }

  bufferevent_enable(conn->input, EV_READ|EV_WRITE);

  /* New bufferevent to connect to the target address */
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
                      obfuscated_read_cb, NULL, output_event_cb, conn);

  /* Queue output right now. */
  struct bufferevent *encrypted =
    conn->mode == LSN_SIMPLE_SERVER ? conn->input : conn->output;

  /* ASN Will all protocols need to handshake here? Don't think so. */
  if (proto_handshake(conn->proto,
                      bufferevent_get_output(encrypted))<0)
    goto err;

  if (conn->mode == LSN_SIMPLE_SERVER || conn->mode == LSN_SIMPLE_CLIENT) {
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
  if (conn->proto)
    proto_destroy(conn->proto);
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
socks_read_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  //struct bufferevent *other;
  enum socks_ret socks_ret;
  assert(bev == conn->input); /* socks must be on the initial bufferevent */

  //dbg(("Got data on the socks side (%d) \n", conn->socks_state->state));

  do {
    enum socks_status_t status = socks_state_get_status(conn->socks_state);
    if (status == ST_SENT_REPLY) {
      /* We shouldn't be here. */
      assert(0);
    } else if (status == ST_HAVE_ADDR) {
      int af, r, port;
      const char *addr=NULL;
      r = socks_state_get_address(conn->socks_state, &af, &addr, &port);
      assert(r==0);
      r = bufferevent_socket_connect_hostname(conn->output,
                                              get_evdns_base(),
                                              af, addr, port);
      bufferevent_enable(conn->output, EV_READ|EV_WRITE);
      dbg(("socket_connect_hostname said %d! (%s,%d)\n", r, addr, port));

      if (r < 0) {
        /* XXXX send socks reply */
        conn_free(conn);
        return;
      }
      bufferevent_disable(conn->input, EV_READ|EV_WRITE);
      /* ignore data XXX */
      return;
    }

    socks_ret = handle_socks(bufferevent_get_input(bev),
                     bufferevent_get_output(bev), conn->socks_state);
  } while (socks_ret == SOCKS_GOOD);

  if (socks_ret == SOCKS_INCOMPLETE)
    return; /* need to read more data. */
  else if (socks_ret == SOCKS_BROKEN)
    conn_free(conn); /* XXXX maybe send socks reply */
  else if (socks_ret == SOCKS_CMD_NOT_CONNECT) {
    bufferevent_enable(bev, EV_WRITE);
    bufferevent_disable(bev, EV_READ);
    socks5_send_reply(bufferevent_get_output(bev), conn->socks_state,
                      SOCKS5_FAILED_UNSUPPORTED);
    bufferevent_setcb(bev, NULL,
                      close_conn_on_flush, output_event_cb, conn);
    return;
  }
}

static void
plaintext_read_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  struct bufferevent *other;
  other = (bev == conn->input) ? conn->output : conn->input;

  dbg(("Got data on plaintext side\n"));
  if (proto_send(conn->proto,
                 bufferevent_get_input(bev),
                 bufferevent_get_output(other)) < 0)
    conn_free(conn);
}

static void
obfuscated_read_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  struct bufferevent *other;
  other = (bev == conn->input) ? conn->output : conn->input;
  enum recv_ret r;

  dbg(("Got data on encrypted side\n"));
  r = proto_recv(conn->proto,
                 bufferevent_get_input(bev),
                 bufferevent_get_output(other));
  
  if (r == RECV_BAD)
    conn_free(conn);
  else if (r == RECV_SEND_PENDING)
    proto_send(conn->proto, 
               bufferevent_get_input(conn->input),
               bufferevent_get_output(conn->output));
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

  bufferevent_setcb(bev_flush, NULL,
                    close_conn_on_flush, output_event_cb, conn);
  bufferevent_enable(bev_flush, EV_WRITE);
}

static void
input_event_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = arg;
  assert(bev == conn->input);

  if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
    printf("Got error: %s\n",
           evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    error_or_eof(conn, bev, conn->output);
  }
  /* XXX we don't expect any other events */
}

static void
output_event_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = arg;
  assert(bev == conn->output);

  /**
     If we got the BEV_EVENT_ERROR flag *AND* we are in socks mode
     *AND* we are in the ST_HAVE_ADDR state, chances are that we
     failed connecting to the host requested by the CONNECT call. This
     means that we should send a negative SOCKS reply back to the
     client and terminate the connection.
  */
  if (what & BEV_EVENT_ERROR) {
    if ((conn->mode == LSN_SOCKS_CLIENT) && 
        (conn->socks_state) &&
        (socks_state_get_status(conn->socks_state) == ST_HAVE_ADDR)) {
      dbg(("Connection failed\n"));
      /* Enable EV_WRITE so that we can send the response.
         Disable EV_READ so that we don't get more stuff from the client. */
      bufferevent_enable(conn->input, EV_WRITE);
      bufferevent_disable(conn->input, EV_READ);
      socks_send_reply(conn->socks_state, bufferevent_get_output(conn->input),
                       evutil_socket_geterror(bufferevent_getfd(bev)));
      bufferevent_setcb(conn->input, NULL,
                        close_conn_on_flush, output_event_cb, conn);
      return;
    }
  }

  /**
     If the connection is terminating *OR* if we got a BEV_EVENT_ERROR
     but we don't match the case above, we most probably have to close
     this connection soon.
  */
  if (conn->flushing || (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR))) {
    printf("Got error: %s\n",
           evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    error_or_eof(conn, bev, conn->input);
    return;
  }

  /**
     If we got the BEV_EVENT_CONNECTED flag it means that a connection
     request was succesfull and normally that should have been off a
     CONNECT request by the SOCKS client. If that's the case we should
     send a happy response to the client and switch to start serving
     our pluggable transport protocol.
  */
  if (what & BEV_EVENT_CONNECTED) {
    /* woo, we're connected.  Now the input buffer can start reading. */
    conn->is_open = 1;
    dbg(("Connection done\n"));
    bufferevent_enable(conn->input, EV_READ|EV_WRITE);
    if (conn->mode == LSN_SOCKS_CLIENT) {
      struct sockaddr_storage ss;
      struct sockaddr *sa = (struct sockaddr*)&ss;
      socklen_t slen = sizeof(&ss);
      assert(conn->socks_state);
      if (getpeername(bufferevent_getfd(bev), sa, &slen) == 0) {
        /* Figure out where we actually connected to so that we can tell the
         * socks client */
        socks_state_set_address(conn->socks_state, sa);
      }
      socks_send_reply(conn->socks_state, 
                       bufferevent_get_output(conn->input), 0);
      /* we sent a socks reply.  We can finally move over to being a regular
         input bufferevent. */
      socks_state_free(conn->socks_state);
      conn->socks_state = NULL;
      bufferevent_setcb(conn->input,
                        plaintext_read_cb, NULL, input_event_cb, conn);
      if (evbuffer_get_length(bufferevent_get_input(conn->input)) != 0)
        obfuscated_read_cb(bev, conn->input);
    }
    return;
  }
  /* XXX we don't expect any other events */
}
