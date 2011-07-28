/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"

#define NETWORK_PRIVATE
#include "network.h"

#include "container.h"
#include "main.h"
#include "socks.h"
#include "protocol.h"

#include <errno.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#include <event2/listener.h>

/* Terminology used in this file:

   A "side" is a bidirectional communications channel, usually backed
   by a network socket and represented at this layer by a
   'struct bufferevent'.

   A "connection" is a _pair_ of sides, referred to as the "upstream"
   side and the "downstream" side.  A connection is represented by a
   'conn_t'.  The upstream side of a connection communicates in
   cleartext with the higher-level program that wishes to make use of
   our obfuscation service.  The downstream side commmunicates in an
   obfuscated fashion with the remote peer that the higher-level
   client wishes to contact.

   A "listener" is a listening socket bound to a particular
   obfuscation protocol, represented in this layer by a 'listener_t'.
   Connecting to a listener creates one side of a connection, and
   causes this program to initiate the other side of the connection.
   A listener is said to be a "client" listener if connecting to it
   creates the _upstream_ side of a connection, and a "server"
   listener if connecting to it creates the _downstream_ side.

   There are two kinds of client listeners: a "simple" client listener
   always connects to the same remote peer every time it needs to
   initiate a downstream connection; a "socks" client listener can be
   told to connect to an arbitrary remote peer using the SOCKS protocol
   (version 4 or 5).
*/

/** All our listeners. */
static smartlist_t *listeners;

/** All active connections.  */
static smartlist_t *connections;

/** Flag toggled when obfsproxy is shutting down. It blocks new
    connections and shutdowns when the last connection is closed. */
static int shutting_down=0;

static void simple_client_listener_cb(struct evconnlistener *evcl,
   evutil_socket_t fd, struct sockaddr *sourceaddr, int socklen, void *arg);
static void socks_client_listener_cb(struct evconnlistener *evcl,
   evutil_socket_t fd, struct sockaddr *sourceaddr, int socklen, void *arg);
static void simple_server_listener_cb(struct evconnlistener *evcl,
   evutil_socket_t fd, struct sockaddr *sourceaddr, int socklen, void *arg);

static void conn_free(conn_t *conn);
static void close_all_connections(void);

static void close_conn_on_flush(struct bufferevent *bev, void *arg);

static void upstream_read_cb(struct bufferevent *bev, void *arg);
static void downstream_read_cb(struct bufferevent *bev, void *arg);
static void socks_read_cb(struct bufferevent *bev, void *arg);

static void error_cb(struct bufferevent *bev, short what, void *arg);
static void flush_error_cb(struct bufferevent *bev, short what, void *arg);
static void pending_conn_cb(struct bufferevent *bev, short what, void *arg);
static void pending_socks_cb(struct bufferevent *bev, short what, void *arg);

/**
   Puts obfsproxy's networking subsystem on "closing time" mode. This
   means that we stop accepting new connections and we shutdown when
   the last connection is closed.

   If 'barbaric' is set, we forcefully close all open connections and
   finish shutdown.

   (Only called by signal handlers)
*/
void
start_shutdown(int barbaric)
{
  log_debug("Beginning %s shutdown.", barbaric ? "barbaric" : "normal");

  if (!shutting_down)
    shutting_down=1;

  if (barbaric)
    close_all_connections();

  if (connections && smartlist_len(connections) == 0) {
    smartlist_free(connections);
    connections = NULL;
  }

  if (!connections)
    finish_shutdown();
}

/**
   Closes all open connections.
*/
static void
close_all_connections(void)
{
  if (!connections)
    return;
  log_debug("Closing all connections.");
  SMARTLIST_FOREACH(connections, conn_t *, conn,
                    { conn_free(conn); });
  smartlist_free(connections);
  connections = NULL;
}

/**
   This function spawns a listener configured according to the
   provided 'protocol_params_t' object'.  Returns 1 on success, 0 on
   failure.  (No, you can't have the listener object. It's private.)

   Regardless of success or failure, the protocol_params_t is consumed.
*/
int
create_listener(struct event_base *base, protocol_params_t *params)
{
  const unsigned flags =
    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE;
  evconnlistener_cb callback;
  listener_t *lsn = xzalloc(sizeof(listener_t));

  switch (params->mode) {
  case LSN_SIMPLE_CLIENT: callback = simple_client_listener_cb; break;
  case LSN_SIMPLE_SERVER: callback = simple_server_listener_cb; break;
  case LSN_SOCKS_CLIENT:  callback = socks_client_listener_cb;  break;
  default: obfs_abort();
  }

  lsn->address = printable_address(params->listen_addr->ai_addr,
                                   params->listen_addr->ai_addrlen);
  lsn->proto_params = params;
  lsn->listener =
    evconnlistener_new_bind(base, callback, lsn, flags, -1,
                            params->listen_addr->ai_addr,
                            params->listen_addr->ai_addrlen);

  if (!lsn->listener) {
    log_warn("Failed to create listener!");
    proto_params_free(params);
    free(lsn);
    return 0;
  }

  log_debug("Now listening on %s in mode %d, protocol %s.",
            lsn->address, params->mode, params->vtable->name);

  /* If we don't have a listener list, create one now. */
  if (!listeners)
    listeners = smartlist_create();
  smartlist_add(listeners, lsn);

  return 1;
}

/**
   Deallocates listener_t 'lsn'.
*/
static void
listener_free(listener_t *lsn)
{
  if (lsn->address)
    free(lsn->address);
  if (lsn->listener)
    evconnlistener_free(lsn->listener);
  if (lsn->proto_params)
    proto_params_free(lsn->proto_params);
  free(lsn);
}

/**
   Frees all active listeners.
*/
void
free_all_listeners(void)
{
  if (!listeners)
    return;
  log_info("Closing all listeners.");

  SMARTLIST_FOREACH(listeners, listener_t *, lsn,
                    { listener_free(lsn); });
  smartlist_free(listeners);
  listeners = NULL;
}

/**
   This function is called when an upstream client connects to us in
   simple client mode.
*/
static void
simple_client_listener_cb(struct evconnlistener *evcl,
                          evutil_socket_t fd, struct sockaddr *sourceaddr,
                          int socklen, void *arg)
{
  listener_t *lsn = arg;
  struct event_base *base;
  conn_t *conn = xzalloc(sizeof(conn_t));

  conn->peername = printable_address(sourceaddr, socklen);
  log_debug("%s: connection to %s from %s", __func__,
            lsn->address, conn->peername);

  conn->mode = lsn->proto_params->mode;
  obfs_assert(conn->mode == LSN_SIMPLE_CLIENT);

  conn->proto = proto_create(lsn->proto_params);
  if (!conn->proto) {
    log_warn("Creation of protocol object failed! Closing connection.");
    goto err;
  }

  /* New bufferevent to wrap socket we received. */
  base = evconnlistener_get_base(lsn->listener);
  conn->upstream = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
  if (!conn->upstream)
    goto err;
  fd = -1; /* prevent double-close */

  bufferevent_setcb(conn->upstream,
                    upstream_read_cb, NULL, error_cb, conn);

  /* Don't enable the upstream side for reading at this point; wait
     till the downstream side is established. */

  /* New bufferevent to connect to the target address */
  conn->downstream = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!conn->downstream)
    goto err;

  bufferevent_setcb(conn->downstream,
                    downstream_read_cb, NULL, pending_conn_cb, conn);

  /* Queue handshake, if any, before connecting. */
  if (proto_handshake(conn->proto,
                      bufferevent_get_output(conn->downstream))<0)
    goto err;

  /* Launch the connect attempt. */
  if (bufferevent_socket_connect(conn->downstream,
                                 lsn->proto_params->target_addr->ai_addr,
                                 lsn->proto_params->target_addr->ai_addrlen)<0)
    goto err;

  bufferevent_enable(conn->downstream, EV_READ|EV_WRITE);

  /* add conn to the connection list */
  if (!connections)
    connections = smartlist_create();
  smartlist_add(connections, conn);

  log_debug("%s: setup completed, %d connections",
            __func__, smartlist_len(connections));
  return;

 err:
  if (conn)
    conn_free(conn);
  if (fd >= 0)
    evutil_closesocket(fd);
}

/**
   This function is called when an upstream client connects to us in
   socks mode.
*/
static void
socks_client_listener_cb(struct evconnlistener *evcl,
                         evutil_socket_t fd, struct sockaddr *sourceaddr,
                         int socklen, void *arg)
{
  listener_t *lsn = arg;
  struct event_base *base;
  conn_t *conn = xzalloc(sizeof(conn_t));

  conn->peername = printable_address(sourceaddr, socklen);
  log_debug("%s: connection to %s from %s", __func__,
            lsn->address, conn->peername);

  conn->mode = lsn->proto_params->mode;
  obfs_assert(conn->mode == LSN_SOCKS_CLIENT);

  conn->proto = proto_create(lsn->proto_params);
  if (!conn->proto) {
    log_warn("Creation of protocol object failed! Closing connection.");
    goto err;
  }

  /* Construct SOCKS state. */
  conn->socks_state = socks_state_new();

  /* New bufferevent to wrap socket we received. */
  base = evconnlistener_get_base(lsn->listener);
  conn->upstream = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
  if (!conn->upstream)
    goto err;
  fd = -1; /* prevent double-close */

  bufferevent_setcb(conn->upstream, socks_read_cb, NULL, error_cb, conn);
  bufferevent_enable(conn->upstream, EV_READ|EV_WRITE);

  /* Do not create a downstream bufferevent at this time; the socks
     handler will do it after it learns the downstream peer address. */

  /* add conn to the connection list */
  if (!connections)
    connections = smartlist_create();
  smartlist_add(connections, conn);

  log_debug("%s: setup completed, %d connections",
            __func__, smartlist_len(connections));
  return;

 err:
  if (conn)
    conn_free(conn);
  if (fd >= 0)
    evutil_closesocket(fd);
}

/**
   This function is called when a remote client connects to us in
   server mode.
*/
static void
simple_server_listener_cb(struct evconnlistener *evcl,
                          evutil_socket_t fd, struct sockaddr *sourceaddr,
                          int socklen, void *arg)
{
  listener_t *lsn = arg;
  struct event_base *base;
  conn_t *conn = xzalloc(sizeof(conn_t));

  conn->peername = printable_address(sourceaddr, socklen);
  log_debug("%s: connection to %s from %s", __func__,
            lsn->address, conn->peername);

  conn->mode = lsn->proto_params->mode;
  obfs_assert(conn->mode == LSN_SIMPLE_SERVER);

  conn->proto = proto_create(lsn->proto_params);
  if (!conn->proto) {
    log_warn("Creation of protocol object failed! Closing connection.");
    goto err;
  }

  /* New bufferevent to wrap socket we received. */
  base = evconnlistener_get_base(lsn->listener);
  conn->downstream = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
  if (!conn->downstream)
    goto err;
  fd = -1; /* prevent double-close */

  bufferevent_setcb(conn->downstream,
                    downstream_read_cb, NULL, error_cb, conn);

  /* Don't enable the downstream side for reading at this point; wait
     till the upstream side is established. */

  /* New bufferevent to connect to the target address. */
  conn->upstream = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!conn->upstream)
    goto err;

  bufferevent_setcb(conn->upstream,
                    upstream_read_cb, NULL, pending_conn_cb, conn);

  /* Queue handshake, if any, before connecting. */
  if (proto_handshake(conn->proto,
                      bufferevent_get_output(conn->upstream))<0)
    goto err;

  /* Launch the connect attempt. */
  if (bufferevent_socket_connect(conn->upstream,
                                 lsn->proto_params->target_addr->ai_addr,
                                 lsn->proto_params->target_addr->ai_addrlen)<0)
    goto err;

  bufferevent_enable(conn->upstream, EV_READ|EV_WRITE);

  /* add conn to the connection list */
  if (!connections)
    connections = smartlist_create();
  smartlist_add(connections, conn);

  log_debug("%s: setup completed, %d connections",
            __func__, smartlist_len(connections));
  return;

 err:
  if (conn)
    conn_free(conn);
  if (fd >= 0)
    evutil_closesocket(fd);
}

/**
   Deallocates conn_t 'conn'.
*/
static void
conn_free(conn_t *conn)
{
  if (conn->peername)
    free(conn->peername);
  if (conn->proto)
    proto_destroy(conn->proto);
  if (conn->socks_state)
    socks_state_free(conn->socks_state);
  if (conn->upstream)
    bufferevent_free(conn->upstream);
  if (conn->downstream)
    bufferevent_free(conn->downstream);

  memset(conn, 0x99, sizeof(conn_t));
  free(conn);
}

/**
   Closes a fully open connection.
*/
static void
close_conn(conn_t *conn)
{
  obfs_assert(connections);
  log_debug("Closing connection from %s; %d remaining",
            conn->peername, smartlist_len(connections) - 1);

  smartlist_remove(connections, conn);
  conn_free(conn);

  /* If this was the last connection AND we are shutting down,
     finish shutdown. */
  if (smartlist_len(connections) == 0) {
    smartlist_free(connections);
    connections = NULL;
  }

  if (!connections && shutting_down)
    finish_shutdown();
}

/**
   Closes associated connection if the output evbuffer of 'bev' is
   empty.
*/
static void
close_conn_on_flush(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  log_debug("%s for %s", __func__, conn->peername);

  if (evbuffer_get_length(bufferevent_get_output(bev)) == 0)
    close_conn(conn);
}

/**
    This callback is responsible for handling SOCKS traffic.
*/
static void
socks_read_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  enum socks_ret socks_ret;
  log_debug("%s for %s", __func__, conn->peername);
  /* socks only makes sense on the upstream side */
  obfs_assert(bev == conn->upstream);

  do {
    enum socks_status_t status = socks_state_get_status(conn->socks_state);
    if (status == ST_SENT_REPLY) {
      /* We shouldn't be here. */
      obfs_abort();
    } else if (status == ST_HAVE_ADDR) {
      int af, r, port;
      const char *addr=NULL;
      r = socks_state_get_address(conn->socks_state, &af, &addr, &port);
      obfs_assert(r==0);
      conn->downstream =
        bufferevent_socket_new(bufferevent_get_base(conn->upstream),
                               -1, BEV_OPT_CLOSE_ON_FREE);

      bufferevent_setcb(conn->downstream,
                        downstream_read_cb, NULL, pending_socks_cb, conn);

      /* Queue handshake, if any, before connecting. */
      if (proto_handshake(conn->proto,
                          bufferevent_get_output(conn->downstream))<0) {
        /* XXXX send socks reply */
        close_conn(conn);
        return;
      }

      r = bufferevent_socket_connect_hostname(conn->downstream,
                                              get_evdns_base(),
                                              af, addr, port);
      bufferevent_enable(conn->downstream, EV_READ|EV_WRITE);
      log_debug("socket_connect_hostname said %d! (%s,%d)", r, addr, port);

      if (r < 0) {
        /* XXXX send socks reply */
        close_conn(conn);
        return;
      }
      /* further upstream data will be processed once the downstream
         side is established */
      bufferevent_disable(conn->upstream, EV_READ|EV_WRITE);
      return;
    }

    socks_ret = handle_socks(bufferevent_get_input(bev),
                             bufferevent_get_output(bev),
                             conn->socks_state);
  } while (socks_ret == SOCKS_GOOD);

  if (socks_ret == SOCKS_INCOMPLETE)
    return; /* need to read more data. */
  else if (socks_ret == SOCKS_BROKEN)
    close_conn(conn); /* XXXX send socks reply */
  else if (socks_ret == SOCKS_CMD_NOT_CONNECT) {
    bufferevent_enable(bev, EV_WRITE);
    bufferevent_disable(bev, EV_READ);
    socks5_send_reply(bufferevent_get_output(bev), conn->socks_state,
                      SOCKS5_FAILED_UNSUPPORTED);
    bufferevent_setcb(bev, NULL,
                      close_conn_on_flush, flush_error_cb, conn);
    return;
  }
}

/**
   This callback is responsible for handling "upstream" traffic --
   traffic coming in from the higher-level client or server that needs
   to be obfuscated and transmitted.
 */
static void
upstream_read_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  log_debug("%s for %s", __func__, conn->peername);
  obfs_assert(bev == conn->upstream);

  if (proto_send(conn->proto,
                 bufferevent_get_input(conn->upstream),
                 bufferevent_get_output(conn->downstream)) < 0)
    close_conn(conn);
}

/**
   This callback is responsible for handling "downstream" traffic --
   traffic coming in from our remote peer that needs to be deobfuscated
   and passed to the upstream client or server.
 */
static void
downstream_read_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  enum recv_ret r;
  log_debug("%s for %s", __func__, conn->peername);
  obfs_assert(bev == conn->downstream);

  r = proto_recv(conn->proto,
                 bufferevent_get_input(conn->downstream),
                 bufferevent_get_output(conn->upstream));

  if (r == RECV_BAD)
    close_conn(conn);
  else if (r == RECV_SEND_PENDING)
    proto_send(conn->proto,
               bufferevent_get_input(conn->upstream),
               bufferevent_get_output(conn->downstream));
}

/**
   Something broke one side of the connection, or we reached EOF.
   We prepare the connection to be closed ASAP.
 */
static void
error_or_eof(conn_t *conn, struct bufferevent *bev_err)
{
  struct bufferevent *bev_flush;
  log_debug("%s for %s", __func__, conn->peername);

  if (bev_err == conn->upstream) bev_flush = conn->downstream;
  else if (bev_err == conn->downstream) bev_flush = conn->upstream;
  else obfs_abort();

  if (conn->flushing || !conn->is_open ||
      evbuffer_get_length(bufferevent_get_output(bev_flush)) == 0) {
    close_conn(conn);
    return;
  }

  conn->flushing = 1;
  /* Stop reading and writing; wait for the other side to flush if it has
   * data. */
  bufferevent_disable(bev_err, EV_READ|EV_WRITE);
  bufferevent_setcb(bev_err, NULL, NULL, flush_error_cb, conn);

  bufferevent_disable(bev_flush, EV_READ);
  bufferevent_setcb(bev_flush, NULL,
                    close_conn_on_flush, flush_error_cb, conn);
  bufferevent_enable(bev_flush, EV_WRITE);
}

/**
   Called when an "event" happens on an already-connected socket.
   This can only be an error or EOF.
*/
static void
error_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = arg;
  int errcode = EVUTIL_SOCKET_ERROR();
  log_debug("%s for %s: what=%x err=%d", __func__, conn->peername,
            what, errcode);

  /* It should be impossible to get here with BEV_EVENT_CONNECTED. */
  obfs_assert(what & (BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT));
  obfs_assert(!(what & BEV_EVENT_CONNECTED));

  if (what & BEV_EVENT_ERROR) {
    /* If we get EAGAIN, EINTR, or EINPROGRESS here, something has
       gone horribly wrong. */
    obfs_assert(errcode != EAGAIN && errcode != EINTR &&
                errcode != EINPROGRESS);

    log_warn("Error on %s side of connection from %s: %s",
             bev == conn->upstream ? "upstream" : "downstream",
             conn->peername,
             evutil_socket_error_to_string(errcode));
  } else if (what & BEV_EVENT_EOF) {
    log_info("EOF on %s side of connection from %s",
             bev == conn->upstream ? "upstream" : "downstream",
             conn->peername);
  } else {
    obfs_assert(what & BEV_EVENT_TIMEOUT);
    log_info("Timeout on %s side of connection from %s",
             bev == conn->upstream ? "upstream" : "downstream",
             conn->peername);
  }
  error_or_eof(arg, bev);
}

/**
   Called when an event happens on a socket that's in the process of
   being flushed and closed.  As above, this can only be an error.
*/
static void
flush_error_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = arg;
  int errcode = EVUTIL_SOCKET_ERROR();
  log_debug("%s for %s: what=%x err=%d", __func__, conn->peername,
            what, errcode);

  /* It should be impossible to get here with BEV_EVENT_CONNECTED. */
  obfs_assert(what & (BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT));
  obfs_assert(!(what & BEV_EVENT_CONNECTED));

  obfs_assert(conn->flushing);

  log_warn("Error during flush of %s side of connection from %s: %s",
           bev == conn->upstream ? "upstream" : "downstream",
           conn->peername,
           evutil_socket_error_to_string(errcode));
  close_conn(conn);
  return;
}

/**
   Called when an event happens on a socket that's still waiting to
   be connected.  We expect to get BEV_EVENT_CONNECTED, which
   indicates that the connection is now open, but we might also get
   errors as above.
*/
static void
pending_conn_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = arg;
  struct bufferevent *other;
  log_debug("%s for %s", __func__, conn->peername);

  if (bev == conn->upstream) other = conn->downstream;
  else if (bev == conn->downstream) other = conn->upstream;
  else obfs_abort();

  /* Upon successful connection, enable traffic on the other side,
     and replace this callback with the regular error_cb */
  if (what & BEV_EVENT_CONNECTED) {
    obfs_assert(!conn->flushing);

    conn->is_open = 1;
    log_debug("Successful %s connection for %s",
              bev == conn->upstream ? "upstream" : "downstream",
              conn->peername);

    /* XXX Dirty access to bufferevent guts.  There appears to be no
       official API to retrieve the callback functions and/or change
       just one callback while leaving the others intact. */
    bufferevent_setcb(bev, bev->readcb, bev->writecb, error_cb, conn);
    bufferevent_enable(other, EV_READ|EV_WRITE);
    return;
  }

  /* Otherwise, must be an error */
  error_cb(bev, what, arg);
}

/**
   Called when an event happens on a socket in socks mode.
   Both connections and errors are possible; must generate
   appropriate socks messages on the upstream side.
 */
static void
pending_socks_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = arg;
  log_debug("%s for %s", __func__, conn->peername);
  obfs_assert(bev == conn->downstream);
  obfs_assert(conn->socks_state);

  /* If we got an error while in the ST_HAVE_ADDR state, chances are
     that we failed connecting to the host requested by the CONNECT
     call. This means that we should send a negative SOCKS reply back
     to the client and terminate the connection.
     XXX properly distinguish BEV_EVENT_EOF from BEV_EVENT_ERROR;
     errno isn't meaningful in that case...  */
  if ((what & (BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT))) {
    int err = EVUTIL_SOCKET_ERROR();
    log_warn("Connection error: %s",
             evutil_socket_error_to_string(err));
    if (socks_state_get_status(conn->socks_state) == ST_HAVE_ADDR) {
      socks_send_reply(conn->socks_state,
                       bufferevent_get_output(conn->upstream),
                       err);
    }
    error_or_eof(conn, bev);
    return;
  }

  /* Additional work to do for BEV_EVENT_CONNECTED: send a happy
     response to the client and switch to the actual obfuscated
     protocol handlers. */
  if (what & BEV_EVENT_CONNECTED) {
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr*)&ss;
    socklen_t slen = sizeof(&ss);

    obfs_assert(!conn->flushing);

    if (getpeername(bufferevent_getfd(bev), sa, &slen) == 0) {
      /* Figure out where we actually connected to so that we can tell the
       * socks client */
      socks_state_set_address(conn->socks_state, sa);
    }
    socks_send_reply(conn->socks_state,
                     bufferevent_get_output(conn->upstream), 0);

    /* Switch to regular upstream behavior. */
    socks_state_free(conn->socks_state);
    conn->socks_state = NULL;
    conn->is_open = 1;
    log_debug("Connection successful");

    bufferevent_setcb(conn->upstream,
                      upstream_read_cb, NULL, error_cb, conn);
    bufferevent_setcb(conn->downstream,
                      downstream_read_cb, NULL, error_cb, conn);
    bufferevent_enable(conn->upstream, EV_READ|EV_WRITE);
    if (evbuffer_get_length(bufferevent_get_input(conn->upstream)) != 0)
      upstream_read_cb(conn->upstream, conn);
    return;
  }

  /* unknown event code */
  obfs_abort();
}
