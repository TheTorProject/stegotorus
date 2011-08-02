/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"

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

/**
  This struct defines the state of a listener on a particular address.
 */
typedef struct listener_t {
  config_t *cfg;
  struct evconnlistener *listener;
  char *address;
} listener_t;

/** All our listeners. */
static smartlist_t *listeners;

/** All active connections.  */
static smartlist_t *connections;

/** Flag toggled when obfsproxy is shutting down. It blocks new
    connections and shutdowns when the last connection is closed. */
static int shutting_down=0;

static void listener_free(listener_t *lsn);

static void listener_cb(struct evconnlistener *evcl, evutil_socket_t fd,
                        struct sockaddr *sourceaddr, int socklen,
                        void *closure);

static void simple_client_listener_cb(conn_t *conn, struct bufferevent *buf);
static void socks_client_listener_cb(conn_t *conn, struct bufferevent *buf);
static void simple_server_listener_cb(conn_t *conn, struct bufferevent *buf);

static void conn_free(conn_t *conn);
static void close_conn(conn_t *conn);
static void close_all_connections(void);

static void close_conn_on_flush(struct bufferevent *bev, void *arg);

static struct bufferevent *open_outbound_socket(conn_t *conn,
                                                struct event_base *base,
                                                bufferevent_data_cb readcb);

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
   This function opens listening sockets configured according to the
   provided 'config_t'.  Returns 1 on success, 0 on failure.
 */
int
open_listeners(struct event_base *base, config_t *cfg)
{
  const unsigned flags =
    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE;
  size_t i;
  listener_t *lsn;
  struct evutil_addrinfo *addrs;

  /* If we don't have a listener list, create one now. */
  if (!listeners)
    listeners = smartlist_create();

  for (i = 0; ; i++) {
    addrs = config_get_listen_addrs(cfg, i);
    if (!addrs) break;
    do {
      lsn = xzalloc(sizeof(listener_t));
      lsn->cfg = cfg;
      lsn->address = printable_address(addrs->ai_addr, addrs->ai_addrlen);
      lsn->listener =
        evconnlistener_new_bind(base, listener_cb, lsn, flags, -1,
                                addrs->ai_addr, addrs->ai_addrlen);

      if (!lsn->listener) {
        log_warn("Failed to open listening socket on %s: %s",
                 lsn->address,
                 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        listener_free(lsn);
        return 0;
      }

      smartlist_add(listeners, lsn);
      log_debug("Now listening on %s for protocol %s.",
                lsn->address, cfg->vtable->name);

      addrs = addrs->ai_next;
    } while (addrs);
  }

  return 1;
}

/**
   Deallocates listener_t 'lsn'.
*/
static void
listener_free(listener_t *lsn)
{
  if (lsn->listener)
    evconnlistener_free(lsn->listener);
  if (lsn->address)
    free(lsn->address);
  free(lsn);
}

/**
   Frees all active listeners.
*/
void
close_all_listeners(void)
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
   This function is called when any listener receives a connection.
 */
static void
listener_cb(struct evconnlistener *evcl, evutil_socket_t fd,
            struct sockaddr *peeraddr, int peerlen,
            void *closure)
{
  struct event_base *base = evconnlistener_get_base(evcl);
  listener_t *lsn = closure;
  char *peername = printable_address(peeraddr, peerlen);
  conn_t *conn = proto_conn_create(lsn->cfg);
  struct bufferevent *buf = bufferevent_socket_new(base, fd,
                                                   BEV_OPT_CLOSE_ON_FREE);

  if (!conn || !buf) {
    log_warn("%s: failed to set up new connection from %s.",
             lsn->address, peername);
    if (buf)
      bufferevent_free(buf);
    else
      evutil_closesocket(fd);
    if (conn)
      proto_conn_free(conn);
    free(peername);
    return;
  }

  if (!connections)
    connections = smartlist_create();
  smartlist_add(connections, conn);
  log_debug("%s: new connection from %s (%d total)", lsn->address, peername,
            smartlist_len(connections));

  conn->peername = peername;
  switch (conn->mode) {
  case LSN_SIMPLE_CLIENT: simple_client_listener_cb(conn, buf); break;
  case LSN_SOCKS_CLIENT:  socks_client_listener_cb(conn, buf);  break;
  case LSN_SIMPLE_SERVER: simple_server_listener_cb(conn, buf); break;
  default:
    obfs_abort();
  }
}

/**
   This function is called when an upstream client connects to us in
   simple client mode.
*/
static void
simple_client_listener_cb(conn_t *conn, struct bufferevent *buf)
{
  struct event_base *base = bufferevent_get_base(buf);
  obfs_assert(buf);
  obfs_assert(conn);
  obfs_assert(conn->mode == LSN_SIMPLE_CLIENT);
  log_debug("%s: simple client connection", conn->peername);

  conn->upstream = buf;
  bufferevent_setcb(conn->upstream, upstream_read_cb, NULL, error_cb, conn);

  /* Don't enable the upstream side for reading at this point; wait
     till the downstream side is established. */

  conn->downstream = open_outbound_socket(conn, base, downstream_read_cb);
  if (!conn->downstream) {
    close_conn(conn);
    return;
  }

  log_debug("%s: setup complete", conn->peername);
}

/**
   This function is called when an upstream client connects to us in
   socks mode.
*/
static void
socks_client_listener_cb(conn_t *conn, struct bufferevent *buf)
{
  obfs_assert(buf);
  obfs_assert(conn);
  obfs_assert(conn->mode == LSN_SOCKS_CLIENT);
  log_debug("%s: socks client connection", conn->peername);

  conn->upstream = buf;
  bufferevent_setcb(conn->upstream, socks_read_cb, NULL, error_cb, conn);
  bufferevent_enable(conn->upstream, EV_READ|EV_WRITE);

  /* Construct SOCKS state. */
  conn->socks_state = socks_state_new();

  /* Do not create a downstream bufferevent at this time; the socks
     handler will do it after it learns the downstream peer address. */

  log_debug("%s: setup complete", conn->peername);
}

/**
   This function is called when a remote client connects to us in
   server mode.
*/
static void
simple_server_listener_cb(conn_t *conn, struct bufferevent *buf)
{
  struct event_base *base = bufferevent_get_base(buf);
  obfs_assert(buf);
  obfs_assert(conn);
  obfs_assert(conn->mode == LSN_SIMPLE_SERVER);
  log_debug("%s: server connection", conn->peername);

  conn->downstream = buf;
  bufferevent_setcb(conn->downstream,
                    downstream_read_cb, NULL, error_cb, conn);

  /* Don't enable the downstream side for reading at this point; wait
     till the upstream side is established. */

  /* New bufferevent to connect to the target address. */
  conn->upstream = open_outbound_socket(conn, base, upstream_read_cb);
  if (!conn->upstream) {
    close_conn(conn);
    return;
  }

  log_debug("%s: setup complete", conn->peername);
}

/**
   Deallocates conn_t 'conn'.
*/
static void
conn_free(conn_t *conn)
{
  if (conn->peername)
    free(conn->peername);
  if (conn->socks_state)
    socks_state_free(conn->socks_state);
  if (conn->upstream)
    bufferevent_free(conn->upstream);
  if (conn->downstream)
    bufferevent_free(conn->downstream);

  proto_conn_free(conn);
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
  if (smartlist_len(connections) == 0 && shutting_down) {
    smartlist_free(connections);
    finish_shutdown();
  }
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
   Make the outbound socket for a connection.
*/
static struct bufferevent *
open_outbound_socket(conn_t *conn, struct event_base *base,
                     bufferevent_data_cb readcb)
{
  struct evutil_addrinfo *addr = config_get_target_addr(conn->cfg);
  struct bufferevent *buf;
  char *peername;

  if (!addr) {
    log_warn("%s: no target addresses available", conn->peername);
    return NULL;
  }

  buf = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("%s: unable to create outbound socket buffer", conn->peername);
    return NULL;
  }

  bufferevent_setcb(buf, readcb, NULL, pending_conn_cb, conn);

  do {
    peername = printable_address(addr->ai_addr, addr->ai_addrlen);
    log_info("%s (%s): trying to connect to %s",
             conn->peername, conn->cfg->vtable->name, peername);
    if (bufferevent_socket_connect(buf, addr->ai_addr, addr->ai_addrlen) >= 0) {
      /* success */
      bufferevent_enable(buf, EV_READ|EV_WRITE);
      free(peername);
      return buf;
    }
    log_info("%s: connection to %s failed: %s",
             conn->peername, peername,
             evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    free(peername);
    addr = addr->ai_next;
  } while (addr);

  log_warn("%s: all outbound connection attempts failed",
           conn->peername);

  bufferevent_free(buf);
  return NULL;
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
  log_debug("%s: %s, %lu bytes available", conn->peername, __func__,
            (unsigned long)evbuffer_get_length(bufferevent_get_input(bev)));
  obfs_assert(bev == conn->upstream);

  if (proto_send(conn,
                 bufferevent_get_input(conn->upstream),
                 bufferevent_get_output(conn->downstream)) < 0) {
    log_debug("%s: Error during transmit.", conn->peername);
    close_conn(conn);
  }
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
  log_debug("%s: %s, %lu bytes available", conn->peername, __func__,
            (unsigned long)evbuffer_get_length(bufferevent_get_input(bev)));
  obfs_assert(bev == conn->downstream);

  r = proto_recv(conn,
                 bufferevent_get_input(conn->downstream),
                 bufferevent_get_output(conn->upstream));

  if (r == RECV_BAD) {
    log_debug("%s: Error during receive.", conn->peername);
    close_conn(conn);
  } else if (r == RECV_SEND_PENDING) {
    log_debug("%s: Reply of %lu bytes", conn->peername,
              (unsigned long)
              evbuffer_get_length(bufferevent_get_input(conn->upstream)));
    if (proto_send(conn,
                   bufferevent_get_input(conn->upstream),
                   bufferevent_get_output(conn->downstream)) < 0) {
      log_debug("%s: Error during reply.", conn->peername);
      close_conn(conn);
    }
  }
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

  /* XXX Dirty access to bufferevent guts.  There appears to be no
     official API to retrieve the callback functions and/or change
     just one callback while leaving the others intact. */
  bufferevent_setcb(bev_flush, bev_flush->readcb,
                    close_conn_on_flush, flush_error_cb, conn);
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
  log_debug("%s: %s", conn->peername, __func__);

  if (bev == conn->upstream) other = conn->downstream;
  else if (bev == conn->downstream) other = conn->upstream;
  else obfs_abort();

  /* Upon successful connection, enable traffic on the other side,
     and replace this callback with the regular error_cb */
  if (what & BEV_EVENT_CONNECTED) {
    obfs_assert(!conn->flushing);

    conn->is_open = 1;
    log_debug("%s: Successful %s connection", conn->peername,
              bev == conn->upstream ? "upstream" : "downstream");

    /* Queue handshake, if any. */
    if (proto_handshake(conn,
                        bufferevent_get_output(conn->downstream))<0) {
      log_debug("%s: Error during handshake", conn->peername);
      close_conn(conn);
      return;
    }

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
  log_debug("%s: %s", conn->peername, __func__);
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
    log_debug("%s: Successful %s connection", conn->peername,
              bev == conn->upstream ? "upstream" : "downstream");

    bufferevent_setcb(conn->upstream,
                      upstream_read_cb, NULL, error_cb, conn);
    bufferevent_setcb(conn->downstream,
                      downstream_read_cb, NULL, error_cb, conn);
    bufferevent_enable(conn->upstream, EV_READ|EV_WRITE);

    /* Queue handshake, if any. */
    if (proto_handshake(conn,
                        bufferevent_get_output(conn->downstream))<0) {
      log_debug("%s: Error during handshake", conn->peername);
      close_conn(conn);
      return;
    }

    if (evbuffer_get_length(bufferevent_get_input(conn->upstream)) != 0)
      upstream_read_cb(conn->upstream, conn);
    return;
  }

  /* unknown event code */
  obfs_abort();
}
