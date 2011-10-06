/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "listener.h"

#include "connections.h"
#include "container.h"
#include "socks.h"
#include "protocol.h"

#include <errno.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

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

static void listener_close(listener_t *lsn);

static void client_listener_cb(struct evconnlistener *evcl, evutil_socket_t fd,
                               struct sockaddr *sourceaddr, int socklen,
                               void *closure);

static void server_listener_cb(struct evconnlistener *evcl, evutil_socket_t fd,
                               struct sockaddr *sourceaddr, int socklen,
                               void *closure);

static void upstream_read_cb(struct bufferevent *bev, void *arg);
static void downstream_read_cb(struct bufferevent *bev, void *arg);
static void socks_read_cb(struct bufferevent *bev, void *arg);

static void upstream_event_cb(struct bufferevent *bev, short what, void *arg);
static void downstream_event_cb(struct bufferevent *bev, short what, void *arg);


/**
   This function opens listening sockets configured according to the
   provided 'config_t'.  Returns 1 on success, 0 on failure.
 */
int
listener_open(struct event_base *base, config_t *cfg)
{
  const unsigned flags =
    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE;
  size_t i;
  listener_t *lsn;
  struct evutil_addrinfo *addrs;
  evconnlistener_cb callback =
    cfg->mode == LSN_SIMPLE_SERVER ? server_listener_cb
                                   : client_listener_cb;

  /* If we don't have a listener list, create one now. */
  if (!listeners)
    listeners = smartlist_create();

  /* We can now record the event_base to be used with this configuration. */
  cfg->base = base;

  /* Open listeners for every address in the configuration. */
  for (i = 0; ; i++) {
    addrs = config_get_listen_addrs(cfg, i);
    if (!addrs) break;
    do {
      lsn = xzalloc(sizeof(listener_t));
      lsn->cfg = cfg;
      lsn->address = printable_address(addrs->ai_addr, addrs->ai_addrlen);
      lsn->listener =
        evconnlistener_new_bind(base, callback, lsn, flags, -1,
                                addrs->ai_addr, addrs->ai_addrlen);

      if (!lsn->listener) {
        log_warn("Failed to open listening socket on %s: %s",
                 lsn->address,
                 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        listener_close(lsn);
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
   Closes and deallocates listener_t 'lsn'.
*/
static void
listener_close(listener_t *lsn)
{
  if (lsn->listener)
    evconnlistener_free(lsn->listener);
  if (lsn->address)
    free(lsn->address);
  free(lsn);
}

/**
   Closes and deallocates all active listeners.
*/
void
listener_close_all(void)
{
  if (!listeners)
    return;
  log_info("Closing all listeners.");

  SMARTLIST_FOREACH(listeners, listener_t *, lsn, listener_close(lsn));
  smartlist_free(listeners);
  listeners = NULL;
}

/**
   This function is called when a client-mode listener (simple or socks)
   receives a connection.
 */
static void
client_listener_cb(struct evconnlistener *evcl, evutil_socket_t fd,
                   struct sockaddr *peeraddr, int peerlen,
                   void *closure)
{
  listener_t *lsn = closure;
  char *peername = printable_address(peeraddr, peerlen);
  struct bufferevent *buf = NULL;
  circuit_t *ckt = NULL;
  int is_socks = lsn->cfg->mode == LSN_SOCKS_CLIENT;

  obfs_assert(lsn->cfg->mode != LSN_SIMPLE_SERVER);
  log_info("%s: new connection to %sclient from %s\n",
           lsn->address, is_socks ? "socks " : "", peername);

  buf = bufferevent_socket_new(lsn->cfg->base, fd, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("%s: failed to create buffer for new connection from %s",
             lsn->address, peername);
    evutil_closesocket(fd);
    free(peername);
    return;
  }

  ckt = circuit_create(lsn->cfg);
  if (!ckt) {
    log_warn("%s: failed to create circuit for new connection from %s",
             lsn->address, peername);
    bufferevent_free(buf);
    free(peername);
    return;
  }

  circuit_add_upstream(ckt, buf, peername);
  if (is_socks) {
    /* We can't do anything more till we know where to connect to. */
    bufferevent_enable(buf, EV_READ|EV_WRITE);
    bufferevent_setcb(buf, socks_read_cb, NULL, upstream_event_cb, ckt);
  } else {
    conn_t *down = conn_create_outbound(ckt);
    if (!down) {
      log_warn("%s: outbound connection failed", peername);
      circuit_close(ckt);
      return;
    }
    bufferevent_setcb(buf, upstream_read_cb, NULL, upstream_event_cb, ckt);
  }
}

/**
   This function is called when a server-mode listener receives a connection.
 */
static void
server_listener_cb(struct evconnlistener *evcl, evutil_socket_t fd,
                   struct sockaddr *peeraddr, int peerlen,
                   void *closure)
{
  listener_t *lsn = closure;
  char *peername = printable_address(peeraddr, peerlen);
  struct bufferevent *buf;
  conn_t *conn;

  obfs_assert(lsn->cfg->mode == LSN_SIMPLE_SERVER);
  log_info("%s: new connection to server from %s\n", lsn->address, peername);

  buf = bufferevent_socket_new(lsn->cfg->base, fd, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("%s: failed to create buffer for new connection from %s",
             lsn->address, peername);
    evutil_closesocket(fd);
    free(peername);
    return;
  }

  conn = conn_create(lsn->cfg, buf, peername);
  if (!conn) {
    log_warn("%s: failed to create connection structure for %s",
             lsn->address, peername);
    bufferevent_free(buf);
    free(peername);
    return;
  }

  /* If appropriate at this point, connect to upstream. */
  if (conn_maybe_open_upstream(conn) < 0) {
    log_debug("%s: Error opening upstream connection", conn->peername);
    conn_close(conn);
    return;
  }

  /* Queue handshake, if any. */
  if (conn_handshake(conn) < 0) {
    log_debug("%s: Error during handshake", conn->peername);
    conn_close(conn);
    return;
  }

  bufferevent_setcb(buf, downstream_read_cb, NULL, downstream_event_cb, conn);
  bufferevent_enable(conn->buffer, EV_READ|EV_WRITE);
}

/**
    This callback is responsible for handling SOCKS traffic.
*/
static void
socks_read_cb(struct bufferevent *bev, void *arg)
{
  circuit_t *ckt = arg;
  socks_state_t *socks;
  enum socks_ret socks_ret;

  log_debug("%s: %s", ckt->up_peer, __func__);
  obfs_assert(ckt->cfg->mode == LSN_SOCKS_CLIENT);
  obfs_assert(ckt->socks_state);
  socks = ckt->socks_state;

  do {
    enum socks_status_t status = socks_state_get_status(socks);
    obfs_assert(status != ST_SENT_REPLY); /* we shouldn't be here then */

    if (status == ST_HAVE_ADDR) {
      /* try to open the outbound connection */
      conn_t *down = conn_create_outbound(ckt);
      if (!down)
        circuit_close(ckt); /* XXXX send socks reply */
      bufferevent_disable(bev, EV_READ|EV_WRITE); /* wait for connection */
      return;
    }

    socks_ret = handle_socks(bufferevent_get_input(bev),
                             bufferevent_get_output(bev),
                             socks);
  } while (socks_ret == SOCKS_GOOD);

  if (socks_ret == SOCKS_INCOMPLETE)
    return; /* need to read more data. */
  else if (socks_ret == SOCKS_BROKEN)
    circuit_close(ckt); /* XXXX send socks reply */
  else if (socks_ret == SOCKS_CMD_NOT_CONNECT) {
    bufferevent_enable(bev, EV_WRITE);
    bufferevent_disable(bev, EV_READ);
    socks5_send_reply(bufferevent_get_output(bev), socks,
                      SOCKS5_FAILED_UNSUPPORTED);
    circuit_do_flush(ckt);
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
  circuit_t *ckt = arg;
  log_debug("%s: %s, %lu bytes available", ckt->up_peer, __func__,
            (unsigned long)evbuffer_get_length(bufferevent_get_input(bev)));

  obfs_assert(ckt->up_buffer == bev);
  circuit_send(ckt);
}

/**
   This callback is responsible for handling "downstream" traffic --
   traffic coming in from our remote peer that needs to be deobfuscated
   and passed to the upstream client or server.
 */
static void
downstream_read_cb(struct bufferevent *bev, void *arg)
{
  conn_t *down = arg;

  log_debug("%s: %s, %lu bytes available", down->peername, __func__,
            (unsigned long)evbuffer_get_length(bufferevent_get_input(bev)));

  if (conn_recv(down) == RECV_BAD) {
    log_debug("%s: error during receive.", down->peername);
    conn_close(down);
  }
}

/** Diagnostic-printing subroutine of upstream_event_cb and
    downstream_event_cb. */
static void
report_event(short what, const char *peer, int errcode)
{
  if (what & BEV_EVENT_ERROR)
    log_warn("%s: network error in %s: %s",
             peer,
             (what & BEV_EVENT_READING) ? "read" : "write",
             evutil_socket_error_to_string(errcode));
  else if (what & BEV_EVENT_EOF)
    log_info("%s: %s",
             peer,
             (what & BEV_EVENT_READING)
             ? "received EOF"
             : "further transmissions squelched");
  else if (what & BEV_EVENT_TIMEOUT)
    log_warn("%s: %s timed out",
             peer,
             (what & BEV_EVENT_READING) ? "read" : "write");
}

/**
   Called when there is an "event" (error, eof, or timeout) on one of
   our upstream connections.
 */

static void
upstream_event_cb(struct bufferevent *bev, short what, void *arg)
{
  circuit_t *ckt = arg;

  if (what & (BEV_EVENT_ERROR|BEV_EVENT_EOF|BEV_EVENT_TIMEOUT)) {
    report_event(what, ckt->up_peer, EVUTIL_SOCKET_ERROR());
    if (what == (BEV_EVENT_EOF|BEV_EVENT_READING)) {
      /* Upstream is done sending us data. */
      circuit_send_eof(ckt);
    } else {
      circuit_close(ckt);
    }
  } else {
    /* We should never get BEV_EVENT_CONNECTED here.
       Ignore any events we don't understand. */
    obfs_assert(!(what & BEV_EVENT_CONNECTED));
  }
}

/**
   Called when there is an "event" (error, eof, or timeout) on one of
   our downstream connections.
 */
static void
downstream_event_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = arg;

  if (what & (BEV_EVENT_ERROR|BEV_EVENT_EOF|BEV_EVENT_TIMEOUT)) {
    report_event(what, conn->peername, EVUTIL_SOCKET_ERROR());
    if (what == (BEV_EVENT_EOF|BEV_EVENT_READING)) {
      /* Peer is done sending us data. */
      conn_recv_eof(conn);
    } else {
      conn_close(conn);
    }
  } else {
    /* We should never get BEV_EVENT_CONNECTED here.
       Ignore any events we don't understand. */
    obfs_assert(!(what & BEV_EVENT_CONNECTED));
  }
}

/**
   Close a circuit when it has finished writing out all pending data.
 */
static void
upstream_flush_cb(struct bufferevent *bev, void *arg)
{
  circuit_t *ckt = arg;
  size_t remain = evbuffer_get_length(bufferevent_get_output(bev));
  log_debug("%s: %s, %ld bytes still to transmit",
            ckt->up_peer, __func__, (unsigned long)remain);

  if (remain == 0) {
    bufferevent_disable(bev, EV_WRITE);
    if (bufferevent_get_enabled(bev)) {
      log_debug("%s: sending EOF", ckt->up_peer);
      shutdown(bufferevent_getfd(bev), SHUT_WR);
    } else {
      log_info("%s: closing circuit", ckt->up_peer);
      circuit_close(ckt);
    }
  }
}

/**
   Close a connection when it has finished writing out all pending data.
*/
static void
downstream_flush_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  size_t remain = evbuffer_get_length(bufferevent_get_output(bev));
  log_debug("%s: %s, %ld bytes still to transmit",
            conn->peername, __func__, (unsigned long)remain);

  if (remain == 0) {
    bufferevent_disable(bev, EV_WRITE);
    if (bufferevent_get_enabled(bev)) {
      log_debug("%s: sending EOF", conn->peername);
      shutdown(bufferevent_getfd(bev), SHUT_WR);
    } else {
      log_info("%s: closing downstream connection", conn->peername);
      conn_close(conn);
    }
  }
}

/**
   Called when an upstream connection has just been established, or
   failed to establish.
*/
static void
upstream_connect_cb(struct bufferevent *bev, short what, void *arg)
{
  circuit_t *ckt = arg;
  log_debug("%s for %s", __func__, ckt->up_peer);

  /* Upon successful connection, enable traffic on both sides of the
     connection, and replace this callback with the regular event_cb */
  if (what & BEV_EVENT_CONNECTED) {
    obfs_assert(ckt->up_buffer == bev);

    log_debug("%s: Successful connection", ckt->up_peer);

    bufferevent_setcb(ckt->up_buffer,
                      upstream_read_cb, NULL, upstream_event_cb, ckt);
    bufferevent_enable(ckt->up_buffer, EV_READ|EV_WRITE);
    return;
  }

  /* Otherwise, must be an error */
  upstream_event_cb(bev, what, arg);
}

/**
   Called when a downstream connection has just been established, or
   failed to establish.
*/
static void
downstream_connect_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = arg;
  log_debug("%s for %s", __func__, conn->peername);

  /* Upon successful connection, enable traffic on both sides of the
     connection, and replace this callback with the regular event_cb */
  if (what & BEV_EVENT_CONNECTED) {
    circuit_t *ckt = conn->circuit;
    obfs_assert(ckt);
    obfs_assert(ckt->up_peer);
    obfs_assert(conn->buffer == bev);

    log_debug("%s: Successful connection", conn->peername);

    /* Queue handshake, if any. */
    if (conn_handshake(conn) < 0) {
      log_debug("%s: Error during handshake", conn->peername);
      conn_close(conn);
      return;
    }

    bufferevent_setcb(conn->buffer,
                      downstream_read_cb, NULL, downstream_event_cb, conn);

    bufferevent_enable(ckt->up_buffer, EV_READ|EV_WRITE);
    bufferevent_enable(conn->buffer, EV_READ|EV_WRITE);
    return;
  }

  /* Otherwise, must be an error */
  downstream_event_cb(bev, what, arg);
}

static void
downstream_socks_connect_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = arg;
  circuit_t *ckt = conn->circuit;
  socks_state_t *socks;

  log_debug("%s for %s", __func__, conn->peername);

  obfs_assert(ckt);
  obfs_assert(ckt->up_buffer);
  obfs_assert(ckt->socks_state);

  socks = ckt->socks_state;

  /* If we got an error while in the ST_HAVE_ADDR state, chances are
     that we failed connecting to the host requested by the CONNECT
     call. This means that we should send a negative SOCKS reply back
     to the client and terminate the connection.
     XXX properly distinguish BEV_EVENT_EOF from BEV_EVENT_ERROR;
     errno isn't meaningful in that case...  */
  if ((what & (BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT))) {
    int err = EVUTIL_SOCKET_ERROR();
    log_warn("Connection error: %s", evutil_socket_error_to_string(err));
    if (socks_state_get_status(socks) == ST_HAVE_ADDR) {
      bufferevent_enable(ckt->up_buffer, EV_WRITE);
      socks_send_reply(socks, bufferevent_get_output(ckt->up_buffer), err);
      circuit_do_flush(ckt);
    } else {
      circuit_close(ckt);
    }
    return;
  }

  /* Additional work to do for BEV_EVENT_CONNECTED: send a happy
     response to the client and switch to the actual obfuscated
     protocol handlers. */
  if (what & BEV_EVENT_CONNECTED) {
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr*)&ss;
    socklen_t slen = sizeof(&ss);

    /* Figure out where we actually connected to, and tell the socks client */
    if (getpeername(bufferevent_getfd(bev), sa, &slen) == 0) {
      socks_state_set_address(socks, sa);
      conn->peername = printable_address(sa, slen);
    }
    socks_send_reply(socks, bufferevent_get_output(ckt->up_buffer), 0);

    /* Switch to regular upstream behavior. */
    socks_state_free(socks);
    ckt->socks_state = NULL;

    log_debug("%s: Successful outbound connection to %s",
              ckt->up_peer, conn->peername);

    bufferevent_setcb(ckt->up_buffer, upstream_read_cb, NULL,
                      upstream_event_cb, ckt);
    bufferevent_setcb(conn->buffer, downstream_read_cb, NULL,
                      downstream_event_cb, conn);
    bufferevent_enable(ckt->up_buffer, EV_READ|EV_WRITE);
    bufferevent_enable(conn->buffer, EV_READ|EV_WRITE);

    /* Queue handshake, if any. */
    if (conn_handshake(conn)) {
      log_debug("%s: Error during handshake", conn->peername);
      conn_close(conn);
      return;
    }

    if (evbuffer_get_length(bufferevent_get_input(ckt->up_buffer)) > 0)
      upstream_read_cb(ckt->up_buffer, ckt);

    return;
  }

  /* ignore unknown event codes */
}

/* These routines are here and not in connections.c because they
   need access to the bufferevent callback functions. */

int
circuit_open_upstream(circuit_t *ckt)
{
  struct evutil_addrinfo *addr;
  struct bufferevent *buf;
  char *peername;

  addr = config_get_target_addr(ckt->cfg);

  if (!addr) {
    log_warn("no target addresses available");
    return -1;
  }

  buf = bufferevent_socket_new(ckt->cfg->base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("unable to create outbound socket buffer");
    return -1;
  }

  bufferevent_setcb(buf, upstream_read_cb, NULL, upstream_connect_cb, ckt);

  do {
    peername = printable_address(addr->ai_addr, addr->ai_addrlen);
    log_info("Trying to connect to %s", peername);
    if (bufferevent_socket_connect(buf, addr->ai_addr, addr->ai_addrlen) >= 0)
      goto success;

    log_info("Connection to %s failed: %s", peername,
             evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    free(peername);
    addr = addr->ai_next;

  } while (addr);

  bufferevent_free(buf);
  return -1;

 success:
  bufferevent_enable(buf, EV_READ|EV_WRITE);
  circuit_add_upstream(ckt, buf, peername);
  return 0;
}

conn_t *
conn_create_outbound(circuit_t *ckt)
{
  config_t *cfg = ckt->cfg;
  char *peername;
  struct bufferevent *buf;
  bufferevent_event_cb connect_cb;
  conn_t *conn;

  buf = bufferevent_socket_new(cfg->base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("unable to create outbound socket buffer");
    return NULL;
  }

  if (cfg->mode == LSN_SIMPLE_CLIENT) {
    struct evutil_addrinfo *addr = config_get_target_addr(cfg);
    if (!addr) {
      log_warn("no target addresses available");
      goto failure;
    }

    connect_cb = downstream_connect_cb;
    do {
      peername = printable_address(addr->ai_addr, addr->ai_addrlen);
      log_info("Trying to connect to %s", peername);
      if (bufferevent_socket_connect(buf,
                                     addr->ai_addr,
                                     addr->ai_addrlen) >= 0)
        goto success;

      log_info("Connection to %s failed: %s", peername,
               evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
      free(peername);
      addr = addr->ai_next;
    } while (addr);

  } else {
    const char *host;
    int af, port;
    struct evdns_base *dns = get_evdns_base();

    obfs_assert(cfg->mode == LSN_SOCKS_CLIENT);
    if (socks_state_get_address(ckt->socks_state, &af, &host, &port)) {
      log_warn("no SOCKS target available");
      goto failure;
    }

    connect_cb = downstream_socks_connect_cb;
    peername = NULL;
    log_info("Trying to connect to %s:%u", host, port);
    if (bufferevent_socket_connect_hostname(buf, dns, af, host, port) >= 0)
      goto success;

    log_info("Connection to %s:%d failed: %s", host, port,
             evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
  }

 failure:
  bufferevent_free(buf);
  return NULL;

 success:
  conn = conn_create(cfg, buf, peername);
  circuit_add_downstream(ckt, conn);
  bufferevent_setcb(buf, downstream_read_cb, NULL, connect_cb, conn);
  bufferevent_enable(buf, EV_READ|EV_WRITE);
  return conn;
}

void
circuit_do_flush(circuit_t *ckt)
{
  bufferevent_setcb(ckt->up_buffer,
                    upstream_read_cb,
                    upstream_flush_cb,
                    upstream_event_cb, ckt);
}

void
conn_do_flush(conn_t *conn)
{
  bufferevent_setcb(conn->buffer,
                    downstream_read_cb,
                    downstream_flush_cb,
                    downstream_event_cb, conn);
}
