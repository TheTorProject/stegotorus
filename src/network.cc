/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "listener.h"

#include "connections.h"
#include "socks.h"
#include "protocol.h"

#include <vector>

#include <errno.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

using std::vector;

/**
  This struct defines the state of a listener on a particular address.
 */
struct listener_t
{
  config_t *cfg;
  struct evconnlistener *listener;
  char *address;
  size_t index;
};

/** All our listeners. */
static vector<listener_t *> listeners;

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

static void upstream_flush_cb(struct bufferevent *bev, void *arg);
static void downstream_flush_cb(struct bufferevent *bev, void *arg);

static void upstream_event_cb(struct bufferevent *bev, short what, void *arg);
static void downstream_event_cb(struct bufferevent *bev, short what, void *arg);

static void create_outbound_connections(circuit_t *ckt, bool is_socks);
static void create_outbound_connections_socks(circuit_t *ckt);

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

  /* We can now record the event_base to be used with this configuration. */
  cfg->base = base;

  /* Open listeners for every address in the configuration. */
  for (i = 0; ; i++) {
    addrs = cfg->get_listen_addrs(i);
    if (!addrs) break;
    do {
      lsn = (listener_t *)xzalloc(sizeof(listener_t));
      lsn->cfg = cfg;
      lsn->address = printable_address(addrs->ai_addr, addrs->ai_addrlen);
      lsn->index = i;
      lsn->listener =
        evconnlistener_new_bind(base, callback, lsn, flags, -1,
                                addrs->ai_addr, addrs->ai_addrlen);

      if (!lsn->listener) {
        log_warn("failed to open listening socket on %s: %s",
                 lsn->address,
                 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        listener_close(lsn);
        return 0;
      }

      listeners.push_back(lsn);
      log_debug("now listening on %s for protocol %s",
                lsn->address, cfg->name());

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
  log_info("closing all listeners");

  for (vector<listener_t *>::iterator i = listeners.begin();
       i != listeners.end(); i++)
    listener_close(*i);
  listeners.clear();
}

/**
   This function is called when a client-mode listener (simple or socks)
   receives a connection.
 */
static void
client_listener_cb(struct evconnlistener *, evutil_socket_t fd,
                   struct sockaddr *peeraddr, int peerlen,
                   void *closure)
{
  listener_t *lsn = (listener_t *)closure;
  char *peername = printable_address(peeraddr, peerlen);
  struct bufferevent *buf = NULL;
  circuit_t *ckt = NULL;
  int is_socks = lsn->cfg->mode == LSN_SOCKS_CLIENT;

  log_assert(lsn->cfg->mode != LSN_SIMPLE_SERVER);
  log_info("%s: new connection to %sclient from %s",
           lsn->address, is_socks ? "socks " : "", peername);

  buf = bufferevent_socket_new(lsn->cfg->base, fd, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("%s: failed to create buffer for new connection from %s",
             lsn->address, peername);
    evutil_closesocket(fd);
    free(peername);
    return;
  }

  ckt = circuit_create(lsn->cfg, lsn->index);
  if (!ckt) {
    log_warn("%s: failed to create circuit for new connection from %s",
             lsn->address, peername);
    bufferevent_free(buf);
    free(peername);
    return;
  }

  ckt->connected = 1;
  circuit_add_upstream(ckt, buf, peername);
  if (is_socks) {
    /* We can't do anything more till we know where to connect to. */
    bufferevent_setcb(buf, socks_read_cb, upstream_flush_cb,
                      upstream_event_cb, ckt);
    bufferevent_enable(buf, EV_READ|EV_WRITE);
  } else {
    bufferevent_setcb(buf, upstream_read_cb, upstream_flush_cb,
                      upstream_event_cb, ckt);
    create_outbound_connections(ckt, false);
    /* Don't enable reading or writing till the outbound connection(s) are
       established. */
  }
}

/**
   This function is called when a server-mode listener receives a connection.
 */
static void
server_listener_cb(struct evconnlistener *, evutil_socket_t fd,
                   struct sockaddr *peeraddr, int peerlen,
                   void *closure)
{
  listener_t *lsn = (listener_t *)closure;
  char *peername = printable_address(peeraddr, peerlen);
  struct bufferevent *buf;
  conn_t *conn;

  log_assert(lsn->cfg->mode == LSN_SIMPLE_SERVER);
  log_info("%s: new connection to server from %s", lsn->address, peername);

  buf = bufferevent_socket_new(lsn->cfg->base, fd, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("%s: failed to create buffer for new connection from %s",
             lsn->address, peername);
    evutil_closesocket(fd);
    free(peername);
    return;
  }

  conn = conn_create(lsn->cfg, lsn->index, buf, peername);
  conn->connected = 1;
  if (!conn) {
    log_warn("%s: failed to create connection structure for %s",
             lsn->address, peername);
    bufferevent_free(buf);
    free(peername);
    return;
  }

  /* If appropriate at this point, connect to upstream. */
  if (conn->maybe_open_upstream() < 0) {
    log_debug(conn, "error opening upstream circuit");
    delete conn;
    return;
  }

  /* Queue handshake, if any. */
  if (conn->handshake() < 0) {
    log_debug(conn, "error during handshake");
    delete conn;
    return;
  }

  bufferevent_setcb(buf, downstream_read_cb, downstream_flush_cb,
                    downstream_event_cb, conn);
  bufferevent_enable(conn->buffer, EV_READ|EV_WRITE);
}

/**
    This callback is responsible for handling SOCKS traffic.
*/
static void
socks_read_cb(struct bufferevent *bev, void *arg)
{
  circuit_t *ckt = (circuit_t *)arg;
  socks_state_t *socks;
  enum socks_ret socks_ret;
  log_assert(ckt->cfg()->mode == LSN_SOCKS_CLIENT);
  log_assert(ckt->socks_state);
  socks = ckt->socks_state;

  log_debug(ckt, "%lu bytes available",
            (unsigned long) evbuffer_get_length(bufferevent_get_input(bev)));

  do {
    enum socks_status_t status = socks_state_get_status(socks);
    log_assert(status != ST_SENT_REPLY); /* we shouldn't be here then */

    if (status == ST_HAVE_ADDR) {
      bufferevent_disable(bev, EV_READ|EV_WRITE); /* wait for connection */
      create_outbound_connections_socks(ckt);
      return;
    }

    socks_ret = handle_socks(bufferevent_get_input(bev),
                             bufferevent_get_output(bev),
                             socks);
  } while (socks_ret == SOCKS_GOOD);

  if (socks_ret == SOCKS_INCOMPLETE)
    return; /* need to read more data. */
  else if (socks_ret == SOCKS_BROKEN)
    delete ckt; /* XXXX send socks reply */
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
  circuit_t *ckt = (circuit_t *)arg;
  log_debug(ckt, "%lu bytes available",
            (unsigned long)evbuffer_get_length(bufferevent_get_input(bev)));

  log_assert(ckt->up_buffer == bev);
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
  conn_t *down = (conn_t *)arg;

  log_debug(down, "%lu bytes available",
            (unsigned long)evbuffer_get_length(bufferevent_get_input(bev)));

  if (down->recv()) {
    log_debug(down, "error during receive");
    delete down;
  }
}

/**
   Called when there is an "event" (error, eof, or timeout) on one of
   our upstream connections.
 */

static void
upstream_event_cb(struct bufferevent *bev, short what, void *arg)
{
  circuit_t *ckt = (circuit_t *)arg;

  if (what & (BEV_EVENT_ERROR|BEV_EVENT_EOF|BEV_EVENT_TIMEOUT)) {
    if (what & BEV_EVENT_ERROR)
      log_warn(ckt, "network error in %s: %s",
               (what & BEV_EVENT_READING) ? "read" : "write",
               evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    else if (what & BEV_EVENT_EOF)
      log_info(ckt, "%s",
               (what & BEV_EVENT_READING)
               ? "EOF from upstream"
               : "further transmissions to upstream squelched");
    else if (what & BEV_EVENT_TIMEOUT)
      log_warn(ckt, "%s timed out",
               (what & BEV_EVENT_READING) ? "read" : "write");

    if (what == (BEV_EVENT_EOF|BEV_EVENT_READING)) {
      /* Upstream is done sending us data. */
      circuit_send_eof(ckt);
      if (bufferevent_get_enabled(bev) ||
          evbuffer_get_length(bufferevent_get_input(bev)) > 0) {
        log_debug(ckt, "acknowledging EOF upstream");
        shutdown(bufferevent_getfd(bev), SHUT_RD);
      } else {
        delete ckt;
      }
    } else {
      delete ckt;
    }
  } else {
    /* We should never get BEV_EVENT_CONNECTED here.
       Ignore any events we don't understand. */
    if (what & BEV_EVENT_CONNECTED)
      log_abort(ckt, "double connection event");
  }
}

/**
   Called when there is an "event" (error, eof, or timeout) on one of
   our downstream connections.
 */
static void
downstream_event_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = (conn_t *)arg;

  if (what & (BEV_EVENT_ERROR|BEV_EVENT_EOF|BEV_EVENT_TIMEOUT)) {
    if (what & BEV_EVENT_ERROR)
      log_warn(conn, "network error in %s: %s",
               (what & BEV_EVENT_READING) ? "read" : "write",
               evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    else if (what & BEV_EVENT_EOF)
      log_info(conn, "%s",
               (what & BEV_EVENT_READING)
               ? "EOF from peer"
               : "further transmissions to peer squelched");
    else if (what & BEV_EVENT_TIMEOUT)
      log_warn(conn, "%s timed out",
               (what & BEV_EVENT_READING) ? "read" : "write");

    if (what == (BEV_EVENT_EOF|BEV_EVENT_READING)) {
      /* Peer is done sending us data. */
      conn->recv_eof();
      if (bufferevent_get_enabled(bev) ||
          evbuffer_get_length(bufferevent_get_input(bev)) > 0) {
        log_debug(conn, "acknowledging EOF downstream");
        shutdown(bufferevent_getfd(bev), SHUT_RD);
      } else {
        delete conn;
      }
    } else {
      delete conn;
    }
  } else {
    /* We should never get BEV_EVENT_CONNECTED here.
       Ignore any events we don't understand. */
    if (what & BEV_EVENT_CONNECTED)
      log_abort(conn, "double connection event");
  }
}

/**
   Close a circuit when it has finished writing out all pending data.
 */
static void
upstream_flush_cb(struct bufferevent *bev, void *arg)
{
  circuit_t *ckt = (circuit_t *)arg;
  size_t remain = evbuffer_get_length(bufferevent_get_output(bev));
  log_debug(ckt, "%lu bytes still to transmit%s%s",
            (unsigned long)remain,
            ckt->connected ? "" : " (not connected)",
            ckt->flushing ? "" : " (not flushing)");

  if (remain == 0 && ckt->flushing && ckt->connected
      && (!ckt->flush_timer || !evtimer_pending(ckt->flush_timer, NULL))) {
    bufferevent_disable(bev, EV_WRITE);
    if (bufferevent_get_enabled(bev) ||
        evbuffer_get_length(bufferevent_get_input(bev)) > 0) {
      log_debug(ckt, "sending EOF upstream");
      shutdown(bufferevent_getfd(bev), SHUT_WR);
    } else {
      delete ckt;
    }
  }
}

/**
   Close a connection when it has finished writing out all pending data.
*/
static void
downstream_flush_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = (conn_t *)arg;
  size_t remain = evbuffer_get_length(bufferevent_get_output(bev));
  log_debug(conn, "%lu bytes still to transmit%s%s",
            (unsigned long)remain,
            conn->connected ? "" : " (not connected)",
            conn->flushing ? "" : " (not flushing)");

  if (remain == 0 && conn->flushing && conn->connected) {
    bufferevent_disable(bev, EV_WRITE);
    if (bufferevent_get_enabled(bev)) {
      log_debug(conn, "sending EOF downstream");
      shutdown(bufferevent_getfd(bev), SHUT_WR);
    } else {
      delete conn;
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
  circuit_t *ckt = (circuit_t *)arg;
  log_debug(ckt, "what=%04hx", what);

  /* Upon successful connection, enable traffic on both sides of the
     connection, and replace this callback with the regular event_cb */
  if (what & BEV_EVENT_CONNECTED) {
    log_info(ckt, "successful connection");

    bufferevent_setcb(ckt->up_buffer, upstream_read_cb, upstream_flush_cb,
                      upstream_event_cb, ckt);
    bufferevent_enable(ckt->up_buffer, EV_READ|EV_WRITE);
    ckt->connected = 1;
    if (ckt->pending_eof) {
      /* Try again to process the EOF. */
      circuit_recv_eof(ckt);
    }
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
  conn_t *conn = (conn_t *)arg;
  log_debug(conn, "what=%04hx", what);

  /* Upon successful connection, enable traffic on both sides of the
     connection, and replace this callback with the regular event_cb */
  if (what & BEV_EVENT_CONNECTED) {
    circuit_t *ckt = conn->circuit();
    log_assert(ckt);
    log_assert(ckt->up_peer);
    log_assert(conn->buffer == bev);

    log_debug(conn, "successful connection");

    bufferevent_setcb(conn->buffer, downstream_read_cb,
                      downstream_flush_cb, downstream_event_cb, conn);

    bufferevent_enable(ckt->up_buffer, EV_READ|EV_WRITE);
    bufferevent_enable(conn->buffer, EV_READ|EV_WRITE);
    conn->connected = 1;

    /* Queue handshake, if any. */
    if (conn->handshake() < 0) {
      log_debug(conn, "error during handshake");
      delete conn;
      return;
    }

    if (ckt->pending_eof) {
      /* Try again to process the EOF. */
      circuit_recv_eof(ckt);
    }
    return;
  }

  /* Otherwise, must be an error */
  downstream_event_cb(bev, what, arg);
}

static void
downstream_socks_connect_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = (conn_t *)arg;
  circuit_t *ckt = conn->circuit();
  socks_state_t *socks;

  log_debug(conn, "what=%04hx", what);
  log_assert(ckt);
  log_assert(ckt->up_buffer);

  if (!ckt->socks_state) {
    /* This can happen if we made more than one downstream connection
       for a circuit; the second and subsequent connections do not
       need the special socks handling, as it's already been done by
       the first one. */
    downstream_connect_cb(bev, what, arg);
    return;
  }

  socks = ckt->socks_state;

  /* If we got an error while in the ST_HAVE_ADDR state, chances are
     that we failed connecting to the host requested by the CONNECT
     call. This means that we should send a negative SOCKS reply back
     to the client and terminate the connection.
     XXX properly distinguish BEV_EVENT_EOF from BEV_EVENT_ERROR;
     errno isn't meaningful in that case...  */
  if ((what & (BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT))) {
    int err = EVUTIL_SOCKET_ERROR();
    log_warn(ckt, "downstream connection error: %s",
             evutil_socket_error_to_string(err));
    if (socks_state_get_status(socks) == ST_HAVE_ADDR) {
      bufferevent_enable(ckt->up_buffer, EV_WRITE);
      socks_send_reply(socks, bufferevent_get_output(ckt->up_buffer), err);
      circuit_do_flush(ckt);
    } else {
      delete ckt;
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

    log_debug(ckt, "successful outbound connection to %s", conn->peername);

    bufferevent_setcb(ckt->up_buffer, upstream_read_cb, upstream_flush_cb,
                      upstream_event_cb, ckt);
    bufferevent_setcb(conn->buffer, downstream_read_cb, downstream_flush_cb,
                      downstream_event_cb, conn);
    bufferevent_enable(ckt->up_buffer, EV_READ|EV_WRITE);
    bufferevent_enable(conn->buffer, EV_READ|EV_WRITE);
    conn->connected = 1;

    /* Queue handshake, if any. */
    if (conn->handshake()) {
      log_debug(conn, "error during handshake");
      delete conn;
      return;
    }

    if (evbuffer_get_length(bufferevent_get_input(ckt->up_buffer)) > 0)
      /* Process any data stacked up while we were waiting for the
         connection. */
      upstream_read_cb(ckt->up_buffer, ckt);

    if (ckt->pending_eof) {
      /* Try again to process the EOF. */
      circuit_recv_eof(ckt);
    }

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

  addr = ckt->cfg()->get_target_addrs(0);

  if (!addr) {
    log_warn(ckt, "no target addresses available");
    return -1;
  }

  buf = bufferevent_socket_new(ckt->cfg()->base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn(ckt, "unable to create outbound socket buffer");
    return -1;
  }

  bufferevent_setcb(buf, upstream_read_cb, upstream_flush_cb,
                    upstream_connect_cb, ckt);

  do {
    peername = printable_address(addr->ai_addr, addr->ai_addrlen);
    log_info(ckt, "trying to connect to %s", peername);
    if (bufferevent_socket_connect(buf, addr->ai_addr, addr->ai_addrlen) >= 0)
      goto success;

    log_info(ckt, "connection to %s failed: %s", peername,
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

static bool
create_one_outbound_connection(circuit_t *ckt, struct evutil_addrinfo *addr,
                               size_t index, bool is_socks)
{
  config_t *cfg = ckt->cfg();
  char *peername;
  struct bufferevent *buf;
  conn_t *conn;

  buf = bufferevent_socket_new(cfg->base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn(ckt, "unable to create outbound socket buffer");
    return false;
  }

  do {
    peername = printable_address(addr->ai_addr, addr->ai_addrlen);
    log_info(ckt, "trying to connect to %s", peername);
    if (bufferevent_socket_connect(buf,
                                   addr->ai_addr,
                                   addr->ai_addrlen) >= 0)
      goto success;

    log_info(ckt, "connection to %s failed: %s", peername,
             evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    free(peername);
    addr = addr->ai_next;
  } while (addr);

  bufferevent_free(buf);
  return false;

 success:
  conn = conn_create(cfg, index, buf, peername);
  ckt->add_downstream(conn);
  bufferevent_setcb(buf, downstream_read_cb, downstream_flush_cb,
                    is_socks ? downstream_socks_connect_cb
                    : downstream_connect_cb, conn);
  bufferevent_enable(buf, EV_READ|EV_WRITE);
  return true;
}

static void
create_outbound_connections(circuit_t *ckt, bool is_socks)
{
  struct evutil_addrinfo *addr;
  size_t n = 0;
  bool any_successes = false;

  while ((addr = ckt->cfg()->get_target_addrs(n))) {
    any_successes |= create_one_outbound_connection(ckt, addr, n, is_socks);
    n++;
  }

  if (n == 0) {
    log_warn(ckt, "no target addresses available");
    delete ckt;
  }
  if (any_successes == 0) {
    log_warn(ckt, "no outbound connections were successful");
    delete ckt;
  }
}

void
circuit_reopen_downstreams(circuit_t *ckt)
{
  create_outbound_connections(ckt, false);
}

static void
create_outbound_connections_socks(circuit_t *ckt)
{
  config_t *cfg = ckt->cfg();
  struct bufferevent *buf = NULL;
  conn_t *conn;
  const char *host;
  int af, port;
  struct evdns_base *dns = get_evdns_base();

  log_assert(cfg->mode == LSN_SOCKS_CLIENT);
  if (socks_state_get_address(ckt->socks_state, &af, &host, &port)) {
    log_warn(ckt, "no destination address available from SOCKS");
    goto failure;
  }

  /* XXXX Feed socks state through the protocol and get a connection set.
     This is a stopgap. */
  if (ckt->cfg()->ignore_socks_destination) {
    create_outbound_connections(ckt, true);
    return;
  }

  buf = bufferevent_socket_new(cfg->base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn(ckt, "unable to create outbound socket buffer");
    goto failure;
  }

  log_info(ckt, "trying to connect to %s:%u", host, port);
  if (bufferevent_socket_connect_hostname(buf, dns, af, host, port) < 0) {
    log_info(ckt, "connection to %s:%d failed: %s", host, port,
             evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    goto failure;
  }

  /* we don't know the peername yet */
  conn = conn_create(cfg, 0, buf, NULL);
  ckt->add_downstream(conn);
  bufferevent_setcb(buf, downstream_read_cb, downstream_flush_cb,
                    downstream_socks_connect_cb, conn);
  bufferevent_enable(buf, EV_READ|EV_WRITE);
  return;

 failure:
  /* XXXX send socks reply */
  delete ckt;
  if (buf)
    bufferevent_free(buf);
}

void
circuit_do_flush(circuit_t *ckt)
{
  size_t remain = evbuffer_get_length(bufferevent_get_output(ckt->up_buffer));
  ckt->flushing = 1;

  /* If 'remain' is already zero, we have to call the flush callback
     manually; libevent won't do it for us. */
  if (remain == 0)
    upstream_flush_cb(ckt->up_buffer, ckt);
  else
    log_debug(ckt, "flushing %lu bytes to upstream", (unsigned long)remain);
}

void
conn_do_flush(conn_t *conn)
{
  size_t remain = evbuffer_get_length(conn->outbound());
  conn->flushing = 1;

  /* If 'remain' is already zero, we have to call the flush callback
     manually; libevent won't do it for us. */
  if (remain == 0)
    downstream_flush_cb(conn->buffer, conn);
  else
    log_debug(conn, "flushing %lu bytes to peer", (unsigned long)remain);
}
