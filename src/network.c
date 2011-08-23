/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "network.h"

#include "connections.h"
#include "container.h"
#include "main.h"
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
  struct event_base *base = evconnlistener_get_base(evcl);
  struct bufferevent *buf = NULL;
  circuit_t *ckt = NULL;
  int is_socks = lsn->cfg->mode == LSN_SOCKS_CLIENT;

  obfs_assert(lsn->cfg->mode != LSN_SIMPLE_SERVER);
  log_info("%s: new connection to %sclient from %s\n",
           lsn->address, is_socks ? "socks " : "", peername);

  buf = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("%s: failed to set up new connection from %s",
             lsn->address, peername);
    evutil_closesocket(fd);
    free(peername);
    return;
  }

  ckt = circuit_create(lsn->cfg, buf, peername);
  if (is_socks) {
    bufferevent_setcb(buf, socks_read_cb, NULL, upstream_event_cb, ckt);
    /* We can't do anything more till we know where to connect to. */
    bufferevent_enable(buf, EV_READ|EV_WRITE);
  } else {
    bufferevent_setcb(buf, upstream_read_cb, NULL, upstream_event_cb, ckt);
    if (!circuit_open_downstream_from_cfg(ckt)) {
      log_warn("%s: outbound connection failed", peername);
      circuit_close(ckt);
    }
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
  struct event_base *base = evconnlistener_get_base(evcl);
  struct bufferevent *buf = NULL;
  conn_t *conn = NULL;

  obfs_assert(lsn->cfg->mode == LSN_SIMPLE_SERVER);
  log_info("%s: new connection to server from %s\n", lsn->address, peername);

  buf = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("%s: failed to set up new connection from %s",
             lsn->address, peername);
    evutil_closesocket(fd);
    free(peername);
    return;
  }

  conn = conn_create(lsn->cfg, buf, peername);
  bufferevent_setcb(buf, downstream_read_cb, NULL, downstream_event_cb, conn);

  if (circuit_create_with_downstream(lsn->cfg, conn) == NULL) {
    log_warn("%s: failed to establish circuit for %s",
             lsn->address, peername);
    conn_close(conn);
  }
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
      circuit_open_downstream_from_socks(ckt);
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
  obfs_assert(ckt->downstream);
  obfs_assert(ckt->is_open);

  if (conn_send(ckt->downstream, bufferevent_get_input(ckt->up_buffer))) {
    log_debug("%s: error during transmit.", ckt->up_peer);
    conn_close(ckt->downstream);
  }
  log_debug("%s: transmitted %lu bytes to %s", ckt->up_peer,
            (unsigned long)
            evbuffer_get_length(conn_get_outbound(ckt->downstream)),
            ckt->downstream->peername);
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
  struct bufferevent *up;
  enum recv_ret r;

  log_debug("%s: %s, %lu bytes available", down->peername, __func__,
            (unsigned long)evbuffer_get_length(bufferevent_get_input(bev)));

  obfs_assert(down->buffer == bev);
  obfs_assert(down->circuit);
  obfs_assert(down->circuit->up_buffer);
  obfs_assert(down->circuit->is_open);
  up = down->circuit->up_buffer;

  r = conn_recv(down, bufferevent_get_output(up));

  if (r == RECV_BAD) {
    log_debug("%s: error during receive.", down->peername);
    conn_close(down);
  } else {
    log_debug("%s: forwarded %lu bytes", down->peername,
              (unsigned long)evbuffer_get_length(bufferevent_get_output(up)));
    if (r == RECV_SEND_PENDING) {
      log_debug("%s: reply of %lu bytes", down->peername,
                (unsigned long)evbuffer_get_length(bufferevent_get_input(up)));

      if (conn_send(down, bufferevent_get_input(up)) < 0) {
        log_debug("%s: error during reply.", down->peername);
        conn_close(down);
      }
      log_debug("%s: transmitted %lu bytes", down->peername,
                (unsigned long)evbuffer_get_length(conn_get_outbound(down)));
    }
  }
}

/**
   Called when there is an "event" (error, eof, or timeout) on one of
   our upstream connections.
 */

static void
upstream_event_cb(struct bufferevent *bev, short what, void *arg)
{
  circuit_t *ckt = arg;
  int errcode = EVUTIL_SOCKET_ERROR();

  if (what & BEV_EVENT_ERROR) {
    log_warn("Error talking to %s: %s",
             ckt->up_peer, evutil_socket_error_to_string(errcode));
  } else if (what & BEV_EVENT_EOF) {
    log_info("EOF from %s", ckt->up_peer);
  } else if (what & BEV_EVENT_TIMEOUT) {
    log_info("Timeout talking to %s", ckt->up_peer);
  } else {
    obfs_assert(!(what & BEV_EVENT_CONNECTED));
    /* ignore events we don't understand */
    return;
  }

  what &= BEV_EVENT_READING|BEV_EVENT_WRITING;
  circuit_upstream_shutdown(ckt, what);
}

/**
   Called when there is an "event" (error, eof, or timeout) on one of
   our downstream connections.
 */
static void
downstream_event_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = arg;
  int errcode = EVUTIL_SOCKET_ERROR();

  if (what & BEV_EVENT_ERROR) {
    log_warn("Error talking to %s: %s",
             conn->peername, evutil_socket_error_to_string(errcode));
  } else if (what & BEV_EVENT_EOF) {
    log_info("EOF from %s", conn->peername);
  } else if (what & BEV_EVENT_TIMEOUT) {
    log_info("Timeout talking to %s", conn->peername);
  } else {
    obfs_assert(!(what & BEV_EVENT_CONNECTED));
    /* ignore events we don't understand */
    return;
  }

  what &= BEV_EVENT_READING|BEV_EVENT_WRITING;
  if (conn->circuit)
    circuit_downstream_shutdown(conn->circuit, conn, what);
  else
    conn_close(conn);
}

/**
   Close a circuit when it has finished writing out all pending data.
 */
static void
upstream_flush_cb(struct bufferevent *bev, void *arg)
{
  circuit_t *ckt = arg;
  log_debug("%s for %s", __func__, ckt->up_peer);

  if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
    bufferevent_disable(bev, EV_WRITE);
    if (bufferevent_get_enabled(bev))
      shutdown(bufferevent_getfd(bev), SHUT_WR);
    else
      circuit_close(ckt);
  }
}

/**
   Close a connection when it has finished writing out all pending data.
*/
static void
downstream_flush_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = arg;
  log_debug("%s for %s", __func__, conn->peername);

  if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
    bufferevent_disable(bev, EV_WRITE);
    if (bufferevent_get_enabled(bev))
      shutdown(bufferevent_getfd(bev), SHUT_WR);
    else
      conn_close(conn);
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
    obfs_assert(!ckt->is_open);
    obfs_assert(ckt->downstream);
    obfs_assert(ckt->up_buffer == bev);

    ckt->is_open = 1;

    log_debug("%s: Successful connection", ckt->up_peer);

    /* Queue handshake, if any. */
    if (conn_handshake(ckt->downstream) < 0) {
      log_debug("%s: Error during handshake", ckt->downstream->peername);
      conn_close(ckt->downstream);
      return;
    }

    bufferevent_setcb(ckt->up_buffer,
                      upstream_read_cb, NULL, upstream_event_cb, ckt);

    bufferevent_enable(ckt->up_buffer, EV_READ|EV_WRITE);
    bufferevent_enable(ckt->downstream->buffer, EV_READ|EV_WRITE);
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
    obfs_assert(!ckt->is_open);
    obfs_assert(ckt->up_peer);
    obfs_assert(ckt->downstream == conn);
    obfs_assert(conn->buffer == bev);

    ckt->is_open = 1;

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
  obfs_assert(ckt->downstream == conn);

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
      socks_send_reply(socks, bufferevent_get_output(ckt->up_buffer), err);
    }
    conn_close(conn);
    return;
  }

  /* Additional work to do for BEV_EVENT_CONNECTED: send a happy
     response to the client and switch to the actual obfuscated
     protocol handlers. */
  if (what & BEV_EVENT_CONNECTED) {
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr*)&ss;
    socklen_t slen = sizeof(&ss);

    obfs_assert(!ckt->is_open);

    /* Figure out where we actually connected to, and tell the socks client */
    if (getpeername(bufferevent_getfd(bev), sa, &slen) == 0) {
      socks_state_set_address(socks, sa);
      conn->peername = printable_address(sa, slen);
    }
    socks_send_reply(socks, bufferevent_get_output(ckt->up_buffer), 0);

    /* Switch to regular upstream behavior. */
    socks_state_free(socks);
    ckt->socks_state = NULL;
    ckt->is_open = 1;
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
circuit_connect_to_upstream(circuit_t *ckt, struct bufferevent *buf,
                            struct evutil_addrinfo *addr)
{
  char *peername;

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

  return 0;

 success:
  bufferevent_enable(buf, EV_READ|EV_WRITE);
  ckt->up_buffer = buf;
  ckt->up_peer = peername;
  return 1;
}

conn_t *
conn_create_outbound(config_t *cfg, struct bufferevent *buf,
                     struct evutil_addrinfo *addr)
{
  char *peername;
  conn_t *conn;

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

  return NULL;

 success:
  conn = conn_create(cfg, buf, peername);
  bufferevent_setcb(buf, downstream_read_cb, NULL, downstream_connect_cb, conn);
  bufferevent_enable(buf, EV_READ|EV_WRITE);
  return conn;
}

conn_t *
conn_create_outbound_socks(config_t *cfg, struct bufferevent *buf,
                           int af, const char *host, int port)
{
  conn_t *conn;
  struct evdns_base *dns = get_evdns_base();

  log_info("Trying to connect to %s:%u", host, port);
  if (bufferevent_socket_connect_hostname(buf, dns, af, host, port) < 0) {
    log_warn("Connection to %s:%d failed: %s", host, port,
             evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    return NULL;
  }

  /* we don't know the peername yet */
  conn = conn_create(cfg, buf, NULL);
  bufferevent_setcb(buf, downstream_read_cb, NULL, downstream_socks_connect_cb,
                    conn);
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
