/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef NETWORK_H
#define NETWORK_H

/* returns 1 on success, 0 on failure */
int listener_open(struct event_base *base, config_t *cfg);
void listener_close_all(void);

/* circuit / connection low-level routines that need access to
   bufferevent callback functions */

int circuit_connect_to_upstream(circuit_t *ckt, struct bufferevent *buf,
                                struct evutil_addrinfo *addr);

conn_t *conn_create_outbound(config_t *cfg, struct bufferevent *buf,
                             struct evutil_addrinfo *addr);
conn_t *conn_create_outbound_socks(config_t *cfg, struct bufferevent *buf,
                                   int af, const char *hostname, int port);

void circuit_do_flush(circuit_t *ckt);
void conn_do_flush(conn_t *conn);

#endif
