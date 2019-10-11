/* Copyright 2013, Tor Project Inc.
 * See LICENSE for other credits and copying information
 *
 * AUTHOR:
 *    Vmon (vmon@riseup.net): August 2013: initial version
 *  
 */

#ifndef TRANSPARENT_PROXY_H
#define TRANSPARENT_PROXY_H

#include <iostream>
#include <unordered_map>
#include <assert.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include "connections.h"
#include "protocol.h"

class TransparentProxy
{
protected:
  static bool trace_packet_data;
  struct sockaddr_storage connect_to_addr;
  int connect_to_addrlen;
  struct event_base *base;
  struct sockaddr_storage listen_on_addr;
  struct evconnlistener *listener;

  static std::unordered_map<bufferevent *, conn_t*> transparentized_connections; //we need to keep track of these connections
  //to close them approperiately

  //based on the fact if the connection was given to us or we have
  //create it we either close it or free it
  static void free_or_close(struct bufferevent *bev) {
    if (transparentized_connections.find(bev) == transparentized_connections.end())
      bufferevent_free(bev);
    else {
      transparentized_connections[bev]->close();
      transparentized_connections.erase(bev);
    }
  }
    
public:
  static void drained_writecb(struct bufferevent *bev, void *ctx);
  static void eventcb(struct bufferevent *bev, short what, void *ctx);
  static void close_on_finished_writecb(struct bufferevent *bev, void *ctx);

  static void readcb(struct bufferevent *bev, void *ctx);

  static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
            struct sockaddr *a, int slen, void *p);

  /**
     This will receive a chop_conn that failed/ignored to handshake
     and turn it into a transparent circuit to the cover server, hence
     it acts similar to accept_cb except that the downstream connection
     is already established.
   */
  void transparentize_connection(conn_t* conn_in, uint8_t* apriori_data, size_t apriori_data_length);

  void set_upstream_address(const std::string& upstream_address)
  {
    memset(&connect_to_addr, 0, sizeof(connect_to_addr));
    connect_to_addrlen = sizeof(connect_to_addr);
    assert(evutil_parse_sockaddr_port(upstream_address.c_str(),
                                      (struct sockaddr*)&connect_to_addr, &connect_to_addrlen)>=0);
  }

  /**
    Constructor: starts listening

    @param cur_event_base the main event base
    @param downstream_port the address where the proxy listen to, if
                           all connection is going to be deligated
                           it can be given as ""

  */
  TransparentProxy(event_base* cur_event_base, const std::string& upstream_address,const std::string& downstream_port = "");

  /**
     Destructor: dismantle the events
  */
  ~TransparentProxy()
  {
    if (listener)
      evconnlistener_free(listener);
  }

};

#endif //TRANSPARENT_PROXY_H
