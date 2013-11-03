/*
  vmon: This is the sample proxy of libevent addopted to be 
  used as a transparent proxy to test stegotorus

  This example code shows how to write a proxy
  with Libevent's bufferevent layer.

  XXX It's a little ugly and should probably be cleaned up.
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h> //To process command line arguements

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <string>

using namespace std;

#include "util.h"
#include "connections.h"

static double drop_rate = 0; //do not drop anything by default

#include "transparent_proxy.h"

#define MAX_OUTPUT (512*1024)
bool TransparentProxy::trace_packet_data = false;

/** 
  Constructor: starts listening
  
  @param cur_event_base the main event base
  @param downstream_address the address where the proxy listen to, if
                            all connection is going to be deligated
                            it can be left NULL
*/
TransparentProxy::TransparentProxy(event_base* cur_event_base, const string& upstream_address,const string& downstream_port)
  : listener(NULL)
{
  
  if (!(base = cur_event_base)) {
    log_warn("event base isn't initialized yet!");
  }
   
  set_upstream_address(upstream_address);

  //if it is empty or we don't have a event base, then we can't
  //set up a listener, they are going to give us the downstream
  //connection after it gets connected
  if (!downstream_port.empty() && base) {
    memset(&listen_on_addr, 0, sizeof(listen_on_addr));
    int socklen = sizeof(listen_on_addr);
  
    if (evutil_parse_sockaddr_port(optarg,
                                   (struct sockaddr*)&listen_on_addr, &socklen)<0) {
      int p = atoi(downstream_port.c_str());
      struct sockaddr_in *sin = (struct sockaddr_in*)&listen_on_addr;
           
      assert(!(p < 1 || p > 65535));

      sin->sin_port = htons(p);
      sin->sin_addr.s_addr = htonl(0x7f000001);
      sin->sin_family = AF_INET;
      socklen = sizeof(struct sockaddr_in);
    }

    listener = evconnlistener_new_bind(base, accept_cb, NULL,
                                       LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
                                       -1, (struct sockaddr*)&listen_on_addr, sizeof(listen_on_addr));

  }

}
void
TransparentProxy::readcb(struct bufferevent *bev, void *ctx)
{
  struct bufferevent *partner = (bufferevent *)ctx;
  struct evbuffer *src, *dst;
  size_t len;
  (void)ctx; //to avoid Werror: unused

  src = bufferevent_get_input(bev);
  len = evbuffer_get_length(src);

  // char* data_4_log =  new char[len + 1];
  // evbuffer_copyout(src, data_4_log, len);
  // data_4_log[len] = '\0';
  // log_debug("Data received: %s",  data_4_log);

  if ((!partner) || ((drop_rate != 0) && ((double)rand()/RAND_MAX < drop_rate)))
  {
    //indicating that we have dropped the packet
    log_debug("#");

    evbuffer_drain(src, len);
    return;
  }

  //indicating that we have passed the packet
  log_debug(".");

  dst = bufferevent_get_output(partner);
  evbuffer_add_buffer(dst, src);

  if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
    /* We're giving the other side data faster than it can
     * pass it on.  Stop reading here until we have drained the
     * other side to MAX_OUTPUT/2 bytes. */
    bufferevent_setcb(partner, readcb, drained_writecb,
                      eventcb, bev);
    bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2,
                             MAX_OUTPUT);
    bufferevent_disable(bev, EV_READ);
  }
}

void
TransparentProxy::drained_writecb(struct bufferevent *bev, void *ctx)
{
  struct bufferevent *partner = (bufferevent *)ctx;

  /* We were choking the other side until we drained our outbuf a bit.
   * Now it seems drained. */
  bufferevent_setcb(bev, readcb, NULL, eventcb, partner);
  bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
  if (partner)
    bufferevent_enable(partner, EV_READ);
}

void
TransparentProxy::close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
  struct evbuffer *b = bufferevent_get_output(bev);
  (void)ctx; //to avoid Werror: unused

  if (evbuffer_get_length(b) == 0) {
    bufferevent_free(bev);
  }
}

void
TransparentProxy::eventcb(struct bufferevent *bev, short what, void *ctx)
{
  struct bufferevent *partner = (bufferevent *)ctx;

  if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
    if (what & BEV_EVENT_ERROR)
        fprintf(stderr,
                "proxy error: %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));

    if (partner) {
      /* Flush all pending data */
      readcb(bev, ctx);
      
      if (evbuffer_get_length(bufferevent_get_output(partner))) {
        if (trace_packet_data) {
          size_t buffer_size = evbuffer_get_length(bufferevent_get_input(partner));
          char* debug_buf = new char[buffer_size+1];
          evbuffer_copyout(bufferevent_get_input(partner), (void*) debug_buf, sizeof(char)* buffer_size);
          debug_buf[buffer_size] = '\0';
          fprintf(stderr, "Received: %s\n", debug_buf);
        }
        /* We still have to flush data from the other
         * side, but when that's done, close the other
         * side. */
        bufferevent_setcb(partner,
                          NULL, close_on_finished_writecb,
                          eventcb, NULL);
        bufferevent_disable(partner, EV_READ);
      } else {
        /* We have nothing left to say to the other
         * side; close it. */
        bufferevent_free(partner);
      }
    }
    bufferevent_free(bev);
  }
}

void
TransparentProxy::accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p)
{
  struct bufferevent *b_out, *b_in;
  /* Create two linked bufferevent objects: one to connect, one for the
   * new connection */
  (void)listener; //to avoid Werror: unused
  (void)a;
  (void)slen;
  TransparentProxy* cur_circuit = (TransparentProxy*)p;

  b_in = bufferevent_socket_new(cur_circuit->base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

  b_out = bufferevent_socket_new(cur_circuit->base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

  assert(b_in && b_out);

  if (bufferevent_socket_connect(b_out, (struct sockaddr*)&cur_circuit->connect_to_addr, 
                                 cur_circuit->connect_to_addrlen)<0) {
    log_warn("bufferevent_socket_connect");
    bufferevent_free(b_out);
    bufferevent_free(b_in);
    return;
  }

  bufferevent_setcb(b_in, readcb, NULL, eventcb, b_out);
  bufferevent_setcb(b_out, readcb, NULL, eventcb, b_in);

  bufferevent_enable(b_in, EV_READ|EV_WRITE);
  bufferevent_enable(b_out, EV_READ|EV_WRITE);
}

void TransparentProxy::transparentize_connection(conn_t* conn_in, uint8_t* apriori_data, size_t apriori_data_length)
{
  assert(conn_in->buffer);
  struct bufferevent *b_out, *b_in = conn_in->buffer;
  /* Create two linked bufferevent objects: one to connect, one for the
   * new connection */

  /*b_in = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);*/

  base = bufferevent_get_base(conn_in->buffer);
  if (!base)
    log_abort("sorry, can not transparentize a connection without event base.");

  b_out = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

  assert(b_in && b_out);

  //TODO:we need to deal with this if it is blocking (or not)
  if (bufferevent_socket_connect(b_out, (struct sockaddr*)&connect_to_addr, 
                                 connect_to_addrlen)<0) {
    log_warn("bufferevent_socket_connect");
    bufferevent_free(b_out);
    bufferevent_free(b_in);
    return;
  }

  bufferevent_setcb(b_in, readcb, NULL, eventcb, b_out);
  bufferevent_setcb(b_out, readcb, NULL, eventcb, b_in);

  bufferevent_enable(b_in, EV_READ|EV_WRITE);
  bufferevent_enable(b_out, EV_READ|EV_WRITE);

  //we need to call the readcb in case there is already data in 
  //in the buffer.
  //readcb(b_in, b_out);
  evbuffer* dst = bufferevent_get_output(b_out);
  evbuffer_add(dst, apriori_data, apriori_data_length);

  if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
    /* We're giving the other side data faster than it can
     * pass it on.  Stop reading here until we have drained the
     * other side to MAX_OUTPUT/2 bytes. */
    bufferevent_setcb(b_out, readcb, drained_writecb,
                      eventcb, b_in);
    bufferevent_setwatermark(b_out, EV_WRITE, MAX_OUTPUT/2,
                             MAX_OUTPUT);
    bufferevent_disable(b_in, EV_READ);
  }

}


