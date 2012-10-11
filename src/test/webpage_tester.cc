/* Copyright 2011 SRI International
 * See ICENSE for other credits and copying information
 */

#include "util.h"

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include <errno.h>
#include <iostream>
#include <sstream>

#include "curl_util.h"

using namespace std;

#ifdef _WIN32
# undef near
# undef far
# define ENOTCONN WSAENOTCONN
#endif

/** 
   This program is used by the integration test harness.  It opens one
   listening socket (the "far" socket) and one outbound connection
   (the "near" socket).  Then it requests web pages whose url is given 
   by standard input using curl, on the near socket, the far socket 
   receives the request and request  it (using curl) from the server. 
   Then it store the result in fartext and  write the result in the the
   far socket. Finally the program receives the result in the near socket
   and store in neartext.
   At the end the program compare the near and far text.

   The program operate in two mode.

   Mode 1: The program open the socket and hand them to curl.
   Mode 2: The program set the socket as SOCKS proxy in curl.

   because it's curl who listen on near socket we do not need
   to get involved with that in bufferevent level. But also
   we need none-blocking so let the far also progress, then
   we need fifo approach.
*/

//#define TL_TIMEOUT 0
//#define LOGGING false
class WebpageFetcher
{
  struct bufferevent *near;
  struct bufferevent *far;
  struct evbuffer *neartext;
  struct evbuffer *fartext;

  CURLM* _curl_multi_handle; //we need the multi so we have none
  //blocking curl
  CURL* curl_near;
  CURL* curl_far; //far doesn't need to be non-blocking

  struct evbuffer *neartrans;
  struct evbuffer *fartrans;
  string url;

  char* http_request;
  
  char *lbuf;
  size_t lbufsize;

  struct evconnlistener *listener;
  struct event *pause_timer;
  struct event *timeout_timer; 
  //stop the program in case of communication
  //error
  struct event_base *base;

  bool rcvd_eof_near : 1;
  bool rcvd_eof_far  : 1;
  bool sent_eof_near : 1;
  bool sent_eof_far  : 1;
  bool script_eof    : 1;
  bool saw_error     : 1;

  static send_curl();
  static recv_curl();

  bool fetch_page();
  bool fetch_direct_socket();
bool fetch_throug_st();
  
};

/*
  This function needs to be called twice to setup the near and the
  far handles
**/
bool init_easy_set_socket(CURL* cur_curl_handle,  bufferevent bufferside)
{
  //setting up near handle to be a part of multi handle
  cur_curl_handle  = curl_easy_init();
  if (!cur_curl_handle) {
    fprintf(stderr, "failed to initiate curl");
    return false;
  }
  
  curl_easy_setopt(cur_curl_handle, CURLOPT_HEADER, 1L);
  curl_easy_setopt(cur_curl_handle, CURLOPT_HTTP_CONTENT_DECODING, 0L);
  curl_easy_setopt(cur_curl_handle, CURLOPT_HTTP_TRANSFER_DECODING, 0L);
  curl_easy_setopt(cur_curl_handle, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(cur_curl_handle, CURLOPT_WRITEFUNCTION, read_data_cb);

  curl_easy_setopt(cur_curl_handle, CURLOPT_OPENSOCKETFUNCTION, get_conn_socket);
  curl_easy_setopt(cur_curl_handle, CURLOPT_OPENSOCKETDATA, bufferside);

  //tells curl the socket is already connected
  curl_easy_setopt(cur_curl_handle, CURLOPT_SOCKOPTFUNCTION, sockopt_callback);
  curl_easy_setopt(cur_curl_handle, CURLOPT_CLOSESOCKETFUNCTION, ignore_close);
}

curl_socket_t get_conn_socket(void *bufferside,
                                curlsocktype purpose,
                                struct curl_sockaddr *address)
{
  (void)purpose;
  //We just igonre the address because the connection has been established
  //before hand.
  (void)address;
  curl_socket_t conn_sock = (curl_socket_t)bufferevent_getfd(bufferside);//In case Zack doesn't like the idea of adding function to conn_t: (curl_socket_t)(bufferevent_getfd(((conn_t*)conn)->buffer));
  return conn_sock;
}


size_t
curl_read_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  if (LOGGING) 
    fprintf(stderr, "received %lu bytes", size * nmemb);

  return evbuffer_add((evbuffer*)userdata, ptr, size * nmemb);
}

bool fetch_page(CURL* curl_easy_handle, evbuffer* webpage)
{

  curl_easy_setopt(curl_easy_handle, CURLOPT_WRITEDATA, &webpage);
  curl_easy_setopt(curl_easy_handle, CURLOPT_URL, url);

  return (curl_easy_perform(curl_easy_handle) == CURLE_OK);
  
}

bool fetch_page_direct(evbuffer* webpage)
{
  CURL* curl_easy_handle = curl_easy_init();
  if (!curl_easy_handle){
    fprintf(stderr, "failed to initiate curl");
    return false;
  }
  
  return fetch_page(curl_easy_handle, webpage);

}

bool fetch_throug_st(evbuffer* webpage)
{
  CURL* curl_easy_handle = curl_easy_init();
  if (!curl_easy_handle){
    fprintf(stderr, "failed to initiate curl");
    return false;
  }

  //forcing to use the socket attached to stegotorus client
  curl_easy_setopt(curl_easy_handle, CURLOPT_OPENSOCKETFUNCTION, get_conn_socket);
  curl_easy_setopt(curl_easy_handle, CURLOPT_OPENSOCKETDATA, webpage);
  //tells curl the socket is already connected
  curl_easy_setopt(curl_easy_handle, CURLOPT_SOCKOPTFUNCTION, sockopt_callback);

  return fetch_page(curl_easy_handle, webpage);

}

bool fake_proxying_http_request()
{
  evbuffer* webpage_at_far = evbuffer_new();

  fetch_page_direct(bufferevent_get_output(far));

}

/* Helpers */

// static void
// flush_text(WebpageFetcher *st, bool near)
// {
//   struct evbuffer *frombuf, *tobuf;
//   size_t avail;
//   int nseg, i, ll;
//   struct evbuffer_iovec *v;
//   char tag[2] = { '<', ' ' };
//   char nl[1] = { '\n' };

//   if (near) {
//     frombuf = st->neartext;
//     tobuf = st->neartrans;
//   } else {
//     frombuf = st->fartext;
//     tobuf = st->fartrans;
//     tag[0] = '>';
//   }

//   avail = evbuffer_get_length(frombuf);
//   if (avail == 0)
//     return;

//   nseg = evbuffer_peek(frombuf, avail, NULL, NULL, 0);
//   v = (struct evbuffer_iovec *) xzalloc(nseg * sizeof(struct evbuffer_iovec));
//   ll = 0;
//   evbuffer_peek(frombuf, avail, NULL, v, nseg);
//   evbuffer_expand(tobuf, avail + ((avail/64)+1)*3);

//   for (i = 0; i < nseg; i++) {
//     const char *p = (const char *)v[i].iov_base;
//     const char *limit = p + v[i].iov_len;
//     for (; p < limit; p++) {
//       if (ll == 0)
//         evbuffer_add(tobuf, tag, 2);

//       if (*p >= 0x20 && *p <= 0x7E && *p != '\\') {
//         evbuffer_add(tobuf, p, 1);
//         ll++;
//       } else {
//         evbuffer_add_printf(tobuf, "\\x%02x", (uint8_t)*p);
//         ll += 4;
//       }
//       if (ll >= 64) {
//         evbuffer_add(tobuf, nl, 1);
//         ll = 0;
//       }
//     }
//   }
//   free(v);
//   evbuffer_drain(frombuf, avail);
//   if (ll > 0)
//     evbuffer_add(tobuf, nl, 1);
// }

static void
send_eof(WebpageFetcher *st, struct bufferevent *bev)
{
  evutil_socket_t fd = bufferevent_getfd(bev);
  bufferevent_disable(bev, EV_WRITE);
  if (fd == -1)
    return;
  if (shutdown(fd, SHUT_WR) &&
      EVUTIL_SOCKET_ERROR() != ENOTCONN) {
    flush_text(st, bev == st->near);
    evbuffer_add_printf(bev == st->near ? st->neartrans : st->fartrans,
                        "%c W sending EOF: %s\n",
                        bev == st->near ? '{' : '}',
                        evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
  }
}

static void
send_squelch(WebpageFetcher *st, struct bufferevent *bev)
{
  evutil_socket_t fd = bufferevent_getfd(bev);
  bufferevent_disable(bev, EV_READ);
  if (fd == -1)
    return;
  if (shutdown(fd, SHUT_RD) &&
      EVUTIL_SOCKET_ERROR() != ENOTCONN) {
    flush_text(st, bev == st->near);
    evbuffer_add_printf(bev == st->near ? st->neartrans : st->fartrans,
                        "%c W sending squelch: %s\n",
                        bev == st->near ? '{' : '}',
                        evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
  }
}

/* Event callbacks */

static void
socket_read_cb(struct bufferevent *bev, void *arg)
{
  WebpageFetcher *st = (WebpageFetcher *)arg;
  /* print out the data for the sake of debug */
  /* first we need the size of the buffer */
  if (LOGGING)
    {
      size_t buffer_size = evbuffer_get_length(bufferevent_get_input(bev));
      char* debug_buf = new char[buffer_size+1];
      evbuffer_copyout(bufferevent_get_input(bev), (void*) debug_buf, sizeof(char)* buffer_size);
      debug_buf[buffer_size] = '\0';
      fprintf(stderr, "Received on %s: %s\n", bev == st->near ? "near" : "far", debug_buf);

    }
  
  evbuffer_add_buffer(bev == st->near ? st->neartext : st->fartext,
                      bufferevent_get_input(bev));
    
}

static void
socket_drain_cb(struct bufferevent *bev, void *arg)
{
  WebpageFetcher *st = (WebpageFetcher *)arg;

  if (evbuffer_get_length(bufferevent_get_output(bev)) > 0)
    return;

  // if ((bev == st->near && st->sent_eof_near) ||
  //     (bev == st->far && st->sent_eof_far)) {
  //   send_eof(st, bev);
  // }

  if (bev == st->near)
    {
      //go to comparison function
    }
  else
    {
      //go to fetching function
    }
}

static void
socket_event_cb(struct bufferevent *bev, short what, void *arg)
{
  WebpageFetcher *st = (WebpageFetcher *)arg;
  bool near = bev == st->near;
  bool reading = (what & BEV_EVENT_READING);
  struct evbuffer *log = near ? st->neartrans : st->fartrans;

  flush_text(st, near);
  what &= ~(BEV_EVENT_READING|BEV_EVENT_WRITING);

  /* EOF, timeout, and error all have the same consequence: we stop
     trying to transmit or receive on that socket, and notify TCP of
     this as well. */
  if (what & (BEV_EVENT_EOF|BEV_EVENT_TIMEOUT|BEV_EVENT_ERROR)) {
    if (what & BEV_EVENT_EOF) {
      what &= ~BEV_EVENT_EOF;
      if (reading)
        {
          evbuffer_add_printf(log, "%c\n", near ? '[' : ']');
          if (LOGGING)
              {
                fprintf(stderr,"%c\n", near ? '[' : ']');
              }
        }
      else
        evbuffer_add_printf(log, "%c S\n", near ? '{' : '}');
    }
    if (what & BEV_EVENT_ERROR) {
      what &= ~BEV_EVENT_ERROR;
      evbuffer_add_printf(log, "%c %c %s\n",
                          near ? '{' : '}', reading ? 'R' : 'W',
                          evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    }
    if (what & BEV_EVENT_TIMEOUT) {
      what &= ~BEV_EVENT_TIMEOUT;
      evbuffer_add_printf(log, "%c %c --timeout--\n",
                          near ? '{' : '}', reading ? 'R' : 'W');
    }

    if (reading) {
      send_squelch(st, bev);
      if (near)
        st->rcvd_eof_near = true;
      else
        st->rcvd_eof_far = true;
    } else {
      send_eof(st, bev);
      if (near)
        st->sent_eof_near = true;
      else
        st->sent_eof_far = true;
    }
  }

  /* connect is just logged */
  if (what & BEV_EVENT_CONNECTED) {
    what &= ~BEV_EVENT_CONNECTED;
    evbuffer_add_printf(log, "%c\n", near ? '(' : ')');
  }

  /* unrecognized events are also just logged */
  if (what) {
    evbuffer_add_printf(log, "%c %c unrecognized events: %04x\n",
                        near ? '{' : '}', reading ? 'R' : 'W', what);
  }

}

/* Stop the loop print what ever you have */
static void
timeout_cb(evutil_socket_t, short, void *arg)
{
  fprintf(stderr, "Communitation timed out...");
  WebpageFetcher *st = (WebpageFetcher *)arg;

  evutil_socket_t fd = bufferevent_getfd(st->near);
  bufferevent_disable(st->near, EV_WRITE);
  if (fd != -1)
    shutdown(fd, SHUT_WR);

  fd = bufferevent_getfd(st->far);
  bufferevent_disable(st->far, EV_WRITE);
  if (fd != -1)
    shutdown(fd, SHUT_WR);

  event_base_loopexit(st->base, 0);
}

static void
queue_eof(WebpageFetcher *st, bool near)
{
  struct bufferevent *buf;

  if (near) {
    st->sent_eof_near = true;
    buf = st->near;
  } else {
    st->sent_eof_far = true;
    buf = st->far;
  }

  if (evbuffer_get_length(bufferevent_get_output(buf)) == 0)
    send_eof(st, buf);
  /* otherwise, socket_drain_cb will do it */
}

static void
stop_if_finished(WebpageFetcher *st)
{
  if (st->rcvd_eof_near &&
      st->rcvd_eof_far &&
      st->sent_eof_near &&
      st->sent_eof_far &&
      st->script_eof &&
      evbuffer_get_length(bufferevent_get_input(st->near)) == 0 &&
      evbuffer_get_length(bufferevent_get_output(st->near)) == 0 &&
      evbuffer_get_length(bufferevent_get_input(st->far)) == 0 &&
      evbuffer_get_length(bufferevent_get_output(st->far)) == 0)
    event_base_loopexit(st->base, 0);
}

static void
init_sockets_internal(WebpageFetcher *st)
{
  /* The behavior of pair bufferevents is sufficiently unlike the behavior
     of socket bufferevents that we don't want them here. Use the kernel's
     socketpair() instead. */
  evutil_socket_t pair[2];
  int rv;

#ifdef AF_LOCAL
  rv = evutil_socketpair(AF_LOCAL, SOCK_STREAM, 0, pair);
#else
  rv = evutil_socketpair(AF_INET, SOCK_STREAM, 0, pair);
#endif
  if (rv == -1) {
    fprintf(stderr, "socketpair: %s\n",
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    exit(1);
  }

  st->near = bufferevent_socket_new(st->base, pair[0], BEV_OPT_CLOSE_ON_FREE);
  st->far = bufferevent_socket_new(st->base, pair[1], BEV_OPT_CLOSE_ON_FREE);
  if (!st->near || !st->far) {
    fprintf(stderr, "creating socket buffers: %s\n",
            strerror(errno));
    exit(1);
  }
}

static void
init_sockets_external(WebpageFetcher *st, const char *near, const char *far)
{
  /* We don't bother using libevent's async connection logic for this,
     because we have nothing else to do while waiting for the
     connections to happen, so we might as well just block in
     connect() and accept().  [XXX It's possible that we will need to
     change this in order to work correctly on Windows; libevent has
     substantial coping-with-Winsock logic that *may* be needed here.]
     However, take note of the order of operations: create both
     sockets, bind the listening socket, *then* call connect(), *then*
     accept().  The code under test triggers outbound connections when
     it receives inbound connections, so any other order will either
     fail or deadlock. */
  evutil_socket_t nearfd, farfd, listenfd;

  struct evutil_addrinfo *near_addr =
    resolve_address_port(near, 1, 0, "5000");
  struct evutil_addrinfo *far_addr =
    resolve_address_port(far, 1, 1, "5001");

  if (!near_addr || !far_addr)
    exit(2); /* diagnostic already printed */

  nearfd = socket(near_addr->ai_addr->sa_family, SOCK_STREAM, 0);
  if (!nearfd) {
    fprintf(stderr, "socket(%s): %s\n", near,
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    exit(1);
  }
  listenfd = socket(far_addr->ai_addr->sa_family, SOCK_STREAM, 0);
  if (!listenfd) {
    fprintf(stderr, "socket(%s): %s\n", far,
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    exit(1);
  }

  if (evutil_make_listen_socket_reuseable(listenfd)) {
    fprintf(stderr, "setsockopt(%s, SO_REUSEADDR): %s\n", far,
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    exit(1);
  }
  if (bind(listenfd, far_addr->ai_addr, far_addr->ai_addrlen)) {
    fprintf(stderr, "bind(%s): %s\n", far,
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    exit(1);
  }
  if (listen(listenfd, 1)) {
    fprintf(stderr, "listen(%s): %s\n", far,
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    exit(1);
  }

  if (connect(nearfd, near_addr->ai_addr, near_addr->ai_addrlen)) {
    fprintf(stderr, "connect(%s): %s\n", near,
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    exit(1);
  }

  farfd = accept(listenfd, NULL, NULL);
  if (farfd == -1) {
    fprintf(stderr, "accept(%s): %s\n", far,
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    exit(1);
  }

  /* Done listening now. */
  evutil_closesocket(listenfd);
  evutil_freeaddrinfo(near_addr);
  evutil_freeaddrinfo(far_addr);

  /* Now we're all hooked up, switch to nonblocking mode and
     create bufferevents. */
  if (evutil_make_socket_nonblocking(nearfd) ||
      evutil_make_socket_nonblocking(farfd)) {
    fprintf(stderr, "setsockopt(SO_NONBLOCK): %s\n",
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    exit(1);
  }
  st->near = bufferevent_socket_new(st->base, nearfd, BEV_OPT_CLOSE_ON_FREE);
  st->far = bufferevent_socket_new(st->base, farfd, BEV_OPT_CLOSE_ON_FREE);
  if (!st->near || !st->far) {
    fprintf(stderr, "creating socket buffers: %s\n",
            strerror(errno));
    exit(1);
  }
}

static void fetch_page(WebpageFetcher *st)
{
  
}

/**

   After openning the socket we need to initiate our
   curl handles and give them the sockets
 */
bool init_curl_handles(WebpageFetcher *st)
{
  if (!(st->_curl_multi_handle = curl_multi_init())) {
    fprintf(stderr, "failed to initiate curl multi object.");
    return false;
  }

  init_easy_set_callback(st->near);
  init_easy_set_callback(st->far);

}

int
main(int argc, char **argv)
{
  WebpageFetcher st;
  memset(&st, 0, sizeof(WebpageFetcher));

  if (argc != 1 && argc != 3) {
    char *name = strrchr(argv[0], '/');
    name = name ? name+1 : argv[0];
    fprintf(stderr, "usage: %s [near-addr far-addr]\n", name);
    return 2;
  }

  cin >> st.url;

  st.base = event_base_new();
  st.neartext = evbuffer_new();
  st.neartrans = evbuffer_new();
  st.fartext = evbuffer_new();
  st.fartrans = evbuffer_new();

  if (!st.base || !st.neartext || !st.neartrans ||
      !st.fartext || !st.fartrans) {
    fprintf(stderr, "creating event base and buffers: %s\n", strerror(errno));
    return 1;
  }
  st.pause_timer = evtimer_new(st.base, pause_expired_cb, &st);
  st.timeout_timer = evtimer_new(st.base, timeout_cb, &st); //to end the 
  //program in the case of communication  problem
  if (!st.pause_timer || !st.timeout_timer) {
    fprintf(stderr, "creating pause timer or timeout timer: %s\n", strerror(errno));
    return 1;
  }

  if (TL_TIMEOUT)
    {
      struct timeval tv;
      tv.tv_sec = TL_TIMEOUT;
      tv.tv_usec = 0;
      evtimer_add(st.timeout_timer, &tv);

    }

  if (argc == 1)
    init_sockets_internal(&st);
  else
    init_sockets_external(&st, argv[1], argv[2]);

  bufferevent_setcb(st.near,
                    socket_read_cb, socket_drain_cb, socket_event_cb, &st);
  bufferevent_setcb(st.far,
                    socket_read_cb, socket_drain_cb, socket_event_cb, &st);
  //bufferevent_enable(st.near, EV_READ|EV_WRITE); libcurl will listen on near
  bufferevent_enable(st.far, EV_READ|EV_WRITE);

  init_curl_handles(st);

  if (!st.fetch_page_through_st(st))
     {
       fprintf(stderr, "Error in fetching web page directly.");
       return -1;
     }

  event_base_dispatch(st.base);

  /*flush_text(&st, true);
  flush_text(&st, false);
  fflush(st.transcript);
  if (evbuffer_write(st.neartrans, fileno(st.transcript)) < 0 ||
      evbuffer_write(st.fartrans, fileno(st.transcript)) < 0) {
    fprintf(stderr, "writing transcript: %s\n", strerror(errno));
    st.saw_error = true;
    }*/

  bufferevent_free(st.near);
  bufferevent_free(st.far);
  event_free(st.pause_timer);
  evbuffer_free(st.neartext);
  evbuffer_free(st.neartrans);
  evbuffer_free(st.fartext);
  evbuffer_free(st.fartrans);
  event_base_free(st.base);
  free(st.lbuf);

  //more clean up
  curl_multi_cleanup(st._curl_multi_handle);

  return st.saw_error;
}
