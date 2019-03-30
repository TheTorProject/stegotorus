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

#ifdef _WIN32
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

const char* program_name;

static struct event_base *base;
static struct sockaddr_storage listen_on_addr;
static struct sockaddr_storage connect_to_addr;
static double drop_rate = 0; //do not drop anything by default
static int connect_to_addrlen;

#define LOGGING_OFF 0
#define LOGGING_MODERATE 1
#define LOGGING_SEVERE 2
#define MAX_OUTPUT (512*1024)
#define LOGGING LOGGING_MODERATE

static void drained_writecb(struct bufferevent *bev, void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);

static void
readcb(struct bufferevent *bev, void *ctx)
{
  struct bufferevent *partner = (bufferevent *)ctx;
  struct evbuffer *src, *dst;
  size_t len;
  (void)ctx; //to avoid Werror: unused

  src = bufferevent_get_input(bev);
  len = evbuffer_get_length(src);

  char* data_4_log =  new char[len + 1];
  evbuffer_copyout(src, data_4_log, len);
  data_4_log[len] = '\0';
  fprintf(stderr,"Data received: %s\n",  data_4_log);

  if ((!partner) || ((drop_rate != 0) && ((double)rand()/RAND_MAX < drop_rate)))
  {
    if (LOGGING >= LOGGING_MODERATE) 
      //indicating that we have dropped the packet
      fprintf(stderr, "#");

    evbuffer_drain(src, len);
    return;
  }

  if (LOGGING >= LOGGING_MODERATE) 
    //indicating that we have passed the packet
    fprintf(stderr, ".");

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

static void
drained_writecb(struct bufferevent *bev, void *ctx)
{
  struct bufferevent *partner = (bufferevent *)ctx;

  /* We were choking the other side until we drained our outbuf a bit.
   * Now it seems drained. */
  bufferevent_setcb(bev, readcb, NULL, eventcb, partner);
  bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
  if (partner)
    bufferevent_enable(partner, EV_READ);
}

static void
close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
  struct evbuffer *b = bufferevent_get_output(bev);
  (void)ctx; //to avoid Werror: unused

  if (evbuffer_get_length(b) == 0) {
    bufferevent_free(bev);
  }
}

static void
eventcb(struct bufferevent *bev, short what, void *ctx)
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
        if (LOGGING > LOGGING_SEVERE){
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

/* print usage information and exit the progam with code 1 */
static void
syntax(int exit_code)
{
  fprintf(stderr, "Usage:  %s options <listen-on-addr> <connect-to-addr>\n", program_name);
  fputs("  -d  --drop-rate rate       The 0 <= rate <= 1, it drops the incomming traffic\n", stderr);
  fputs("                             i.e. read_cb drain the buffer and discards data.\n", stderr);
  fputs("  -h  --help                 Display this usage information.\n", stderr);
  fputs("Example:\n", stderr);
  fputs("   tester-proxy 127.0.0.1:8888 1.2.3.4:80\n", stderr);

  exit(exit_code);
}

static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p)
{
  struct bufferevent *b_out, *b_in;
  /* Create two linked bufferevent objects: one to connect, one for the
   * new connection */
  (void)listener; //to avoid Werror: unused
  (void)a;
  (void)slen;
  (void)p;

  b_in = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

  b_out = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

  assert(b_in && b_out);

  if (bufferevent_socket_connect(b_out, (struct sockaddr*)&connect_to_addr, 
                                 connect_to_addrlen)<0) {
    perror("bufferevent_socket_connect");
    bufferevent_free(b_out);
    bufferevent_free(b_in);
    return;
  }

  bufferevent_setcb(b_in, readcb, NULL, eventcb, b_out);
  bufferevent_setcb(b_out, readcb, NULL, eventcb, b_in);

  bufferevent_enable(b_in, EV_READ|EV_WRITE);
  bufferevent_enable(b_out, EV_READ|EV_WRITE);
}

/* read the command line argument and set the variable accordingly 
  exits with 1 if anything goes wrong*/
void read_options(int argc, char* argv[])
{
  //A string representigshort opt letters 
  const char* short_options = "-d:";
  //long options
  const option long_options[] = {
    { "drop-rate", 1, NULL, 'd'},
    { "help", 1, NULL, 'h'}
  };

  unsigned int cur_side = 0;

  program_name = argv[0];

  int next_option;
  do {
    next_option = getopt_long(argc, argv, short_options, long_options, NULL);
    
    switch (next_option) {
      case 'h':
        syntax(0);
        break;
      
      case 'd':
        drop_rate = strtod(optarg, NULL);
        break;

      case 1:
        switch (cur_side) {
          case 0:
            {
              memset(&listen_on_addr, 0, sizeof(listen_on_addr));
              int socklen = sizeof(listen_on_addr);

              if (evutil_parse_sockaddr_port(optarg,
                                 (struct sockaddr*)&listen_on_addr, &socklen)<0) {
                int p = atoi(optarg);
                struct sockaddr_in *sin = (struct sockaddr_in*)&listen_on_addr;
           
                if (p < 1 || p > 65535)
                  syntax(1);
                sin->sin_port = htons(p);
                sin->sin_addr.s_addr = htonl(0x7f000001);
                sin->sin_family = AF_INET;
                socklen = sizeof(struct sockaddr_in);
              }
              break;
            }
         
         case 1:
           memset(&connect_to_addr, 0, sizeof(connect_to_addr));
           connect_to_addrlen = sizeof(connect_to_addr);
           if (evutil_parse_sockaddr_port(optarg,
                                          (struct sockaddr*)&connect_to_addr, &connect_to_addrlen)<0)
             syntax(1);
           
           break;

         default: //too many paramerters. We only need two sides
           syntax(1);
        }

        cur_side++;
        break;

      case '?': //unknown option
        syntax(1);
        
      case -1: //done with the options
        break;

      default: //Something is wrong
        abort();
      
    }
  }while(next_option != -1);
  
  //make sure user has specified both sides
  if (cur_side < 2)
    syntax(1);

}

int
main(int argc, char **argv)
{
 
  struct evconnlistener *listener;
    read_options(argc, argv);
  
  base = event_base_new();
  if (!base) {
    perror("event_base_new()");
    return 1;
  }
    
  listener = evconnlistener_new_bind(base, accept_cb, NULL,
                                     LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
                                     -1, (struct sockaddr*)&listen_on_addr, sizeof(listen_on_addr));
  
  event_base_dispatch(base);
  
  evconnlistener_free(listener);
  event_base_free(base);
  
  return 0;

}
