/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information. */

#include "util.h"

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/* This program is used by the integration test harness.  It opens one
   listening socket (the "far" socket) and one outbound connection
   (the "near" socket).  Then it writes data to both of them as
   directed by the script on standard input.  Whatever it gets back,
   it records in a similar format and writes to standard output.

   The input script format is very, very simple (since we have to
   parse it in C :) It's line-oriented.  The first character on a
   line is a directive; everything after that on the line is an
   argument to the directive.  Blank lines are ignored.
   Directives are:

   # comment line - note that # _only_ introduces a comment at the beginning
                    of a line; elsewhere, it's either a syntax error or part
                    of an argument

   P number       - pause for |number| milliseconds
   > text         - transmit |text| on the near socket
   < text         - transmit |text| on the far socket
   ]              - signal EOF on the near socket
   [              - signal EOF on the far socket

   It is an error if > appears after ], or < appears after [.  The end
   of the script implicitly supplies whichever of ] and [ have not yet
   appeared.

   The output transcript exchanges the roles of near and far sockets,
   and will never contain P, blank, or comment lines:

   > (text)       - |text| received on the far socket
   < (text)       - |text| received on the near socket
   ]              - EOF received on the far socket
   [              - EOF received on the near socket
   )              - connection established on the far socket
   (              - connection established on the near socket

   It may also contain diagnostic lines:

   } R message    - read error on the far socket
   } W message    - write error on the far socket
   } S            - transmission squelch on the far socket
   { R message    - read error on the near socket
   { W message    - write error on the near socket
   { S            - transmission squelch on the near socket

   The program exits when it reaches the end of the script _and_ has
   received EOFs in both directions from its sockets.

   If a script line is ill-formed or cannot be executed for any
   reason, it is skipped but copied to the transcript, with a ! at the
   beginning of the line.  */

typedef struct tstate
{
  struct bufferevent *near;
  struct bufferevent *far;
  FILE *script;
  FILE *transcript;
  char *lbuf;
  size_t lbufsize;

  struct evconnlistener *listener;
  struct event *pause_timer;
  struct event_base *base;

  bool rcvd_eof_near : 1;
  bool rcvd_eof_far  : 1;
  bool sent_eof_near : 1;
  bool sent_eof_far  : 1;
  bool script_eof    : 1;
  bool saw_error     : 1;
} tstate;

static void script_next_action(tstate *st);

/* Helpers */

static void
write_quoting_unprintables(FILE *fp, const char *p, const char *limit)
{
  for (; p < limit; p++)
    if (*p >= 0x20 && *p <= 0x7E && *p != '\\')
      putc(*p, fp);
    else
      fprintf(fp, "\\x%02x", (unsigned char)*p);
}

static void
send_eof(tstate *st, struct bufferevent *buf)
{
  evutil_socket_t fd = bufferevent_getfd(buf);
  bufferevent_disable(buf, EV_WRITE);
  if (fd == -1)
    return;
  if (shutdown(fd, SHUT_WR))
    fprintf(st->transcript, "%c W sending EOF: %s\n",
            buf == st->near ? '{' : '}',
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
}

static void
send_squelch(tstate *st, struct bufferevent *buf)
{
  evutil_socket_t fd = bufferevent_getfd(buf);
  bufferevent_disable(buf, EV_READ);
  if (fd == -1)
    return;
  if (shutdown(fd, SHUT_RD))
    fprintf(st->transcript, "%c W sending squelch: %s\n",
            buf == st->near ? '{' : '}',
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
}

/* Event callbacks */

static void
socket_read_cb(struct bufferevent *bev, void *arg)
{
  tstate *st = arg;
  struct evbuffer *buf = bufferevent_get_input(bev);
  size_t avail = evbuffer_get_length(buf);
  int nseg = evbuffer_peek(buf, avail, NULL, NULL, 0);
  struct evbuffer_iovec *v = xzalloc(nseg * sizeof(struct evbuffer_iovec));
  int i;

  putc(bev == st->near ? '>' : '<', st->transcript);
  putc(' ', st->transcript);

  nseg = evbuffer_peek(buf, avail, NULL, v, nseg);
  for (i = 0; i < nseg; i++)
    write_quoting_unprintables(st->transcript, v[i].iov_base,
                               v[i].iov_base + v[i].iov_len);
  evbuffer_drain(buf, avail);
  free(v);

  putc('\n', st->transcript);
  script_next_action(st);
}

static void
socket_drain_cb(struct bufferevent *buf, void *arg)
{
  tstate *st = arg;

  if (evbuffer_get_length(bufferevent_get_output(buf)) > 0)
    return;

  if ((buf == st->near && st->sent_eof_near) ||
      (buf == st->far && st->sent_eof_far)) {
    send_eof(st, buf);
  }

  script_next_action(st);
}

static void
socket_event_cb(struct bufferevent *buf, short what, void *arg)
{
  tstate *st = arg;
  bool near = buf == st->near;
  bool reading = (what & BEV_EVENT_READING);

  what &= ~(BEV_EVENT_READING|BEV_EVENT_WRITING);

  /* EOF, timeout, and error all have the same consequence: we stop
     trying to transmit or receive on that socket, and notify TCP of
     this as well. */
  if (what & (BEV_EVENT_EOF|BEV_EVENT_TIMEOUT|BEV_EVENT_ERROR)) {
    if (what & BEV_EVENT_EOF) {
      what &= ~BEV_EVENT_EOF;
      if (reading)
        fprintf(st->transcript, "%c\n", near ? '[' : ']');
      else
        fprintf(st->transcript, "%c S\n", near ? '{' : '}');
    }
    if (what & BEV_EVENT_ERROR) {
      what &= ~BEV_EVENT_ERROR;
      fprintf(st->transcript, "%c %c %s\n",
              near ? '{' : '}', reading ? 'R' : 'W',
              evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    }
    if (what & BEV_EVENT_TIMEOUT) {
      what &= ~BEV_EVENT_TIMEOUT;
      fprintf(st->transcript, "%c %c --timeout--\n",
              near ? '{' : '}', reading ? 'R' : 'W');
    }

    if (reading) {
      send_squelch(st, buf);
      if (near)
        st->rcvd_eof_near = true;
      else
        st->rcvd_eof_far = true;
    } else {
      send_eof(st, buf);
      if (near)
        st->sent_eof_near = true;
      else
        st->sent_eof_far = true;
    }
  }

  /* connect is just logged */
  if (what & BEV_EVENT_CONNECTED) {
    what &= ~BEV_EVENT_CONNECTED;
    fprintf(st->transcript, "%c\n", near ? '(' : ')');
  }

  /* unrecognized events are also just logged */
  if (what) {
    fprintf(st->transcript, "%c %c unrecognized events: %04x\n",
            near ? '{' : '}', reading ? 'R' : 'W', what);
  }

  script_next_action(st);
}

static void
pause_expired_cb(evutil_socket_t fd, short what, void *arg)
{
  tstate *st = arg;
  script_next_action(st);
}

/* Script processing */

static void
queue_text(tstate *st, bool near, const char *p, size_t n)
{
  errno = 0;
  if (evbuffer_add(bufferevent_get_output(near ? st->near : st->far), p, n)) {
    st->saw_error = true;
    fprintf(st->transcript, "%c W evbuffer_add failed", near ? '{' : '}');
    if (errno)
      fprintf(st->transcript, ": %s", strerror(errno));
    putc('\n', st->transcript);
  }
}

static void
queue_eof(tstate *st, bool near)
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
queue_delay(tstate *st, unsigned long milliseconds)
{
  struct timeval tv;
  tv.tv_sec = milliseconds / 1000;
  tv.tv_usec = (milliseconds % 1000) * 1000;
  evtimer_add(st->pause_timer, &tv);
}

static void
stop_if_finished(tstate *st)
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
script_syntax_error(tstate *st, const char *p, size_t n)
{
  st->saw_error = true;

  putc('!', st->transcript);
  putc(' ', st->transcript);
  write_quoting_unprintables(st->transcript, p, p + n);
  putc('\n', st->transcript);
}

static void
script_next_action(tstate *st)
{
  char *line;
  size_t n;

  /* Don't do anything until both send queues have drained, and don't
     do anything if the pause timer is running, either. */
  if (evbuffer_get_length(bufferevent_get_output(st->near)) > 0 ||
      evbuffer_get_length(bufferevent_get_output(st->far)) > 0 ||
      evtimer_pending(st->pause_timer, 0)) {
    return;
  }

  if (st->script_eof) {
    stop_if_finished(st);
    return; /* we're just waiting for EOF near and far */
  }

  for (;;) {
    n = obfs_getline(&st->lbuf, &st->lbufsize, st->script);
    line = st->lbuf;

    if (n == 0) {
      /* EOF or error */
      if (ferror(st->script)) {
        perror("reading from script");
        st->saw_error = true;
      }

      st->script_eof = true;
      if (!st->sent_eof_near)
        queue_eof(st, true);
      if (!st->sent_eof_far)
        queue_eof(st, false);
      return;
    }

    /* Discard comments. */
    if (line[0] == '#')
      continue;

    /* Strip all trailing white space. */
    while (n > 0 &&
           (line[n-1] == '\n' || line[n-1] == ' ' || line[n-1] == '\t'))
      n--;

    /* Discard empty lines. */
    if (n == 0)
      continue;

    if (n == 1) {
      /* Only some directives can validly appear on one-character lines. */
      switch (line[0]) {
      case ']':
        if (!st->sent_eof_near) {
          queue_eof(st, true);
          return;
        }
        break;

      case '[':
        if (!st->sent_eof_far) {
          queue_eof(st, false);
          return;
        }
        break;

      default:
        break;
      }
    }

    /* There are no well-formed two-character lines (after all the
       stripping above). All lines *longer* than two characters must
       have a space character as the second. */
    if (n >= 3 && line[1] == ' ') {
      switch (line[0]) {
      case 'P': {
        char *endptr;
        unsigned long delay = strtoul(line+2, &endptr, 10);
        if (endptr == line+n && delay > 0) {
          queue_delay(st, delay);
          return;
        }
        break;
      }

      case '>':
        if (!st->sent_eof_near) {
          queue_text(st, true, line+2, n-2);
          return;
        }
        break;

      case '<':
        if (!st->sent_eof_far) {
          queue_text(st, false, line+2, n-2);
          return;
        }
        break;

      default:
        break;
      }
    }

    script_syntax_error(st, line, n);
  }
}

static void
init_sockets_internal(tstate *st)
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
init_sockets_external(tstate *st, const char *near, const char *far)
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

int
main(int argc, char **argv)
{
  tstate st;
  memset(&st, 0, sizeof(tstate));

  if (argc != 1 && argc != 3) {
    char *name = strrchr(argv[0], '/');
    name = name ? name+1 : argv[0];
    fprintf(stderr, "usage: %s [near-addr far-addr]\n", name);
    return 2;
  }

  st.script = stdin;
  st.transcript = stdout;
  st.base = event_base_new();
  if (!st.base) {
    fprintf(stderr, "creating event_base: %s\n", strerror(errno));
    return 1;
  }
  st.pause_timer = evtimer_new(st.base, pause_expired_cb, &st);
  if (!st.pause_timer) {
    fprintf(stderr, "creating pause timer: %s\n", strerror(errno));
    return 1;
  }

  if (argc == 1)
    init_sockets_internal(&st);
  else
    init_sockets_external(&st, argv[1], argv[2]);

  bufferevent_setcb(st.near,
                    socket_read_cb, socket_drain_cb, socket_event_cb, &st);
  bufferevent_setcb(st.far,
                    socket_read_cb, socket_drain_cb, socket_event_cb, &st);
  bufferevent_enable(st.near, EV_READ|EV_WRITE);
  bufferevent_enable(st.far, EV_READ|EV_WRITE);

  script_next_action(&st);
  event_base_dispatch(st.base);

  bufferevent_free(st.near);
  bufferevent_free(st.far);
  event_free(st.pause_timer);
  event_base_free(st.base);
  free(st.lbuf);

  return st.saw_error;
}
