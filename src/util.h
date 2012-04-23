/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef UTIL_H
#define UTIL_H

#include "config.h"

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS
#include <limits.h>
#include <stdarg.h> /* va_list */
#include <stddef.h> /* size_t, ptrdiff_t, offsetof, NULL */
#include <stdint.h> /* intN_t, uintN_t */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <new>

#include <event2/util.h> /* evutil_addrinfo */

#ifdef _WIN32
#include <ws2tcpip.h> /* addrinfo (event2/util.h should do this,
                         but it doesn't) */

#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND
#endif

/* event2/util.h finds ssize_t but refuses to actually call it ssize_t.
   Correct this. */
#ifdef _EVENT_ssize_t
#undef ssize_t
#define ssize_t _EVENT_ssize_t
#endif

struct bufferevent;
struct evbuffer;
struct evconnlistener;
struct evdns_base;
struct event_base;

/***** Type annotations. *****/

#ifndef __GNUC__
#define __attribute__(x) /* nothing */
#endif
#define ATTR_MALLOC   __attribute__((malloc))
#define ATTR_NORETURN __attribute__((noreturn))
#define ATTR_NOTHROW  __attribute__((nothrow))
#define ATTR_PRINTF_1 __attribute__((format(printf, 1, 2)))
#define ATTR_PRINTF_2 __attribute__((format(printf, 2, 3)))
#define ATTR_PRINTF_3 __attribute__((format(printf, 3, 4)))
#define ATTR_PURE     __attribute__((pure))

/***** Memory allocation. *****/

/** Any size_t larger than this amount is likely to be an underflow. */
#define SIZE_T_CEILING  (SIZE_MAX/2 - 16)

/* Because this isn't Tor and functions named "tor_whatever" would be
   confusing, I am instead following the GNU convention of naming
   allocate-memory-or-crash functions "xwhatever". Also, at this time
   I do not see a need for a free() wrapper. */

void *xmalloc(size_t size) ATTR_MALLOC ATTR_NOTHROW; /* does not clear memory */
void *xzalloc(size_t size) ATTR_MALLOC ATTR_NOTHROW; /* clears memory */
void *xrealloc(void *ptr, size_t size) ATTR_NOTHROW;
void *xmemdup(const void *ptr, size_t size) ATTR_MALLOC ATTR_NOTHROW;
char *xstrdup(const char *s) ATTR_MALLOC ATTR_NOTHROW;
char *xstrndup(const char *s, size_t maxsize) ATTR_MALLOC ATTR_NOTHROW;

/* Global operator new forwards to xzalloc (therefore, global operator
   delete must forward to free). Clearing everything on allocation may
   become unnecessary in the future, but for now it's good defensiveness. */

inline void *operator new(size_t n)
{ return xzalloc(n); }
inline void *operator new[](size_t n)
{ return xzalloc(n); }
inline void operator delete(void *p)
{ free(p); }
inline void operator delete[](void *p)
{ free(p); }
inline void* operator new(size_t n, const std::nothrow_t &)
{ return xzalloc(n); }
inline void* operator new[](size_t n, const std::nothrow_t &)
{ return xzalloc(n); }
inline void operator delete(void *p, const std::nothrow_t &)
{ free(p); }
inline void operator delete[](void *p, const std::nothrow_t &)
{ free(p); }

/***** Pseudo-inheritance. *****/

#define DOWNCAST(container_type, element, ptr) \
  (container_type*)( ((char*)ptr) - offsetof(container_type, element) )

/***** Math. *****/

unsigned int ui64_log2(uint64_t u64) ATTR_NOTHROW;

/***** Network types and functions. *****/

struct circuit_t;
struct config_t;
struct conn_t;
struct rng_t;
struct socks_state_t;
struct steg_t;

enum listen_mode {
  LSN_SIMPLE_CLIENT = 1,
  LSN_SIMPLE_SERVER,
  LSN_SOCKS_CLIENT
};

struct evutil_addrinfo *resolve_address_port(const char *address,
                                             int nodns, int passive,
                                             const char *default_port);

/** Produce a printable name for this sockaddr.  The result is in
    malloced memory. */
char *printable_address(struct sockaddr *addr, socklen_t addrlen);

struct evdns_base *get_evdns_base(void);
int init_evdns_base(struct event_base *base);

/***** String functions. *****/

static inline int ascii_isspace(unsigned char c)
{
  return (c == ' ' ||
          c == '\t' ||
          c == '\r' ||
          c == '\n' ||
          c == '\v' ||
          c == '\f');
}

static inline int ascii_isxdigit(unsigned char c)
{
  return (('0' <= c && c <= '9') ||
          ('A' <= c && c <= 'F') ||
          ('a' <= c && c <= 'f'));
}

void ascii_strstrip(char *s, const char *kill);
void ascii_strlower(char *s);

int xvsnprintf(char *str, size_t size, const char *format, va_list args);
int xsnprintf(char *str, size_t size, const char *format, ...)
  ATTR_PRINTF_3;

size_t xgetline(char **lineptr, size_t *nptr, FILE *stream);

/***** Logging. *****/

/** Log destinations */

/** Spit log messages on stderr. */
#define LOG_METHOD_STDERR 1
/** Place log messages in a file. */
#define LOG_METHOD_FILE 2
/** We don't want no logs. */
#define LOG_METHOD_NULL 3

/** Set the log method, and open the logfile 'filename' if appropriate. */
int log_set_method(int method, const char *filename);

/** Set the minimum severity that will be logged.
    'sev_string' may be "warn", "info", or "debug" (case-insensitively). */
int log_set_min_severity(const char* sev_string);

/** Request timestamps on all log messages. */
void log_enable_timestamps();

/** True if debug messages are being logged. Guard expensive debugging
    checks with this, to avoid doing useless work when the messages are
    just going to be thrown away anyway. */
int log_do_debug(void);

/** Close the logfile if it's open.  Ignores errors. */
void log_close(void);

/** The actual log-emitting functions.  There are three families of
    these functions: generic, circuit-related, and
    connection-related. */

/* Note: we are using the C99/C++11 syntax for variadic macros, but
   nonetheless we are only doing them if we know we have GCC, because
   to do otherwise is too much tsuris with the predefined macros.
   Maybe there should be an autoconf test. */
#if  __GNUC__ >= 3

/** Fatal errors: the program cannot continue and will exit. */
void log_abort(const char *fn, const char *format, ...)
  ATTR_PRINTF_2 ATTR_NORETURN ATTR_NOTHROW;
void log_abort(const char *fn, circuit_t *ckt, const char *format, ...)
  ATTR_PRINTF_3 ATTR_NORETURN ATTR_NOTHROW;
void log_abort(const char *fn, conn_t *conn, const char *format, ...)
  ATTR_PRINTF_3 ATTR_NORETURN ATTR_NOTHROW;

/** Warn-level severity: for messages that only appear when something
    has gone wrong. */
void log_warn(const char *fn, const char *format, ...)
  ATTR_PRINTF_2 ATTR_NOTHROW;
void log_warn(const char *fn, circuit_t *ckt, const char *format, ...)
  ATTR_PRINTF_3 ATTR_NOTHROW;
void log_warn(const char *fn, conn_t *conn,const char *format, ...)
  ATTR_PRINTF_3 ATTR_NOTHROW;

/** Info-level severity: for messages that should be sent to the user
    during normal operation. */
void log_info(const char *fn, const char *format, ...)
  ATTR_PRINTF_2 ATTR_NOTHROW;
void log_info(const char *fn, circuit_t *ckt, const char *format, ...)
  ATTR_PRINTF_3 ATTR_NOTHROW;
void log_info(const char *fn, conn_t *conn,const char *format, ...)
  ATTR_PRINTF_3 ATTR_NOTHROW;

/** Debug-level severity: for hyper-verbose messages of no interest to
    anybody but developers. */
void log_debug(const char *fn, const char *format, ...)
  ATTR_PRINTF_2 ATTR_NOTHROW;
void log_debug(const char *fn, circuit_t *ckt, const char *format, ...)
  ATTR_PRINTF_3 ATTR_NOTHROW;
void log_debug(const char *fn, conn_t *conn, const char *format, ...)
  ATTR_PRINTF_3 ATTR_NOTHROW;

#define log_abort(...)     log_abort(__func__, __VA_ARGS__)
#define log_warn(...)      log_warn(__func__, __VA_ARGS__)
#define log_info(...)      log_info(__func__, __VA_ARGS__)
#define log_debug(...)     log_debug(__func__, __VA_ARGS__)

#else
/** Fatal errors: the program cannot continue and will exit. */
void log_abort(const char *format, ...)
  ATTR_PRINTF_1 ATTR_NORETURN ATTR_NOTHROW;
void log_abort(circuit_t *ckt, const char *format, ...)
  ATTR_PRINTF_2 ATTR_NORETURN ATTR_NOTHROW;
void log_abort(conn_t *conn, const char *format, ...)
  ATTR_PRINTF_2 ATTR_NORETURN ATTR_NOTHROW;

/** Warn-level severity: for messages that only appear when something
    has gone wrong. */
void log_warn(const char *format, ...)
  ATTR_PRINTF_1 ATTR_NOTHROW;
void log_warn(circuit_t *ckt, const char *format, ...)
  ATTR_PRINTF_2 ATTR_NOTHROW;
void log_warn(conn_t *conn,const char *format, ...)
  ATTR_PRINTF_2 ATTR_NOTHROW;

/** Info-level severity: for messages that should be sent to the user
    during normal operation. */
void log_info(const char *format, ...)
  ATTR_PRINTF_1 ATTR_NOTHROW;
void log_info(circuit_t *ckt, const char *format, ...)
  ATTR_PRINTF_2 ATTR_NOTHROW;
void log_info(conn_t *conn,const char *format, ...)
  ATTR_PRINTF_2 ATTR_NOTHROW;

/** Debug-level severity: for hyper-verbose messages of no interest to
    anybody but developers. */
void log_debug(const char *format, ...)
  ATTR_PRINTF_1 ATTR_NOTHROW;
void log_debug(circuit_t *ckt, const char *format, ...)
  ATTR_PRINTF_2 ATTR_NOTHROW;
void log_debug(conn_t *conn,const char *format, ...)
  ATTR_PRINTF_2 ATTR_NOTHROW;
#endif

/** Assertion checking.  We don't ever compile assertions out, and we
    want precise control over the error messages, so we use our own
    assertion macro.  */
#define log_assert(expr)                                \
  do {                                                  \
    if (!(expr))                                        \
      log_abort("assertion failure at %s:%d: %s",       \
                __FILE__, __LINE__, #expr);             \
  } while (0)

/***** Time. *****/

/** Compute x - y and store the value result. Returns 1 if the difference is
    negative, and 0 otherwise. **/
int timeval_subtract(struct timeval *x, struct timeval *y,
		     struct timeval *result);

#endif
