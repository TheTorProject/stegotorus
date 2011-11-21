/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef UTIL_H
#define UTIL_H

#include "config.h"

#include <limits.h>
#include <stdarg.h> /* va_list */
#include <stddef.h> /* size_t, ptrdiff_t, offsetof, NULL */
#include <stdint.h> /* intN_t, uintN_t */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/util.h> /* evutil_addrinfo */

#ifdef _WIN32
#include <ws2tcpip.h> /* addrinfo (event2/util.h should do this,
                         but it doesn't) */

#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND
#endif

/* event2/util.h finds us a ssize_t but refuses to actually call it
   that. Correct this. */
#ifdef _EVENT_ssize_t
#undef ssize_t
#define ssize_t _EVENT_ssize_t
#endif

#ifdef __cplusplus
extern "C" {
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
#define ATTR_PRINTF_1 __attribute__((format(printf, 1, 2)))
#define ATTR_PRINTF_2 __attribute__((format(printf, 2, 3)))
#define ATTR_PRINTF_3 __attribute__((format(printf, 3, 4)))
#define ATTR_PURE     __attribute__((pure))

/***** Memory allocation. *****/

/* Because this isn't Tor and functions named "tor_whatever" would be
   confusing, I am instead following the GNU convention of naming
   allocate-memory-or-crash functions "xwhatever". Also, at this time
   I do not see a need for a free() wrapper. */

void *xmalloc(size_t size) ATTR_MALLOC; /* does not clear memory */
void *xzalloc(size_t size) ATTR_MALLOC; /* clears memory */
void *xrealloc(void *ptr, size_t size);
void *xmemdup(const void *ptr, size_t size) ATTR_MALLOC;
char *xstrdup(const char *s) ATTR_MALLOC;
char *xstrndup(const char *s, size_t maxsize) ATTR_MALLOC;

/***** Pseudo-inheritance. *****/

#define DOWNCAST(container_type, element, ptr) \
  (container_type*)( ((char*)ptr) - offsetof(container_type, element) )

/***** Math. *****/

unsigned int ui64_log2(uint64_t u64);

/***** Network types and functions. *****/

typedef struct circuit_t circuit_t;
typedef struct config_t config_t;
typedef struct conn_t conn_t;
typedef struct rng_t rng_t;
typedef struct socks_state_t socks_state_t;
typedef struct steg_t steg_t;

typedef struct proto_vtable proto_vtable;
typedef struct steg_vtable steg_vtable;

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

int obfs_vsnprintf(char *str, size_t size,
                   const char *format, va_list args);
int obfs_snprintf(char *str, size_t size,
                  const char *format, ...)
  ATTR_PRINTF_3;

size_t obfs_getline(char **lineptr, size_t *nptr, FILE *stream);

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

/** True if debug messages are being logged. */
int log_do_debug(void);

/** Close the logfile if it's open.  Ignores errors. */
void close_obfsproxy_logfile(void);

/** The actual log-emitting functions.  There are three families of
    these functions: generic, circuit-related, and
    connection-related. */

#if __STDC_VERSION__ >= 199901L || __GNUC__ >= 4

/** Fatal errors: the program cannot continue and will exit. */
void log_abort(const char *fn, const char *format, ...)
  ATTR_PRINTF_2 ATTR_NORETURN;
void log_abort_ckt(const char *fn, circuit_t *ckt, const char *format, ...)
  ATTR_PRINTF_3 ATTR_NORETURN;
void log_abort_cn(const char *fn, conn_t *conn, const char *format, ...)
  ATTR_PRINTF_3 ATTR_NORETURN;

/** Warn-level severity: for messages that only appear when something
    has gone wrong. */
void log_warn(const char *fn, const char *format, ...) ATTR_PRINTF_2;
void log_warn_ckt(const char *fn, circuit_t *ckt, const char *format, ...)
  ATTR_PRINTF_3;
void log_warn_cn(const char *fn, conn_t *conn,const char *format, ...)
  ATTR_PRINTF_3;

/** Info-level severity: for messages that should be sent to the user
    during normal operation. */
void log_info(const char *fn, const char *format, ...) ATTR_PRINTF_2;
void log_info_ckt(const char *fn, circuit_t *ckt, const char *format, ...)
  ATTR_PRINTF_3;
void log_info_cn(const char *fn, conn_t *conn,const char *format, ...)
  ATTR_PRINTF_3;

/** Debug-level severity: for hyper-verbose messages of no interest to
    anybody but developers. */
void log_debug(const char *fn, const char *format, ...) ATTR_PRINTF_2;
void log_debug_ckt(const char *fn, circuit_t *ckt, const char *format, ...)
  ATTR_PRINTF_3;
void log_debug_cn(const char *fn, conn_t *conn, const char *format, ...)
  ATTR_PRINTF_3;

#define log_abort(...)     log_abort(__func__, __VA_ARGS__)
#define log_abort_ckt(...) log_abort_ckt(__func__, __VA_ARGS__)
#define log_abort_cn(...)  log_abort_cn(__func__, __VA_ARGS__)

#define log_warn(...)      log_warn(__func__, __VA_ARGS__)
#define log_warn_ckt(...)  log_warn_ckt(__func__, __VA_ARGS__)
#define log_warn_cn(...)   log_warn_cn(__func__, __VA_ARGS__)

#define log_info(...)      log_info(__func__, __VA_ARGS__)
#define log_info_ckt(...)  log_info_ckt(__func__, __VA_ARGS__)
#define log_info_cn(...)   log_info_cn(__func__, __VA_ARGS__)

#define log_debug(...)     log_debug(__func__, __VA_ARGS__)
#define log_debug_ckt(...) log_debug_ckt(__func__, __VA_ARGS__)
#define log_debug_cn(...)  log_debug_cn(__func__, __VA_ARGS__)

#else
/** Fatal errors: the program cannot continue and will exit. */
void log_abort(const char *format, ...) ATTR_PRINTF_1 ATTR_NORETURN;
void log_abort_ckt(circuit_t *ckt,
                   const char *format, ...) ATTR_PRINTF_2 ATTR_NORETURN;
void log_abort_cn(conn_t *conn,
                  const char *format, ...) ATTR_PRINTF_2 ATTR_NORETURN;

/** Warn-level severity: for messages that only appear when something
    has gone wrong. */
void log_warn(const char *format, ...) ATTR_PRINTF_1;
void log_warn_ckt(circuit_t *ckt, const char *format, ...) ATTR_PRINTF_2;
void log_warn_cn(conn_t *conn,const char *format, ...) ATTR_PRINTF_2;

/** Info-level severity: for messages that should be sent to the user
    during normal operation. */
void log_info(const char *format, ...) ATTR_PRINTF_1;
void log_info_ckt(circuit_t *ckt, const char *format, ...) ATTR_PRINTF_2;
void log_info_cn(conn_t *conn,const char *format, ...) ATTR_PRINTF_2;

/** Debug-level severity: for hyper-verbose messages of no interest to
    anybody but developers. */
void log_debug(const char *format, ...) ATTR_PRINTF_1;
void log_debug_ckt(circuit_t *ckt, const char *format, ...) ATTR_PRINTF_2;
void log_debug_cn(conn_t *conn,const char *format, ...) ATTR_PRINTF_2;
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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
