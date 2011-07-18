/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef UTIL_H
#define UTIL_H

#include "config.h"
#include <stdarg.h> /* for va_list */
#include <stddef.h> /* size_t, offsetof, NULL, etc */

#ifndef __GNUC__
#define __attribute__(x) /* nothing */
#endif
#define ATTR_MALLOC   __attribute__((malloc))
#define ATTR_NORETURN __attribute__((noreturn))
#define ATTR_PRINTF_1 __attribute__((format(printf, 1, 2)))
#define ATTR_PRINTF_3 __attribute__((format(printf, 3, 4)))
#define ATTR_PURE     __attribute__((pure))

struct sockaddr;
struct event_base;
struct evdns_base;

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

/***** Network functions stuff. *****/

int resolve_address_port(const char *address,
                         int nodns, int passive,
                         struct sockaddr **addr_out,
                         size_t *addrlen_out,
                         const char *default_port);

struct evdns_base *get_evdns_base(void);
int init_evdns_base(struct event_base *base);

/***** String functions stuff. *****/

int obfs_vsnprintf(char *str, size_t size,
                   const char *format, va_list args);
int obfs_snprintf(char *str, size_t size,
                  const char *format, ...)
  ATTR_PRINTF_3;

/***** Doubly Linked List stuff. *****/

#define DOWNCAST(container_type, element, ptr) \
  (container_type*)( ((char*)ptr) - offsetof(container_type, element) )

/** A doubly linked list node.
    [algorithms ripped off Wikipedia (Doubly_linked_list) ] */
typedef struct dll_node_t {
  struct dll_node_t *next, *prev;
} dll_node_t;

/** A doubly linked list. */
typedef struct dll_t {
  struct dll_node_t *head;
  struct dll_node_t *tail;
} dll_t;

void dll_init(dll_t *list);
int dll_append(dll_t *list, dll_node_t *node);
void dll_remove(dll_t *list, dll_node_t *node);
#define DLL_INIT() { NULL, NULL }

/***** Logging subsystem stuff. *****/

/** Logging methods */

/** Spit log messages on stdout. */
#define LOG_METHOD_STDOUT 1
/** Place log messages in a file. */
#define LOG_METHOD_FILE 2
/** We don't want no logs. */
#define LOG_METHOD_NULL 3

/** Set the log method, and open the logfile 'filename' if appropriate. */
int log_set_method(int method, const char *filename);

/** Set the minimum severity that will be logged.
    'sev_string' may be "warn", "info", or "debug" (case-insensitively). */
int log_set_min_severity(const char* sev_string);

/** Close the logfile if it's open.  Ignores errors. */
void close_obfsproxy_logfile(void);

/** The actual log-emitting functions */

/** Fatal errors: the program cannot continue and will exit. */
void log_error(const char *format, ...)
  ATTR_PRINTF_1 ATTR_NORETURN;

/** Warn-level severity: for messages that only appear when something
    has gone wrong. */
void log_warn(const char *format, ...)
  ATTR_PRINTF_1;

/** Info-level severity: for messages that should be sent to the user
    during normal operation. */
void log_info(const char *format, ...)
  ATTR_PRINTF_1;

/** Debug-level severity: for hyper-verbose messages of no interest to
    anybody but developers. */
void log_debug(const char *format, ...)
  ATTR_PRINTF_1;

/** Assertion checking.  We don't ever compile assertions out, and we
    want precise control over the error messages, so we use our own
    assertion macros. */
#define obfs_assert(expr)                               \
  do {                                                  \
    if (!(expr))                                        \
      log_error("assertion failure at %s:%d: %s",       \
                __FILE__, __LINE__, #expr);             \
  } while (0)

#define obfs_abort()                                    \
  do {                                                  \
    log_error("aborted at %s:%d", __FILE__, __LINE__);  \
  } while (0)


#endif
