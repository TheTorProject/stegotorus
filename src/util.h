/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef UTIL_H
#define UTIL_H

#include <stdarg.h> /* for va_list */
#include <stddef.h> /* for size_t etc */

#ifndef __GNUC__
#define __attribute__(x) /* nothing */
#endif

struct sockaddr;
struct event_base;
struct evdns_base;

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
  __attribute__((format(printf, 3, 4)));

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

/** Warn-level severity: for messages that only appear when something
    has gone wrong. */
void log_warn(const char *format, ...)
  __attribute__((format(printf, 1, 2)));

/** Info-level severity: for messages that should be sent to the user
    during normal operation. */
void log_info(const char *format, ...)
  __attribute__((format(printf, 1, 2)));

/** Debug-level severity: for hyper-verbose messages of no interest to
    anybody but developers. */
void log_debug(const char *format, ...)
  __attribute__((format(printf, 1, 2)));

#endif
