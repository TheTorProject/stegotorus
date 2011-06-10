/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#ifndef UTIL_H
#define UTIL_H

/* va_list definition */
#include <stdarg.h>

#include "config.h"

struct sockaddr_storage;
struct event_base;
struct evdns_base;

/***** Network functions stuff. *****/

int resolve_address_port(const char *address,
                         int nodns, int passive,
                         struct sockaddr_storage *addr_out,
                         int *addrlen_out,
                         const char *default_port);

struct evdns_base *get_evdns_base(void);
int init_evdns_base(struct event_base *base);

/***** String functions stuff. *****/

/* The sizeof a size_t, as computed by sizeof. */
#ifndef SSIZE_T_MAX
#if (SIZEOF_SIZE_T == 4)
#define SSIZE_T_MAX INT32_MAX
#elif (SIZEOF_SIZE_T == 8)
#define SSIZE_T_MAX INT64_MAX
#else
#error "Can't define SSIZE_T_MAX"
#endif
#endif
/** Any size_t larger than this amount is likely to be an underflow. */
#define SIZE_T_CEILING  ((size_t)(SSIZE_T_MAX-16))

int obfs_vsnprintf(char *str, size_t size, 
                   const char *format, va_list args);
int obfs_snprintf(char *str, size_t size, 
                  const char *format, ...);

/***** Logging subsystem stuff. *****/

void log_fn(int severity, const char *format, ...);
int log_set_method(int method, char *filename);
int log_set_min_severity(char* sev_string);
int close_obfsproxy_logfile(void);

#define log_info(args...) log_fn(LOG_SEV_INFO, args)
#define log_warn(args...) log_fn(LOG_SEV_WARN, args)
#define log_debug(args...) log_fn(LOG_SEV_DEBUG, args)

/** Logging methods */

/** Spit log messages on stdout. */
#define LOG_METHOD_STDOUT 1
/** Place log messages in a file. */
#define LOG_METHOD_FILE 2
/** We don't want no logs. */
#define LOG_METHOD_NULL 3 

/** Logging severities */

/** Warn-level severity: for messages that only appear when something has gone  wrong. */
#define LOG_SEV_WARN    3
/** Info-level severity: for messages that should be sent to the user
    during normal operation. */
#define LOG_SEV_INFO    2
/** Debug-level severity: for hyper-verbose messages of no interest to
    anybody but developers. */
#define LOG_SEV_DEBUG   1

#endif
