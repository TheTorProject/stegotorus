/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <assert.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "util.h"

#ifdef _WIN32
#include <Ws2tcpip.h>
#endif

#include <event2/util.h>
#include <event2/dns.h>

/** Any size_t larger than this amount is likely to be an underflow. */
#define SIZE_T_CEILING  (SIZE_MAX/2 - 16)

static const char *sev_to_string(int severity);
static int sev_is_valid(int severity);
static int write_logfile_prologue(int fd);
static int compose_logfile_prologue(char *buf, size_t buflen);
static int string_to_sev(const char *string);
static int open_and_set_obfsproxy_logfile(const char *filename);
static void logv(int severity, const char *format, va_list ap);

/************************ Obfsproxy Network Routines *************************/

int
resolve_address_port(const char *address,
                     int nodns, int passive,
                     struct sockaddr_storage *addr_out,
                     int *addrlen_out,
                     const char *default_port)
{
  struct evutil_addrinfo *ai = NULL;
  struct evutil_addrinfo ai_hints;
  int result = -1, ai_res;
  char *a = strdup(address), *cp;
  const char *portstr;
  if (!a)
    return -1;

  if ((cp = strchr(a, ':'))) {
    portstr = cp+1;
    *cp = '\0';
  } else if (default_port) {
    portstr = default_port;
  } else {
    log_debug("Error in address %s: port required.", address);
    goto done;
  }

  memset(&ai_hints, 0, sizeof(ai_hints));
  ai_hints.ai_family = AF_UNSPEC;
  ai_hints.ai_socktype = SOCK_STREAM;
  ai_hints.ai_flags = EVUTIL_AI_ADDRCONFIG | EVUTIL_AI_NUMERICSERV;
  if (passive)
    ai_hints.ai_flags |= EVUTIL_AI_PASSIVE;
  if (nodns)
    ai_hints.ai_flags |= EVUTIL_AI_NUMERICHOST;

  if ((ai_res = evutil_getaddrinfo(a, portstr, &ai_hints, &ai))) {
    log_warn("Error resolving %s (%s) (%s): %s",
             address,  a, portstr, evutil_gai_strerror(ai_res));
    goto done;
  }
  if (ai == NULL) {
    log_warn("No result for address %s", address);
    goto done;
  }
  if (ai->ai_addrlen > sizeof(struct sockaddr_storage)) {
    log_warn("Result for address %s too long", address);
    goto done;
  }

  memcpy(addr_out, ai->ai_addr, ai->ai_addrlen);
  *addrlen_out = (int) ai->ai_addrlen;
  result = 0;

 done:
  free(a);
  if (ai)
    evutil_freeaddrinfo(ai);
  return result;
}

static struct evdns_base *the_evdns_base = NULL;

struct evdns_base *
get_evdns_base(void)
{
  return the_evdns_base;
}

int
init_evdns_base(struct event_base *base)
{
  the_evdns_base = evdns_base_new(base, 1);
  return the_evdns_base == NULL ? -1 : 0;
}

/************************ String Functions *************************/
/** The functions in this section were carbon copied off tor. Thank you tor! */

/** Replacement for snprintf.  Differs from platform snprintf in two
 * ways: First, always NUL-terminates its output.  Second, always
 * returns -1 if the result is truncated.  (Note that this return
 * behavior does <i>not</i> conform to C99; it just happens to be
 * easier to emulate "return -1" with conformant implementations than
 * it is to emulate "return number that would be written" with
 * non-conformant implementations.) */
int
obfs_snprintf(char *str, size_t size, const char *format, ...)
{
  va_list ap;
  int r;
  va_start(ap,format);
  r = obfs_vsnprintf(str,size,format,ap);
  va_end(ap);
  return r;
}

/** Replacement for vsnprintf; behavior differs as obfs_snprintf differs from
 * snprintf.
 */
int
obfs_vsnprintf(char *str, size_t size, const char *format, va_list args)
{
  int r;
  if (size == 0)
    return -1; /* no place for the NUL */
  if (size > SIZE_T_CEILING)
    return -1;
  r = vsnprintf(str, size, format, args);
  str[size-1] = '\0';
  if (r < 0 || r >= (ssize_t)size)
    return -1;
  return r;
}

/************************ Logging Subsystem *************************/
/** The code of this section was to a great extend shamelessly copied
    off tor. It's basicaly a stripped down version of tor's logging
    system. Thank you tor. */

/* Size of maximum log entry, including newline and NULL byte. */
#define MAX_LOG_ENTRY 1024
/* String to append when a log entry doesn't fit in MAX_LOG_ENTRY. */
#define TRUNCATED_STR "[...truncated]"
/* strlen(TRUNCATED_STR) */
#define TRUNCATED_STR_LEN 14

/* logging method */
static int logging_method=LOG_METHOD_STDOUT;
/* minimum logging severity */
static int logging_min_sev=LOG_SEV_INFO;
/* logfile fd */
static int logging_logfile=-1;

/** Helper: map a log severity to descriptive string. */
static const char *
sev_to_string(int severity)
{
  switch (severity) {
  case LOG_SEV_WARN:    return "warn";
  case LOG_SEV_INFO:    return "info";
  case LOG_SEV_DEBUG:   return "debug";
  default:
    assert(0); return "UNKNOWN";
  }
}

/** If 'string' is a valid log severity, return the corresponding
 * numeric value.  Otherwise, return -1. */
static int
string_to_sev(const char *string)
{
  if (!strcasecmp(string, "warn"))
    return LOG_SEV_WARN;
  else if (!strcasecmp(string, "info"))
    return LOG_SEV_INFO;
  else if (!strcasecmp(string, "debug"))
    return LOG_SEV_DEBUG;
  else
    return -1;
}

/**
   Returns True if 'severity' is a valid obfsproxy logging severity.
   Otherwise, it returns False.
*/
static int
sev_is_valid(int severity)
{
  return (severity == LOG_SEV_WARN || 
          severity == LOG_SEV_INFO || 
          severity == LOG_SEV_DEBUG);
}

/**
   Sets the global logging 'method' and also sets and open the logfile
   'filename' in case we want to log into a file.
   It returns 1 on success and -1 on fail.
*/
int
log_set_method(int method, const char *filename)
{
  
  logging_method = method;
  if (method == LOG_METHOD_FILE) {
    if (open_and_set_obfsproxy_logfile(filename) < 0)
      return -1;
    if (write_logfile_prologue(logging_logfile) < 0)
      return -1;
  }    
  return 1;
}

/**
   Helper: Opens 'filename' and sets it as the obfsproxy logfile.
   On success it returns 1, on fail it returns -1.
*/
static int
open_and_set_obfsproxy_logfile(const char *filename)
{
  if (!filename)
    return -1;
  logging_logfile = open(filename, 
                         O_WRONLY|O_CREAT|O_APPEND,
                         0644);
  if (logging_logfile < 0)
    return -1;
  return 1;
}

/**
   Closes the obfsproxy logfile if it exists.
   Returns 0 on success or if we weren't using a logfile (that's
   close()'s success return value) and -1 on failure.
*/
int
close_obfsproxy_logfile(void)
{
  if (logging_logfile < 0) /* no logfile. */
    return 0;
  else
    return close(logging_logfile);
}

/**
   Writes a small prologue in the logfile 'fd' that mentions the
   obfsproxy version and helps separate log instances.
*/
static int
write_logfile_prologue(int logfile) {
  char buf[256];
  if (compose_logfile_prologue(buf, sizeof(buf)) < 0)
    return -1;
  if (write(logfile, buf, strlen(buf)) < 0)
    return -1;
  return 1;
}

#define TEMP_PROLOGUE "\nBrand new obfsproxy log:\n"
/**
   Helper: Composes the logfile prologue.
*/
static int
compose_logfile_prologue(char *buf, size_t buflen)
{  
  if (obfs_snprintf(buf, buflen, TEMP_PROLOGUE) < 0) {
    log_warn("Logfile prologue couldn't be written.");
    return -1;
  }
  return 1;
}
#undef TEMP_PROLOGUE

/**
   Sets the minimum logging severity of obfsproxy to the severity
   described by 'sev_string', then it returns 1.  If 'sev_string' is
   not a valid severity, it returns -1.
*/
int
log_set_min_severity(const char* sev_string) {
  int severity = string_to_sev(sev_string);
  if (!sev_is_valid(severity)) {
    log_warn("Severity '%s' makes no sense.", sev_string);
    return -1;
  }
  logging_min_sev = severity;
  return 1;
}

/**
    Logging function of obfsproxy.
    Don't call this directly; use the log_* macros defined in util.h
    instead.

    It accepts a logging 'severity' and a 'format' string and logs the
    message in 'format' according to the configured obfsproxy minimum
    logging severity and logging method.
*/
void
log_fn(int severity, const char *format, ...)
{

  va_list ap;
  va_start(ap,format);

  logv(severity, format, ap);

  va_end(ap);
}

static void
logv(int severity, const char *format, va_list ap)
{
  assert(sev_is_valid(severity));

  if (logging_method == LOG_METHOD_NULL)
    return;

  /* See if the user is interested in this log message. */
  if (severity < logging_min_sev)
    return;

  size_t n=0;
  int r=0;
  char buf[MAX_LOG_ENTRY];

  size_t buflen = MAX_LOG_ENTRY-2;

  r = obfs_snprintf(buf, buflen, "[%s] ", sev_to_string(severity));
  if (r < 0)
    n = strlen(buf);
  else
    n=r;

  r = obfs_vsnprintf(buf+n, buflen-n, format, ap);
  if (r < 0) {
    if (buflen >= TRUNCATED_STR_LEN) {
      size_t offset = buflen-TRUNCATED_STR_LEN;
      r = obfs_snprintf(buf+offset, TRUNCATED_STR_LEN+1,
                        "%s", TRUNCATED_STR);
      if (r < 0) assert(0);
    }
    n = buflen;
  } else
    n+=r;

  buf[n]='\n';
  buf[n+1]='\0';

  if (logging_method == LOG_METHOD_STDOUT)
    fprintf(stdout, "%s", buf);
  else if (logging_method == LOG_METHOD_FILE) {
    assert(logging_logfile);
    if (write(logging_logfile, buf, strlen(buf)) < 0)
      printf("%s(): Terrible write() error!!!\n", __func__);
  } else
    assert(0);
}

#ifdef NEED_LOG_WRAPPERS
void
log_info(const char *format, ...)
{
  va_list ap;
  va_start(ap,format);

  logv(LOG_SEV_INFO, format, ap);

  va_end(ap);
}
void
log_warn(const char *format, ...)
{
  va_list ap;
  va_start(ap,format);

  logv(LOG_SEV_WARN, format, ap);

  va_end(ap);
}
void
log_debug(const char *format, ...)
{
  va_list ap;
  va_start(ap,format);

  logv(LOG_SEV_DEBUG, format, ap);

  va_end(ap);
}
#endif
