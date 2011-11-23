/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <event2/dns.h>
#ifndef _WIN32
#include <arpa/inet.h>
#endif
#ifdef AF_LOCAL
#include <sys/un.h>
#endif

/** Any size_t larger than this amount is likely to be an underflow. */
#define SIZE_T_CEILING  (SIZE_MAX/2 - 16)

/**************************** Memory Allocation ******************************/

static void ATTR_NORETURN
die_oom(void)
{
  log_abort("memory allocation failed: %s", strerror(errno));
}

void *
xmalloc(size_t size)
{
  void *result;

  log_assert(size < SIZE_T_CEILING);

  /* Some malloc() implementations return NULL when the input argument
     is zero. We don't bother detecting whether the implementation we're
     being compiled for does that, because it should hardly ever come up,
     and avoiding it unconditionally does no harm. */
  if (size == 0)
    size = 1;

  result = malloc(size);
  if (result == NULL)
    die_oom();

  return result;
}

void *
xrealloc(void *ptr, size_t size)
{
  void *result;
  log_assert (size < SIZE_T_CEILING);
  if (size == 0)
    size = 1;

  result = realloc(ptr, size);
  if (result == NULL)
    die_oom();

  return result;
}

void *
xzalloc(size_t size)
{
  void *result = xmalloc(size);
  memset(result, 0, size);
  return result;
}

void *
xmemdup(const void *ptr, size_t size)
{
  void *copy = xmalloc(size);
  memcpy(copy, ptr, size);
  return copy;
}

char *
xstrdup(const char *s)
{
  return (char *)xmemdup(s, strlen(s) + 1);
}

char *
xstrndup(const char *s, size_t maxsize)
{
  char *copy;
  size_t size;
  /* strnlen is not in any standard :-( */
  for (size = 0; size < maxsize; size++)
    if (s[size] == '\0')
      break;

  copy = (char *)xmalloc(size + 1);
  memcpy(copy, s, size);
  copy[size] = '\0';
  return copy;
}

/******************************** Mathematics ********************************/

unsigned int
ui64_log2(uint64_t u64)
{
  unsigned int r = 0;
  if (u64 >= (((uint64_t)1)<<32)) {
    u64 >>= 32;
    r = 32;
  }
  if (u64 >= (((uint64_t)1)<<16)) {
    u64 >>= 16;
    r += 16;
  }
  if (u64 >= (((uint64_t)1)<<8)) {
    u64 >>= 8;
    r += 8;
  }
  if (u64 >= (((uint64_t)1)<<4)) {
    u64 >>= 4;
    r += 4;
  }
  if (u64 >= (((uint64_t)1)<<2)) {
    u64 >>= 2;
    r += 2;
  }
  if (u64 >= (((uint64_t)1)<<1)) {
    u64 >>= 1;
    r += 1;
  }
  return r;
}

/************************ Network Routines *************************/

/**
   Accepts a string 'address' of the form ADDRESS:PORT and attempts to
   parse it into an 'evutil_addrinfo' structure.

   If 'nodns' is set it means that 'address' was an IP address.
   If 'passive' is set it means that the address is destined for
   listening and not for connecting.

   If no port was given in 'address', we set 'default_port' as the
   port.
*/
struct evutil_addrinfo *
resolve_address_port(const char *address, int nodns, int passive,
                     const char *default_port)
{
  struct evutil_addrinfo *ai = NULL;
  struct evutil_addrinfo ai_hints;
  int ai_res, ai_errno;
  char *a = xstrdup(address), *cp;
  const char *portstr;

  if ((cp = strchr(a, ':'))) {
    portstr = cp+1;
    *cp = '\0';
  } else if (default_port) {
    portstr = default_port;
  } else {
    log_debug("error in address %s: port required", address);
    free(a);
    return NULL;
  }

  memset(&ai_hints, 0, sizeof(ai_hints));
  ai_hints.ai_family = AF_UNSPEC;
  ai_hints.ai_socktype = SOCK_STREAM;
  ai_hints.ai_flags = EVUTIL_AI_ADDRCONFIG | EVUTIL_AI_NUMERICSERV;
  if (passive)
    ai_hints.ai_flags |= EVUTIL_AI_PASSIVE;
  if (nodns)
    ai_hints.ai_flags |= EVUTIL_AI_NUMERICHOST;

  ai_res = evutil_getaddrinfo(a, portstr, &ai_hints, &ai);
  ai_errno = errno;

  free(a);

  if (ai_res) {
    if (ai_res == EVUTIL_EAI_SYSTEM)
      log_warn("error resolving %s: %s [%s]",
               address, evutil_gai_strerror(ai_res), strerror(ai_errno));
    else
      log_warn("error resolving %s: %s", address, evutil_gai_strerror(ai_res));

    if (ai) {
      evutil_freeaddrinfo(ai);
      ai = NULL;
    }
  } else if (ai == NULL) {
    log_warn("address resolution failed for %s", address);
  }

  return ai;
}

char *
printable_address(struct sockaddr *addr, socklen_t addrlen)
{
  char apbuf[INET6_ADDRSTRLEN + 8]; /* []:65535 is 8 characters */

  switch (addr->sa_family) {
#ifndef _WIN32 /* Windows XP doesn't have inet_ntop. Fix later. */
  case AF_INET: {
    char abuf[INET6_ADDRSTRLEN];
    struct sockaddr_in *sin = (struct sockaddr_in*)addr;
    if (!inet_ntop(AF_INET, &sin->sin_addr, abuf, INET6_ADDRSTRLEN))
      break;
    xsnprintf(apbuf, sizeof apbuf, "%s:%d", abuf, ntohs(sin->sin_port));
    return xstrdup(apbuf);
  }

  case AF_INET6: {
    char abuf[INET6_ADDRSTRLEN];
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)addr;
    if (!inet_ntop(AF_INET, &sin6->sin6_addr, abuf, INET6_ADDRSTRLEN))
      break;
    xsnprintf(apbuf, sizeof apbuf, "[%s]:%d", abuf, ntohs(sin6->sin6_port));
    return xstrdup(apbuf);
  }
#endif

#ifdef AF_LOCAL
  case AF_LOCAL:
    return xstrdup(((struct sockaddr_un*)addr)->sun_path);
#endif
  default:
    break;
  }

  xsnprintf(apbuf, sizeof apbuf, "<addr family %d>", addr->sa_family);
  return xstrdup(apbuf);
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
/** Many of the functions in this section were carbon copied off tor.
    Thank you tor! */

/** Replacement for snprintf.  Differs from platform snprintf in two
 * ways: First, always NUL-terminates its output.  Second, always
 * returns -1 if the result is truncated.  (Note that this return
 * behavior does <i>not</i> conform to C99; it just happens to be
 * easier to emulate "return -1" with conformant implementations than
 * it is to emulate "return number that would be written" with
 * non-conformant implementations.) */
int
xsnprintf(char *str, size_t size, const char *format, ...)
{
  va_list ap;
  int r;
  va_start(ap,format);
  r = xvsnprintf(str,size,format,ap);
  va_end(ap);
  return r;
}

/** Replacement for vsnprintf; behavior differs as xsnprintf differs from
 * snprintf.
 */
int
xvsnprintf(char *str, size_t size, const char *format, va_list args)
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

/** getline() as standardized by POSIX-1.2008, except:
 *
 *  - The return type is unsigned. The return value on EOF
 *    or error is 0, not -1, and we guarantee to fill in
 *    *lineptr and *nptr regardless.
 *
 *  - Implements "universal newline" handling, i.e. the line
 *    terminator may be '\n', '\r', or '\r\n' regardless of
 *    the system convention. For this to work correctly,
 *    |stream| should have been opened in binary mode.
 */
size_t
xgetline(char **lineptr, size_t *nptr, FILE *stream)
{
  char *line = *lineptr;
  size_t asize = *nptr;
  size_t linelen = 0;
  int c;

  if (!line) {
    /* start with an 80-character buffer */
    line = (char *)xmalloc(80);
    asize = 80;
  }

  while ((c = getc(stream)) != EOF) {
    if (linelen >= asize) {
      asize *= 2;
      line = (char *)xrealloc(line, asize);
    }

    line[linelen++] = c;
    if (c == '\n')
      break;
    if (c == '\r') {
      line[linelen-1] = '\n'; /* canonicalize */
      c = getc(stream);
      if (c != '\n')
        ungetc(c, stream);
      break;
    }
  }

  if (linelen >= asize) {
    asize++;
    line = (char *)xrealloc(line, asize);
  }
  line[linelen] = '\0';
  *lineptr = line;
  *nptr = asize;
  return linelen;
}

/** Remove from the string <b>s</b> every character which appears in
 * <b>strip</b>. */
void
ascii_strstrip(char *s, const char *strip)
{
  char *read = s;
  while (*read) {
    if (strchr(strip, *read)) {
      ++read;
    } else {
      *s++ = *read++;
    }
  }
  *s = '\0';
}

void
ascii_strlower(char *s)
{
  while (*s) {
    if (*s >= 'A' && *s <= 'Z')
      *s = *s - 'A' + 'a';
    ++s;
  }
}

/************************ Logging Subsystem *************************/
/** The code of this section was to a great extent shamelessly copied
    off tor. It's basicaly a stripped down version of tor's logging
    system. Thank you tor. */

/* Note: log_assert and log_abort cannot be used anywhere in the
   logging system, as they will recurse into the logging system and
   cause an infinite loop.  We use plain old abort(3) instead. */

/* Size of maximum log entry, including newline and NULL byte. */
#define MAX_LOG_ENTRY 1024
/* String to append when a log entry doesn't fit in MAX_LOG_ENTRY. */
#define TRUNCATED_STR "[...truncated]"
/* strlen(TRUNCATED_STR) */
#define TRUNCATED_STR_LEN 14

/** Logging severities */

#define LOG_SEV_ERR     4
#define LOG_SEV_WARN    3
#define LOG_SEV_INFO    2
#define LOG_SEV_DEBUG   1

/* logging destination; NULL for no logging. */
static FILE *log_dest;
/* minimum logging severity */
static int log_min_sev = LOG_SEV_INFO;

/** Helper: map a log severity to descriptive string. */
static const char *
sev_to_string(int severity)
{
  switch (severity) {
  case LOG_SEV_ERR:     return "error";
  case LOG_SEV_WARN:    return "warn";
  case LOG_SEV_INFO:    return "info";
  case LOG_SEV_DEBUG:   return "debug";
  default:
    abort();
  }
}

/** If 'string' is a valid log severity, return the corresponding
 * numeric value.  Otherwise, return -1. */
static int
string_to_sev(const char *string)
{
  if (!strcasecmp(string, "error"))
    return LOG_SEV_ERR;
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
   Returns True if 'severity' is a valid logging severity.
   Otherwise, it returns False.
*/
static int
sev_is_valid(int severity)
{
  return (severity == LOG_SEV_ERR  ||
          severity == LOG_SEV_WARN ||
          severity == LOG_SEV_INFO ||
          severity == LOG_SEV_DEBUG);
}

/**
   Helper: Opens 'filename' and sets it as the logfile.
   On success it returns 0, on fail it returns -1.
*/
static int
log_open(const char *filename)
{
  if (!filename)
    return -1;

  log_dest = fopen(filename, "a");
  if (!log_dest)
    return -1;

  fputs("\nBrand new log:\n", log_dest);
  fflush(log_dest);
  setvbuf(log_dest, NULL, _IOLBF, 0);

  return 0;
}

/**
   Closes the logfile if it exists.
   Ignores errors.
*/
void
log_close(void)
{
  if (log_dest && log_dest != stderr)
    fclose(log_dest);
}

/**
   Sets the global logging 'method' and also sets and open the logfile
   'filename' in case we want to log into a file.
   It returns 1 on success and -1 on fail.
*/
int
log_set_method(int method, const char *filename)
{
  log_close();

  switch (method) {
  case LOG_METHOD_NULL:
    log_dest = NULL;
    return 0;

  case LOG_METHOD_STDERR:
    log_dest = stderr;
    setvbuf(log_dest, NULL, _IOLBF, 0);
    return 0;

  case LOG_METHOD_FILE:
    return log_open(filename);

  default:
    abort();
  }
}

/**
   Sets the minimum logging severity to the severity described by
   'sev_string', then it returns 0.  If 'sev_string' is not a valid
   severity, it returns -1.  */
int
log_set_min_severity(const char* sev_string)
{
  int severity = string_to_sev(sev_string);
  if (!sev_is_valid(severity)) {
    log_warn("unknown logging severity '%s'", sev_string);
    return -1;
  }
  log_min_sev = severity;
  return 0;
}

/** True if the minimum log severity is "debug".  Used in a few places
    to avoid some expensive formatting work if we are going to ignore the
    result. */
int
log_do_debug(void)
{
  return log_min_sev == LOG_SEV_DEBUG;
}

/**
    Logging worker function.  Accepts a logging 'severity' and a
    'format' string and logs the message in 'format' according to the
    configured minimum logging severity and logging method.  */
static void
logv(int severity, const char *format, va_list ap)
{
  if (!sev_is_valid(severity))
    abort();

  /* See if the user is interested in this log message. */
  if (!log_dest || severity < log_min_sev)
    return;

  vfprintf(log_dest, format, ap);
  putc('\n', log_dest);
}

static void
logpfx(int severity, const char *fn)
{
  if (!sev_is_valid(severity))
    abort();

  /* See if the user is interested in this log message. */
  if (!log_dest || severity < log_min_sev)
    return;

  fprintf(log_dest, "[%s] ", sev_to_string(severity));
  if (log_min_sev == LOG_SEV_DEBUG && fn)
    fprintf(log_dest, "%s: ", fn);
}

static void
logpfx(int severity, const char *fn, circuit_t *ckt)
{
  if (!sev_is_valid(severity))
    abort();

  /* See if the user is interested in this log message. */
  if (!log_dest || severity < log_min_sev)
    return;

  fprintf(log_dest, "[%s] ", sev_to_string(severity));
  if (log_min_sev == LOG_SEV_DEBUG && fn)
    fprintf(log_dest, "%s: ", fn);
  if (ckt)
    fprintf(log_dest, "<%u> ", ckt->serial);
}

static void
logpfx(int severity, const char *fn, conn_t *conn)
{
  if (!sev_is_valid(severity))
    abort();

  /* See if the user is interested in this log message. */
  if (!log_dest || severity < log_min_sev)
    return;

  fprintf(log_dest, "[%s] ", sev_to_string(severity));
  if (log_min_sev == LOG_SEV_DEBUG && fn)
    fprintf(log_dest, "%s: ", fn);
  if (conn)
    fprintf(log_dest, "<%u.%u> ",
            conn->circuit ? conn->circuit->serial : 0,
            conn->serial);
}

/**** Public logging API. ****/

#define logfmt(sev_, fmt_) do {                 \
    va_list ap_;                                \
    va_start(ap_, fmt_);                        \
    logv(sev_, fmt_, ap_);                      \
    va_end(ap_);                                \
  } while (0)

#if __GNUC__ >= 3
#define FNARG const char *fn,
#define FN fn
#else
#define FNARG /**/
#define FN 0
#endif

void
(log_abort)(FNARG const char *format, ...)
{
  logpfx(LOG_SEV_ERR, FN);
  logfmt(LOG_SEV_ERR, format);
  exit(1);
}

void
(log_abort)(FNARG circuit_t *ckt, const char *format, ...)
{
  logpfx(LOG_SEV_ERR, FN, ckt);
  logfmt(LOG_SEV_ERR, format);
  exit(1);
}

void
(log_abort)(FNARG conn_t *conn, const char *format, ...)
{
  logpfx(LOG_SEV_ERR, FN, conn);
  logfmt(LOG_SEV_ERR, format);
  exit(1);
}

void
(log_warn)(FNARG const char *format, ...)
{
  logpfx(LOG_SEV_WARN, FN);
  logfmt(LOG_SEV_WARN, format);
}

void
(log_warn)(FNARG circuit_t *ckt, const char *format, ...)
{
  logpfx(LOG_SEV_WARN, FN, ckt);
  logfmt(LOG_SEV_WARN, format);
}

void
(log_warn)(FNARG conn_t *cn, const char *format, ...)
{
  logpfx(LOG_SEV_WARN, FN, cn);
  logfmt(LOG_SEV_WARN, format);
}

void
(log_info)(FNARG const char *format, ...)
{
  logpfx(LOG_SEV_INFO, FN);
  logfmt(LOG_SEV_INFO, format);
}

void
(log_info)(FNARG circuit_t *ckt, const char *format, ...)
{
  logpfx(LOG_SEV_INFO, FN, ckt);
  logfmt(LOG_SEV_INFO, format);
}

void
(log_info)(FNARG conn_t *cn, const char *format, ...)
{
  logpfx(LOG_SEV_INFO, FN, cn);
  logfmt(LOG_SEV_INFO, format);
}

void
(log_debug)(FNARG const char *format, ...)
{
  logpfx(LOG_SEV_DEBUG, FN);
  logfmt(LOG_SEV_DEBUG, format);
}

void
(log_debug)(FNARG circuit_t *ckt, const char *format, ...)
{
  logpfx(LOG_SEV_DEBUG, FN, ckt);
  logfmt(LOG_SEV_DEBUG, format);
}

void
(log_debug)(FNARG conn_t *cn, const char *format, ...)
{
  logpfx(LOG_SEV_DEBUG, FN, cn);
  logfmt(LOG_SEV_DEBUG, format);
}
