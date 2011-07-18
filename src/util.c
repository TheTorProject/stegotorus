/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <event2/dns.h>
#include <event2/util.h>

#ifdef _WIN32
#include <ws2tcpip.h> /* addrinfo */
#endif

/** Any size_t larger than this amount is likely to be an underflow. */
#define SIZE_T_CEILING  (SIZE_MAX/2 - 16)

/**************************** Memory Allocation ******************************/

static void ATTR_NORETURN
die_oom(void)
{
  log_warn("Memory allocation failed: %s",strerror(errno));
  exit(1);
}

void *
xmalloc(size_t size)
{
  void *result;

  assert(size < SIZE_T_CEILING);

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
  assert (size < SIZE_T_CEILING);
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
  return xmemdup(s, strlen(s) + 1);
}

/************************ Obfsproxy Network Routines *************************/

/**
   Accepts a string 'address' of the form ADDRESS:PORT and attempts to
   parse it into 'addr_out' and put it's length into 'addrlen_out'.

   If 'nodns' is set it means that 'address' was an IP address.
   If 'passive' is set it means that the address is destined for
   listening and not for connecting.

   If no port was given in 'address', we set 'default_port' as the
   port.
*/
int
resolve_address_port(const char *address,
                     int nodns, int passive,
                     struct sockaddr **addr_out,
                     size_t *addrlen_out,
                     const char *default_port)
{
  struct evutil_addrinfo *ai = NULL;
  struct evutil_addrinfo ai_hints;
  int result = -1, ai_res;
  char *a = xstrdup(address), *cp;
  const char *portstr;

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
  *addrlen_out = ai->ai_addrlen;
  *addr_out = xmemdup(ai->ai_addr, ai->ai_addrlen);
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

/************************ Doubly Linked List (DLL) ******************/

/**
   Insert 'new_node' after 'node' in the doubly linked list 'list'.
*/
static void
dll_insert_after(dll_t *list, dll_node_t *node, dll_node_t *new_node)
{
  assert(node);
  assert(new_node);

  if (!list)
    return;

  new_node->prev = node;
  new_node->next = node->next;
  if (!node->next)
    list->tail = new_node;
  else
    node->next->prev = new_node;
  node->next = new_node;
}

/**
   Insert 'new_node' before 'node' in the doubly linked list 'list'.
*/ 
static void
dll_insert_before(dll_t *list, dll_node_t *node, dll_node_t *new_node)
{
  assert(node);
  assert(new_node);

  if (!list)
    return;

  new_node->prev = node->prev;
  new_node->next = node;
  if (!node->prev)
    list->head = new_node;
  else
    node->prev->next = new_node;
  node->prev = new_node;
}

/** Initialize <b>list</b> as an empty list. */
void
dll_init(dll_t *list)
{
  list->head = list->tail = NULL;
}
  
/**
   Insert 'node' in the beginning of the doubly linked 'list'.
*/ 
static void
dll_insert_beginning(dll_t *list, dll_node_t *node)
{
  assert(node);

  if (!list)
    return;

  if (!list->head) {
    list->head = node;
    list->tail = node;
    node->prev = NULL;
    node->next = NULL;
  } else {
    dll_insert_before(list, list->head, node);
  }
}
  
/** 
    Appends 'data' to the end of the doubly linked 'list'.
    Returns 1 on success, -1 on fail.
*/
int
dll_append(dll_t *list, dll_node_t *node)
{
  assert(list);
  assert(node);

  if (!list->tail)
    dll_insert_beginning(list, node);
  else
    dll_insert_after(list, list->tail, node);

  return 1;
}

/**
   Removes 'node' from the doubly linked list 'list'.
   It frees the list node, but leaves its data intact.
*/ 
void
dll_remove(dll_t *list, dll_node_t *node)
{
  assert(node);

  if (!list)
    return;

  if (!node->prev)
    list->head = node->next;
  else
    node->prev->next = node->next;
  if (!node->next)
    list->tail = node->prev;
  else
    node->next->prev = node->prev;
}

/************************ Logging Subsystem *************************/
/** The code of this section was to a great extent shamelessly copied
    off tor. It's basicaly a stripped down version of tor's logging
    system. Thank you tor. */

/* Size of maximum log entry, including newline and NULL byte. */
#define MAX_LOG_ENTRY 1024
/* String to append when a log entry doesn't fit in MAX_LOG_ENTRY. */
#define TRUNCATED_STR "[...truncated]"
/* strlen(TRUNCATED_STR) */
#define TRUNCATED_STR_LEN 14

/** Logging severities */

#define LOG_SEV_WARN    3
#define LOG_SEV_INFO    2
#define LOG_SEV_DEBUG   1

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
   Helper: Opens 'filename' and sets it as the obfsproxy logfile.
   On success it returns 0, on fail it returns -1.
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
  return 0;
}

/**
   Closes the obfsproxy logfile if it exists.
   Ignores errors.
*/
void
close_obfsproxy_logfile(void)
{
  if (logging_logfile >= 0)
    close(logging_logfile);
}

/**
   Writes a small prologue in the logfile 'fd' that mentions the
   obfsproxy version and helps separate log instances.

   Returns 0 on success, -1 on failure.
*/
static int
write_logfile_prologue(int logfile)
{
  static const char prologue[] = "\nBrand new obfsproxy log:\n";
  if (write(logfile, prologue, strlen(prologue)) != strlen(prologue))
    return -1;
  return 0;
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
  return 0;
}

/**
   Sets the minimum logging severity of obfsproxy to the severity
   described by 'sev_string', then it returns 0.  If 'sev_string' is
   not a valid severity, it returns -1.
*/
int
log_set_min_severity(const char* sev_string)
{
  int severity = string_to_sev(sev_string);
  if (!sev_is_valid(severity)) {
    log_warn("Severity '%s' makes no sense.", sev_string);
    return -1;
  }
  logging_min_sev = severity;
  return 0;
}

/**
    Logging worker function.
    Accepts a logging 'severity' and a 'format' string and logs the
    message in 'format' according to the configured obfsproxy minimum
    logging severity and logging method.
*/
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

/**** Public logging API. ****/

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
