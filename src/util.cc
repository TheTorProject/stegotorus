
/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */
#include <string>
#include <sstream>
#include <fstream>

#include "util.h"
#include "connections.h"
#include "strncasestr.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <event2/buffer.h>

using namespace std;
#ifdef _WIN32
void
print_trace (void)
{

}
#elif __ANDROID__
void
print_trace (void)
{

}
#else
#include <execinfo.h>

/* Obtain a backtrace and print it to stderr. */
void
print_trace (void)
{
  void *array[10];
  size_t size;
  char **strings;
  size_t i;

  size = backtrace (array, 10);
  strings = backtrace_symbols (array, size);
  fprintf (stderr, "Obtained %zd stack frames.\n", size);
  for (i = 0; i < size; i++)
    fprintf (stderr, "%s\n", strings[i]);
  free (strings);
} 
#endif
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

  if (result == NULL) {
    print_trace();
    die_oom();
  }

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

/* logging destination; NULL for no logging. */
static FILE *log_dest;
/* minimum logging severity */
static int log_min_sev = LOG_SEV_INFO;
/* whether timestamps are wanted */
static bool log_timestamps = false;
static struct timeval log_ts_base = { 0, 0 };

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
  if (!strncasecmp(string, "error", strlen("error")))
    return LOG_SEV_ERR;
  if (!strncasecmp(string, "warn", strlen("warn")))
    return LOG_SEV_WARN;
  else if (!strncasecmp(string, "info", strlen("info")))
    return LOG_SEV_INFO;
  else if (!strncasecmp(string, "debug", strlen("debug")))
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

  setvbuf(log_dest, 0, _IONBF, 0);
  fputs("\nBrand new log:\n", log_dest);

  return 0;
}

/**
   Closes the logfile if it exists.
   Ignores errors.
*/
void
log_close()
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
    setvbuf(stderr, 0, _IONBF, 0);
    log_dest = stderr;
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

/**
   returns the log severity as integer. This helps programmer to 
   write codes that only run during debug mode
 */
int
log_get_min_severity()
{
  return log_min_sev;
}

/** Enable timestamps on all log messages. */
void
log_enable_timestamps()
{
  if (!log_timestamps) {
    log_timestamps = true;
    gettimeofday(&log_ts_base, 0);
  }
}

/** Get a timestamp, as a floating-point number of seconds. */
double
log_get_timestamp()
{
  struct timeval now, delta;
  gettimeofday(&now, 0);
  timeval_subtract(&now, &log_ts_base, &delta);
  return delta.tv_sec + double(delta.tv_usec) / 1e6;
}

double log_get_abs_timestamp(){
  struct timeval now;
  gettimeofday(&now, 0);
  return now.tv_sec + double(now.tv_usec) / 1e6;
}

/** True if the minimum log severity is "debug".  Used in a few places
    to avoid some expensive formatting work if we are going to ignore the
    result. */
int
log_do_debug()
{
  return log_min_sev == LOG_SEV_DEBUG;
}

/**
    Logging worker function.  Accepts a logging 'severity' and a
    'format' string and logs the message in 'format' according to the
    configured minimum logging severity and logging method.  */
static void
logv(int severity, const char *format, va_list ap) ATTR_VPRINTF_2;
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

static bool
logpfx(int severity, const char *fn)
{
  if (!sev_is_valid(severity))
    abort();

  /* See if the user is interested in this log message. */
  if (!log_dest || severity < log_min_sev)
    return false;

  if (log_timestamps)
    fprintf(log_dest, "%.4f ", log_get_timestamp());

  fprintf(log_dest, "[%s] ", sev_to_string(severity));
  if (log_min_sev == LOG_SEV_DEBUG && fn)
    fprintf(log_dest, "%s: ", fn);
  return true;
}

static void
logpfx(int severity, const char *fn, circuit_t *ckt)
{
  if (logpfx(severity, fn))
    if (ckt)
      fprintf(log_dest, "<%u> ", ckt->serial);
}

static void
logpfx(int severity, const char *fn, conn_t *conn)
{
  if (logpfx(severity, fn))
    if (conn) {
      circuit_t *ckt = conn->circuit();
      unsigned int ckt_serial = ckt ? ckt->serial : 0;
      fprintf(log_dest, "<%u.%u> ", ckt_serial, conn->serial);
    }
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

void  buf2hex(uint8_t* buf, size_t len, std::string& res)
{
  log_assert(buf); log_assert(len);
  stringstream res_stream;
  for(unsigned char* i = buf; i < buf + len - 1; i++)
    res_stream << hex << (int)*i << " ";

  res_stream << hex << (int)*(buf+len -1);
  
  res = res_stream.str();
}

/**
   strips off the scheme and the domain part from the url

   @param absolute_url the aboslute url optionally with the scheme

   @return only the relative part of the url
 */
std::string 
relativize_url(const std::string& absolute_url)
{
  log_debug("%s, %zu", absolute_url.c_str(), absolute_url.length());
  
  if (absolute_url[0] == '/') //already relative
    return absolute_url;
  else { 
    size_t schemes_end = absolute_url.find("://");
    if (schemes_end == std::string::npos) //no scheme
      return absolute_url.substr(absolute_url.find("/"));
    else {
      return absolute_url.substr(absolute_url.find("/", schemes_end+3));
    }
  }

  return string();
  
}
/************************* Time Functions **************************/

int timeval_subtract(struct timeval *x, struct timeval *y,
		     struct timeval *result) {
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

/**
  convert vector buffer to hex string to be encoded in a text only
  covers like js.

  @param data the buffer which contains the raw data
  @param hexed_data will contained the hex representation of the data.
*/
void encode_data_to_hex(const std::vector<uint8_t>& data, std::vector<uint8_t>& hexed_data)
{
  for(size_t cnt = 0; cnt < data.size(); cnt++) {
    hexed_data[cnt*2] = "0123456789abcdef"[(data[cnt] & 0xF0) >> 4]; //does this need to change to 8, I don't think so, just hex encoding, this function is present elsewhere too
    hexed_data[cnt*2+1] = "0123456789abcdef"[(data[cnt] & 0x0F) >> 0];
  }
  

}

/*
 * int isxString(char *str)
 *
 * description:
 *   return 1 if all char in str are hexadecimal
 *   return 0 otherwise
 *
 */
int isxString(const char *str) {
  unsigned int i;
  const char *dp = str;
  for (i=0; i<strlen(str); i++) {
    if (! isxdigit(*dp) ) {
      return 0;
    }
  }
  return 1;
}

/*
 * strInBinary looks for char array pattern of length patternLen in a char array
 * blob of length blobLen
 *
 * return a pointer for the first occurrence of pattern in blob, if found
 * otherwise, return NULL
 * 
 */
char *
strInBinary (const char *pattern, unsigned int patternLen, 
             const char *blob, unsigned int blobLen) {
  int found = 0;
  char *cp = (char *)blob;

  while (1) {
    if (blob+blobLen-cp < (int) patternLen) break;
    if (*cp == pattern[0]) {
      if (memcmp(cp, pattern, patternLen) == 0) {
        found = 1;
        break;
      }
    }
    cp++; 
  }
  if (found) return cp;
  else return NULL;
}

/**
 * checks if a character c is a number letter or _ 
 *
 * @param c The character to be checked
 *
 * @return 1 if character c is a number letter or _ otherwise 0
 */
int
isalnum_ (char c) {
  if (isalnum(c) || c == '_') return 1;
  else return 0;
}

int
offset2Alnum_ (const char *p, int range) {
  const char *cp = p;

  while ((cp < (p+range)) && !isalnum_(*cp)) {
    cp++;
  }

  if (cp < (p+range)) {
    return (cp-p);
  } else {
    return -1;
  }
}

/**
 * checks if a file exists
 *
 * @param filename the full path of the file to be checked its existance
 * 
 * @return true if the file exists otherwise false
 */
bool file_exists_with_name(const std::string& filename) {
    ifstream f(filename.c_str());
    return f.good();
}

/**
 * return the files if it succeed to open the file
 *
 * @param filename the full path of the file 
 * 
 * @return return the file size in byte or -1 if failed
 */
ssize_t file_size(const std::string& filename) {
  ifstream cur_file(filename.c_str(), ios::binary | ios::ate);
  if (!cur_file.good()) {
      fprintf(stderr, "Error opening payload for capacity analyze.");
      return -1;
  }
            
  return cur_file.tellg();
}
