/* Use libcurl to retrieve many URLs, according to a wildcard pattern,
   starting new connections at a constant rate until we hit a limit.

   Command line arguments -- all are required, but 'proxy' may be an
   empty string if you want direct connections:

       bm-mcurl [-v] rate limit proxy url-pattern [url-pattern ...]

   There is no output; it is assumed that you are monitoring traffic
   externally.  Passing -v turns on CURLOPT_VERBOSE debugging spew.
 */

#define _XOPEN_SOURCE 600

#include <stdbool.h>
#include <stddef.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>
#include "tool_urlglob.h"

#define NORETURN __attribute__((noreturn))

static bool verbose = false;

static size_t
discard_data(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  return size * nmemb;
}

static size_t
read_abort(void *ptr, size_t size, size_t nmemb, void *userdata)
{
  /* we don't do anything that should require this to be called,
     so if it does get called, something is wrong */
  return CURL_READFUNC_ABORT;
}

static CURL *
setup_curl_easy_handle(char *proxy)
{
  CURL *h = curl_easy_init();
  if (!h) abort();

#define SET_OR_CRASH(h, opt, param) \
  do { if (curl_easy_setopt(h, opt, param)) abort(); } while (0)

  SET_OR_CRASH(h, CURLOPT_VERBOSE,         (unsigned long)verbose);
  SET_OR_CRASH(h, CURLOPT_NOPROGRESS,      1L);
  SET_OR_CRASH(h, CURLOPT_FAILONERROR,     1L);
  SET_OR_CRASH(h, CURLOPT_USERAGENT,       "bm-mcurl/0.1");
  SET_OR_CRASH(h, CURLOPT_ACCEPT_ENCODING, "");
  SET_OR_CRASH(h, CURLOPT_AUTOREFERER,     1L);
  SET_OR_CRASH(h, CURLOPT_FOLLOWLOCATION,  1L);
  SET_OR_CRASH(h, CURLOPT_MAXREDIRS,       30L);

  SET_OR_CRASH(h, CURLOPT_WRITEFUNCTION,   discard_data);
  SET_OR_CRASH(h, CURLOPT_WRITEDATA,       NULL);
  SET_OR_CRASH(h, CURLOPT_READFUNCTION,    read_abort);
  SET_OR_CRASH(h, CURLOPT_READDATA,        NULL);

  if (proxy && proxy[0]) {
    SET_OR_CRASH(h, CURLOPT_PROXY,         proxy);
    SET_OR_CRASH(h, CURLOPT_PROXYTYPE,     CURLPROXY_SOCKS5_HOSTNAME);
  }
#undef SET_OR_CRASH
}

static bool
process_events_once(CURLM *multi, unsigned long timeout_max)
{
  struct timeval tv;
  int rc; /* select() return code */

  fd_set fdread;
  fd_set fdwrite;
  fd_set fdexcept;
  int maxfd = -1;

  unsigned long timeout = 1000000; /* one second - ultimate default */
  long curl_tout_ms = -1;

  /* get fd sets for all pending transfers */
  FD_ZERO(&fdread);
  FD_ZERO(&fdwrite);
  FD_ZERO(&fdexcept);
  curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcept, &maxfd);

  /* timeout */
  if (timeout_max > 0 && timeout_max < timeout)
    timeout = timeout_max;

  curl_multi_timeout(multi_handle, &curl_tout_ms);

  if (curl_tout_ms >= 0) {
    unsigned long curl_tout_us = ((unsigned long)curl_tout_ms) * 1000;
    if (timeout > curl_tout_us)
      timeout = curl_tout_us;
  }

  tv.tv_sec = timeout / 1000000;
  if(tv.tv_sec >= 1)
    tv.tv_sec = 1;
  else
    tv.tv_usec = timeout % 1000000;

  do {
    rc = select(maxfd+1, &fdread, &fdwrite, &fdexcept, &tv);
  } while (rc == -1 && errno == EINTR);

  if (rc > 0) {
    int still_running;
    curl_multi_perform(multi_handle, &still_running);
    return !!still_running;
  } else
    abort();
}

/* Note: this function must not return until we are ready to start
   another connection. */
static void
queue_one(CURLM *multi, unsigned long rate, unsigned long limit,
          char *proxy, char *url)
{

}

static void
run(unsigned long rate, unsigned long limit, char *proxy, char **urls)
{
  CURLM *multi;
  curl_global_init();
  multi = curl_multi_init();
  if (!multi) abort();

  for (char **upat = urls; *upat; url++) {
    URLGlob *uglob;
    int *n;
    if (glob_url(&uglob, *upat, &n, stderr))
      continue;
    do {
      char *url;
      if (glob_next_url(&url, uglob)) abort();
      queue_one(multi, rate, limit, proxy, url); /* takes ownership */
    } while (--n);
    glob_cleanup(uglob);
  }

  /* spin the event loop until all outstanding transfers complete */
  while (process_events_once(multi, 0));

  curl_multi_cleanup(multi);
}

static NORETURN
usage(const char *av0, const char *complaint)
{
  fprintf(stderr,
          "%s\nusage: %s [-v] rate limit proxy url [url...]\n",
          complaint, av0);
  exit(2);
}

int
main(int argc, char **argv)
{
  unsigned long rate;
  unsigned long limit;
  char *endp;

  if (argv[1] && (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--verbose"))) {
    verbose = true;
    argc--;
    argv[1] = argv[0];
    argv++;
  }

  if (argc < 5)
    usage("not enough arguments");

  rate = strtoul(argv[1], &endp, 10);
  if (endp == argv[1] || *endp)
    usage("rate must be a positive integer (connections per second)");

  limit = strtoul(argv[2], &endp, 10);
  if (endp == argv[2] || *endp)
    usage("limit must be a positive integer (max outstanding requests)");

  run(rate, limit, argv[3], argv+4);
  return 0;
}
