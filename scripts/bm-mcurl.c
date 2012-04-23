/* Copyright 2012 Zachary Weinberg
   Copying and distribution of this file, with or without modification, are
   permitted in any medium without royalty provided the copyright notice
   and this notice are preserved. This file is offered as-is, without any
   warranty.

   Use libcurl to retrieve many URLs, according to a wildcard pattern,
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

#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>
#include "tool_urlglob.h"

#define NORETURN void __attribute__((noreturn))
#define UNUSED __attribute__((unused))

static bool verbose = false;

static inline double
timevaldiff(const struct timeval *start, const struct timeval *finish)
{
  double s = finish->tv_sec - start->tv_sec;
  s += ((double)(finish->tv_usec - start->tv_usec)) / 1.0e6;
  return s;
}

struct url_iter
{
  char **upats;
  URLGlob *uglob;
  int nglob;
};

static inline struct url_iter
url_prep(char **upats)
{
  struct url_iter it;
  it.upats = upats;
  it.uglob = NULL;
  it.nglob = -1;
  return it;
}

static char *
url_next(struct url_iter *it)
{
  char *url;

  if (!it->uglob) {
    for (;;) {
      if (!*it->upats)
        return 0;
      if (!glob_url(&it->uglob, *it->upats, &it->nglob, stderr)) {
        if (verbose)
          fprintf(stderr, "# %s\n", *it->upats);
        break;
      }
      it->upats++;
    }
  }

  if (glob_next_url(&url, it->uglob))
    abort();
  if (--it->nglob == 0) {
    glob_cleanup(it->uglob);
    it->uglob = 0;
    it->upats++;
  }
  return url;
}

static size_t
discard_data(char *ptr UNUSED, size_t size, size_t nmemb, void *userdata UNUSED)
{
  return size * nmemb;
}

static size_t
read_abort(void *ptr UNUSED, size_t size UNUSED, size_t nmemb UNUSED,
           void *userdata UNUSED)
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

  /*SET_OR_CRASH(h, CURLOPT_VERBOSE,         (unsigned long)verbose);*/
  SET_OR_CRASH(h, CURLOPT_NOPROGRESS,      1L);
  SET_OR_CRASH(h, CURLOPT_FAILONERROR,     1L);
  SET_OR_CRASH(h, CURLOPT_USERAGENT,       "bm-mcurl/0.1");
  SET_OR_CRASH(h, CURLOPT_ENCODING,        "");
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

  return h;
}

static void
process_urls(struct url_iter *it, CURLM *multi, CURL **handles,
             unsigned long limit, double interval)
{
  struct timeval last, now, timeout;
  fd_set fdread;
  fd_set fdwrite;
  fd_set fdexcept;
  int maxfd = -1;
  int rc;
  int still_running;
  int dummy;
  unsigned long maxh = 0;
  unsigned long i;
  CURLMsg *msg;
  CURL *h;
  char *url;
  double d_timeout;
  long curl_timeout;
  bool no_more_urls = false;

  last.tv_sec = 0;
  last.tv_usec = 0;

  for (;;) {
    /* possibly queue another URL for download */
    if (!no_more_urls) {
      gettimeofday(&now, 0);
      if (timevaldiff(&last, &now) >= interval && maxh < limit) {
        last = now;
        url = url_next(it);
        if (url) {
          if (curl_easy_setopt(handles[maxh], CURLOPT_URL, url))
            abort();
          if (curl_multi_add_handle(multi, handles[maxh]))
            abort();
          maxh++;
          free(url); /* curl takes a copy */
        } else
          no_more_urls = true;
      }
    }

    /* call curl_multi_perform as many times as it wants */
  again:
    switch (curl_multi_perform(multi, &still_running)) {
    case CURLM_OK: break;
    case CURLM_CALL_MULTI_PERFORM: goto again;
    default:
      abort();
    }
    if (no_more_urls && still_running == 0)
      break;

    /* clean up finished downloads */
    while ((msg = curl_multi_info_read(multi, &dummy))) {
      if (msg->msg != CURLMSG_DONE)
        abort(); /* no other messages are defined as of Feb 2012 */
      h = msg->easy_handle;
      if (verbose) {
        double rqtime = 0.0;
        char *url = "<?>";
        curl_easy_getinfo(h, CURLINFO_EFFECTIVE_URL, &url);
        curl_easy_getinfo(h, CURLINFO_TOTAL_TIME, &rqtime);
        fprintf(stderr, "%f %s\n", rqtime, url);
      }
      if (curl_multi_remove_handle(multi, h) != CURLM_OK)
        abort();
      for (i = 0; i < maxh; i++) {
        if (handles[i] == h)
          goto found;
      }
      abort();
    found:
      /* shuffle 'h' to the beginning of the set of handles not
         currently in use */
      handles[i] = handles[--maxh];
      handles[maxh] = h;
    }

    /* wait for external event or timeout */
    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcept);
    curl_multi_fdset(multi, &fdread, &fdwrite, &fdexcept, &maxfd);

    curl_multi_timeout(multi, &curl_timeout);
    if (curl_timeout >= 0)
      d_timeout = ((double)curl_timeout) / 1000.0;
    else
      d_timeout = 1;
    if (d_timeout > interval)
      d_timeout = interval;

    timeout.tv_sec = floor(d_timeout);
    timeout.tv_usec = lrint((d_timeout - timeout.tv_sec) * 1e6);

    do
      rc = select(maxfd+1, &fdread, &fdwrite, &fdexcept, &timeout);
    while (rc == -1 && errno == EINTR);
    if (rc == -1)
      abort();
  }
}

static void
run(double interval, unsigned long limit, char *proxy, char **upats)
{
  struct url_iter it;
  CURLM *multi;
  CURL **handles;
  unsigned long n;

  curl_global_init(CURL_GLOBAL_ALL);
  multi = curl_multi_init();
  if (!multi) abort();

  handles = calloc(limit, sizeof(CURL *));
  for (n = 0; n < limit; n++) {
    handles[n] = setup_curl_easy_handle(proxy);
  }

  it = url_prep(upats);
  process_urls(&it, multi, handles, limit, interval);

  for (n = 0; n < limit; n++) {
    curl_easy_cleanup(handles[n]);
  }
  free(handles);
  curl_multi_cleanup(multi);
  curl_global_cleanup();
}

static NORETURN
usage(const char *av0, const char *complaint)
{
  fprintf(stderr,
          "%s\nusage: %s [-v] cps limit proxy url [url...]\n",
          complaint, av0);
  exit(2);
}

int
main(int argc, char **argv)
{
  unsigned long cps;
  unsigned long limit;
  char *endp;

  if (argv[1] && (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--verbose"))) {
    verbose = true;
    argc--;
    argv[1] = argv[0];
    argv++;
  }

  if (argc < 5)
    usage(argv[0], "not enough arguments");

  cps = strtoul(argv[1], &endp, 10);
  if (endp == argv[1] || *endp)
    usage(argv[0], "cps must be a positive integer (connections per second)");

  limit = strtoul(argv[2], &endp, 10);
  if (endp == argv[2] || *endp)
    usage(argv[0],
          "limit must be a positive integer (max outstanding requests)");

  if (limit == 0)
    usage(argv[0], "minimum number of outstanding requests is 1");

  run(1./(double)cps, limit, argv[3], argv+4);
  return 0;
}
