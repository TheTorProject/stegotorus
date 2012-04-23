/* Copyright 2012 Zachary Weinberg
 *
 * Copying and distribution of this file, with or without modification, are
 * permitted in any medium without royalty provided the copyright notice
 * and this notice are preserved. This file is offered as-is, without any
 * warranty.
 */
#define _XOPEN_SOURCE 600
#define _POSIX_C_SOURCE 200112

#include <stdbool.h>
#include <stddef.h>

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if __GNUC__ >= 3
#define NORETURN void __attribute__((noreturn))
#else
#define NORETURN void
#endif

extern char **environ;

static NORETURN
error_400(const char *msg)
{
  char **p;
  printf("Status: 400 Bad Request\nContent-Type: text/plain\n\n"
         "400 Bad Request (%s)\nCGI environment dump follows:\n\n", msg);
  for (p = environ; *p; p++)
    puts(*p);
  exit(0);
}

static NORETURN
error_500(const char *syscall)
{
  printf("Status: 500 Internal Server Error\nContent-Type:text/plain\n\n"
         "500 Internal Server Error: %s: %s\n",
         syscall, strerror(errno));
  exit(0);
}

static void
generate(unsigned long rate, bool dryrun)
{
  timer_t timerid;
  struct sigevent sev;
  struct itimerspec its;
  sigset_t mask;
  int sig;
  char *data;
  size_t bufsz;

  /* Despite our use of the high-resolution interval timers, we cannot
     count on being scheduled more often than 1/CLOCKS_PER_SEC
     seconds.  We ask to be scheduled every 0.01 seconds to avoid a
     class of rounding errors, since it is very likely that we will be
     asked to generate at a rate that is a power of ten.

     Therefore, every time we are scheduled we should produce R/100
     bytes of data. */

  /* You send data at R bytes per second in 1400-byte blocks by
     calling write() every 1/(R/1400) second.  However, despite our
     use of the high-resolution interval timers, we cannot count on
     being scheduled more often than every 1/CLOCKS_PER_SEC seconds,
     so if we need to send data faster than that, bump up the block
     size instead.  */
  bufsz = rate / 100;

  its.it_value.tv_sec = 0;
  its.it_value.tv_nsec = 10000000; /* 1e7 ns = 0.01 s */
  its.it_interval.tv_sec = its.it_value.tv_sec;
  its.it_interval.tv_nsec = its.it_value.tv_nsec;

  if (dryrun) {
    printf("Content-Type: text/plain\n\n"
           "Goal %lu bytes per second:\n"
           "would send %zu bytes every 0.01 seconds\n"
           "  \"    \"    \"     \"     \"   %lu sec + %lu nsec\n",
           rate, bufsz,
           (unsigned long)its.it_value.tv_sec,
           (unsigned long)its.it_value.tv_nsec);
    return;
  }

  data = malloc(bufsz);
  if (!data)
    error_500("malloc");
  memset(data, 0, bufsz);

  fflush(stdout);
  setvbuf(stdout, 0, _IONBF, 0);
  fputs("Content-Type: application/octet-stream\n"
        "Cache-Control: no-store,no-cache\n\n", stdout);

  sigemptyset(&mask);
  sigaddset(&mask, SIGRTMIN);
  if (sigprocmask(SIG_SETMASK, &mask, 0))
    error_500("sigprocmask");

  memset(&sev, 0, sizeof sev);
  sev.sigev_notify = SIGEV_SIGNAL;
  sev.sigev_signo = SIGRTMIN;
  sev.sigev_value.sival_ptr = &timerid;
  if (timer_create(CLOCK_MONOTONIC, &sev, &timerid))
    error_500("timer_create");

  if (timer_settime(timerid, 0, &its, 0))
    error_500("timer_settime");

  do {
    size_t r, n = bufsz;
    char *p = data;
    do {
      r = fwrite(p, 1, n, stdout);
      if (r == 0)
        exit(1);
      n -= r;
      p += r;
    } while (n > 0);
  } while (sigwait(&mask, &sig) == 0);
}

int
main(void)
{
  unsigned long rate;
  char *endp;
  bool dryrun;
  char *request_method = getenv("REQUEST_METHOD");
  char *query_string = getenv("QUERY_STRING");
  char *path_info = getenv("PATH_INFO");

  if (!request_method || strcmp(request_method, "GET"))
    error_400("method not supported");
  if (query_string && strcmp(query_string, ""))
    error_400("no query parameters accepted");

  if (!path_info || path_info[0] != '/')
    error_400("malformed or missing PATH_INFO");

  rate = strtoul(path_info+1, &endp, 10);
  if (endp == path_info+1)
    error_400("missing rate (specify bytes per second)");

  if (endp[0] == '\0')
    dryrun = false;
  else if (endp[0] == ';' && endp[1] == 'd' && endp[2] == '\0')
    dryrun = true;
  else
    error_400("unrecognized extra arguments");

  generate(rate, dryrun);
  return 0;
}
