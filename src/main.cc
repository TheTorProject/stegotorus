/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "main.h"

#include "connections.h"
#include "crypt.h"
#include "listener.h"
#include "protocol.h"

#include <vector>
#include <string>

#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <process.h>
#include <io.h>
#else
#include <unistd.h>
#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
#endif
#endif

#include <event2/event.h>
#include <event2/dns.h>

using std::vector;
using std::string;

static struct event_base *the_event_base;
static bool allow_kq = false;

/**
   Puts stegotorus's networking subsystem on "closing time" mode. This
   means that we stop accepting new connections and we shutdown when
   the last connection is closed.

   If 'barbaric' is set, we forcefully close all open connections and
   finish shutdown.

   (Only called by signal handlers)
*/
static void
start_shutdown(int barbaric, const char *label)
{
  log_info("%s shutdown triggered by %s "
           "(%lu connection%s, %lu circuit%s %s)",
           barbaric ? "barbaric" : "normal", label,
           (unsigned long)conn_count(), conn_count() == 1 ? "" : "s",
           (unsigned long)circuit_count(), circuit_count() == 1 ? "" : "s",
           barbaric ? "will be broken" : "remain");

  listener_close_all();          /* prevent further connections */
  conn_start_shutdown(barbaric); /* possibly break existing connections */
}

/** Stop stegotorus's event loop. Final cleanup happens in main().
    Called by conn_start_shutdown and/or conn_free (see connections.c). */
void
finish_shutdown(void)
{
  log_debug("finishing shutdown");
  event_base_loopexit(the_event_base, NULL);
}

/**
   This is called when we receive an asynchronous signal.
   It figures out the signal type and acts accordingly.

   Current behavior:
   SIGINT: On a single SIGINT we stop accepting new connections,
           keep the already existing connections open,
           and terminate when they all close.
           On a second SIGINT we shut down immediately but cleanly.
   SIGTERM: Shut down immediately but cleanly.
*/
static void
handle_signal_cb(evutil_socket_t fd, short, void *)
{
  static int got_sigint = 0;
  int signum = (int) fd;

  log_assert(signum == SIGINT || signum == SIGTERM);

  if (signum == SIGINT && !got_sigint) {
    got_sigint++;
    start_shutdown(0, "SIGINT");
  } else {
    start_shutdown(1, signum == SIGINT ? "SIGINT" : "SIGTERM");
  }
}

/**
   This is called when we receive a synchronous signal that indicates
   a fatal programming error (SIGSEGV and friends). Unlike the above,
   this is a regular old signal handler, *not* mediated through
   libevent; that wouldn't work.
*/
#ifndef _WIN32
static void
lethal_signal(int signum, siginfo_t *si, void *)
{
  char faultmsg[80];
#ifdef HAVE_EXECINFO_H
  int n;
  void *backtracebuf[256];
#endif

  /* Print a basic diagnostic first. */
  xsnprintf(faultmsg, sizeof faultmsg,
            sizeof(unsigned long) == 4
            ? "\n[error] %s at %08lx\n"
            : "\n[error] %s at %016lx\n",
            strsignal(signum), (unsigned long)si->si_addr);
  /* we really, truly don't care about a short write here */
  if(write(2, faultmsg, strlen(faultmsg))) {}

#ifdef HAVE_EXECINFO_H
  /* Now do a backtrace if we can. */
  n = backtrace(backtracebuf, sizeof backtracebuf / sizeof(void*));
  backtrace_symbols_fd(backtracebuf, n, 2);
#endif

  /* Falling off the end of this function will cause the kernel to
     reassert the original signal, which (because we use SA_RESETHAND
     below) will now take the default action and kill the process. */
}
#endif

/**
   Largely because Windows and signals don't mix for beans, there is
   another way to trigger a clean shutdown: if standard input is a
   pipe, socket, or terminal, we will shut down non-barbarically when
   that channel receives an EOF.
*/
static void
stdin_detect_eof_cb(evutil_socket_t fd, short, void *arg)
{
  size_t nread = 0;
  ssize_t r;
  char buf[4096];
  for (;;) {
    r = read(fd, buf, sizeof buf);
    if (r <= 0) break;
    nread += r;
  }

  log_debug("read %lu bytes from stdin", (unsigned long)nread);
  if (nread == 0) {
    struct event *ev = (struct event *)arg;
    event_del(ev);
    start_shutdown(0, "stdin closing");
  }
}

/**
   Prints usage instructions then exits.
*/
static void ATTR_NORETURN
usage(void)
{
  const proto_module *const *p;

  fputs("usage: stegotorus protocol_name [protocol_args] protocol_options "
        "protocol_name ...\n"
        "* Available protocols:\n", stderr);
  /* this is awful. */
  for (p = supported_protos; *p; p++)
    fprintf(stderr,"[%s] ", (*p)->name);
  fprintf(stderr, "\n* Available arguments:\n"
          "--log-file=<file> ~ set logfile\n"
          "--log-min-severity=warn|info|debug ~ set minimum logging severity\n"
          "--no-log ~ disable logging\n"
          "--allow-kqueue ~ allow use of kqueue(2) (may be buggy)\n");

  exit(1);
}

/**
   Receives 'argv' and scans for any non-protocol-specific optional
   arguments and tries to set them in effect.

   If it succeeds it returns the number of argv arguments its caller
   should skip to get past the optional arguments we already handled.
   If it fails, it exits the program.
*/
static int
handle_generic_args(const char *const *argv)
{
  bool logmethod_set = false;
  bool logsev_set = false;
  bool allow_kq_set = false;
  int i = 1;

  while (argv[i] &&
         !strncmp(argv[i],"--",2)) {
    if (!strncmp(argv[i], "--log-file=", 11)) {
      if (logmethod_set) {
        log_warn("you've already set a log file!");
        exit(1);
      }
      if (log_set_method(LOG_METHOD_FILE,
                         (char *)argv[i]+11) < 0) {
        log_warn("failed creating logfile");
        exit(1);
      }
      logmethod_set=1;
    } else if (!strncmp(argv[i], "--log-min-severity=", 19)) {
      if (logsev_set) {
        log_warn("you've already set a min. log severity!");
        exit(1);
      }
      if (log_set_min_severity((char *)argv[i]+19) < 0) {
        log_warn("error at setting logging severity");
        exit(1);
      }
      logsev_set = true;
    } else if (!strcmp(argv[i], "--no-log")) {
        if (logsev_set) {
          fprintf(stderr, "you've already set a min. log severity!\n");
          exit(1);
        }
        if (log_set_method(LOG_METHOD_NULL, NULL) < 0) {
          fprintf(stderr, "error at setting logging severity.\n");
          exit(1);
        }
        logsev_set = true;
    } else if (!strcmp(argv[i], "--allow-kqueue")) {
      if (allow_kq_set) {
        fprintf(stderr, "you've already allowed kqueue!\n");
        exit(1);
      }
      allow_kq = true;
      allow_kq_set = true;
    } else {
      log_warn("unrecognizable argument '%s'", argv[i]);
      exit(1);
    }
    i++;
  }

  return i;
}

int
main(int, const char *const *argv)
{
  struct event_config *evcfg;
  struct event *sig_int;
  struct event *sig_term;
  struct event *stdin_eof;
  vector<config_t *> configs;
  const char *const *begin;
  const char *const *end;
  struct stat st;

  /* Set the logging defaults before doing anything else.  It wouldn't
     be necessary, but some systems don't let you initialize a global
     variable to stderr. */
  log_set_method(LOG_METHOD_STDERR, NULL);

  /* Handle optional non-protocol-specific arguments. */
  begin = argv + handle_generic_args(argv);

  /* Find the subsets of argv that define each configuration.
     Each configuration's subset consists of the entries in argv from
     its recognized protocol name, up to but not including the next
     recognized protocol name. */
  if (!*begin || !config_is_supported(*begin))
    usage();

  do {
    end = begin+1;
    while (*end && !config_is_supported(*end))
      end++;
    if (log_do_debug()) {
      string joined = *begin;
      const char *const *p;
      for (p = begin+1; p < end; p++) {
        joined += " ";
        joined += *p;
      }
      log_debug("configuration %lu: %s",
                (unsigned long)configs.size()+1, joined.c_str());
    }
    if (end == begin+1) {
      log_warn("no arguments for configuration %lu",
               (unsigned long)configs.size()+1);
      usage();
    } else {
      config_t *cfg = config_create(end - begin, begin);
      if (!cfg)
        return 2; /* diagnostic already issued */
      configs.push_back(cfg);
    }
    begin = end;
  } while (*begin);
  log_assert(configs.size() > 0);

  /* Configurations have been established; proceed with initialization. */

  /* Ugly method to fix a Windows problem:
     http://archives.seul.org/libevent/users/Oct-2010/msg00049.html */
#ifdef _WIN32
  {
    WSADATA wsaData;
    WSAStartup(0x101, &wsaData);
  }
#endif

  /* Configure and initialize libevent. */
  evcfg = event_config_new();
  if (!evcfg)
    log_abort("failed to initialize networking (evcfg)");

  /* The main reason we bother with an event_config object is that
     nobody's had time to track down the bugs that only the kqueue
     backend exposes and figure out whose fault they are. There is
     a command line switch waiting for the person who will do this
     detective work. */
  if (!allow_kq)
    if (event_config_avoid_method(evcfg, "kqueue"))
      log_abort("failed to initialize networking (avoiding kqueue)");

  /* Possibly worth doing in the future: activating Windows IOCP and
     telling it how many CPUs to use. */

  the_event_base = event_base_new_with_config(evcfg);
  if (!the_event_base)
    log_abort("failed to initialize networking (evbase)");

  /* ASN should this happen only when SOCKS is enabled? */
  if (init_evdns_base(the_event_base))
    log_abort("failed to initialize DNS resolver");

  /* Handle signals. */
#ifdef SIGPIPE
   signal(SIGPIPE, SIG_IGN);
#endif
  sig_int = evsignal_new(the_event_base, SIGINT,
                         handle_signal_cb, NULL);
  sig_term = evsignal_new(the_event_base, SIGTERM,
                          handle_signal_cb, NULL);
  if (event_add(sig_int, NULL) || event_add(sig_term, NULL))
    log_abort("failed to initialize signal handling");

#ifndef _WIN32
  /* trap and diagnose fatal signals */
  {
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    /* yes, we really do want a one-shot signal handler that doesn't block
       the signal while it executes, in this case */
    sa.sa_flags = SA_NODEFER|SA_RESETHAND|SA_SIGINFO;
    sa.sa_sigaction = lethal_signal;

    /* it doesn't matter if any of these fail */
    sigaction(SIGILL, &sa, 0);
    /* sigaction(SIGTRAP, &sa, 0);  would interfere with debuggers */
    sigaction(SIGABRT, &sa, 0);
    sigaction(SIGBUS,  &sa, 0);
    sigaction(SIGFPE,  &sa, 0);
    sigaction(SIGSEGV, &sa, 0);
  }
#endif

  /* Handle EOF-on-stdin. */
  if (!fstat(STDIN_FILENO, &st) &&
      (S_ISFIFO(st.st_mode) ||
#ifndef _WIN32
       S_ISSOCK(st.st_mode) ||
#endif
       (S_ISCHR(st.st_mode) && isatty(STDIN_FILENO)))) {
    /* We do this this way because we want to make the event itself the
       callback argument. */
    stdin_eof = (struct event *)xmalloc(event_get_struct_event_size());
    evutil_make_socket_nonblocking(STDIN_FILENO);
    event_assign(stdin_eof, the_event_base,
                 STDIN_FILENO, EV_READ|EV_PERSIST,
                 stdin_detect_eof_cb, stdin_eof);
    if (event_add(stdin_eof, 0))
      log_abort("failed to initialize stdin monitor");
  } else {
    stdin_eof = NULL;
  }

  /* Open listeners for each configuration. */
  for (vector<config_t *>::iterator i = configs.begin(); i != configs.end();
       i++)
    if (!listener_open(the_event_base, *i))
      log_abort("failed to open listeners for configuration %lu",
                (unsigned long)(i - configs.begin()) + 1);

  /* We are go for launch. As a signal to any monitoring process that may
     be running, close stdout now. */
  log_info("%s process %lu now initialized", argv[0], (unsigned long)getpid());
  fclose(stdout);

  event_base_dispatch(the_event_base);

  /* We have landed. */
  log_info("exiting");

  /* By the time we get to this point, all listeners and connections
     have already been freed. */

  for (vector<config_t *>::iterator i = configs.begin(); i != configs.end();
       i++)
    delete *i;

  evdns_base_free(get_evdns_base(), 0);
  event_free(sig_int);
  event_free(sig_term);
  free(stdin_eof);
  event_base_free(the_event_base);
  event_config_free(evcfg);
  log_close();

  return 0;
}
