/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"

#include "connections.h"
#include "container.h"
#include "crypt.h"
#include "listener.h"
#include "protocol.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>

#include <event2/event.h>
#include <event2/dns.h>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

static struct event_base *the_event_base;

/**
   Puts obfsproxy's networking subsystem on "closing time" mode. This
   means that we stop accepting new connections and we shutdown when
   the last connection is closed.

   If 'barbaric' is set, we forcefully close all open connections and
   finish shutdown.

   (Only called by signal handlers)
*/
static void
start_shutdown(int barbaric)
{
  listener_close_all();          /* prevent further connections */
  conn_start_shutdown(barbaric); /* possibly break existing connections */
}

/** Stop obfsproxy's event loop. Final cleanup happens in main().
    Called by conn_start_shutdown and/or conn_free (see connections.c). */
void
finish_shutdown(void)
{
  log_debug("Finishing shutdown.");
  event_base_loopexit(the_event_base, NULL);
}

/**
   This is called when we receive a signal.
   It figures out the signal type and acts accordingly.

   Current behavior:
   SIGINT: On a single SIGINT we stop accepting new connections,
           keep the already existing connections open,
           and terminate when they all close.
           On a second SIGINT we shut down immediately but cleanly.
   SIGTERM: Shut down obfsproxy immediately but cleanly.
*/
static void
handle_signal_cb(evutil_socket_t fd, short what, void *arg)
{
  static int got_sigint = 0;
  int signum = (int) fd;

  obfs_assert(signum == SIGINT || signum == SIGTERM);

  if (signum == SIGINT && !got_sigint) {
    got_sigint++;
    log_info("Normal shutdown on SIGINT "
             "(%ld connection%s, %ld circuit%s remain)",
             conn_count(), conn_count() == 1 ? "" : "s",
             circuit_count(), circuit_count() == 1 ? "" : "s");
    start_shutdown(0);
  } else {
    log_info("Barbaric shutdown on %s "
             "(%ld connection%s, %ld circuit%s will be broken)",
             signum == SIGINT ? "SIGINT" : "SIGTERM",
             conn_count(), conn_count() == 1 ? "" : "s",
             circuit_count(), circuit_count() == 1 ? "" : "s");
    start_shutdown(1);
  }
}

/**
   Prints the obfsproxy usage instructions then exits.
*/
static void ATTR_NORETURN
usage(void)
{
  const proto_vtable *const *p;

  fputs("Usage: obfsproxy protocol_name [protocol_args] protocol_options "
        "protocol_name ...\n"
        "* Available protocols:\n", stderr);
  /* this is awful. */
  for (p = supported_protocols; *p; p++)
    fprintf(stderr,"[%s] ", (*p)->name);
  fprintf(stderr, "\n* Available arguments:\n"
          "--log-file=<file> ~ set logfile\n"
          "--log-min-severity=warn|info|debug ~ set minimum logging severity\n"
          "--no-log ~ disable logging\n");

  exit(1);
}

/**
   Receives 'argv' and scans for any obfsproxy optional arguments and
   tries to set them in effect.

   If it succeeds it returns the number of argv arguments its caller
   should skip to get past the optional arguments we already handled.
   If it fails, it exits obfsproxy.
*/
static int
handle_obfsproxy_args(const char *const *argv)
{
  int logmethod_set=0;
  int logsev_set=0;
  int i=1;

  while (argv[i] &&
         !strncmp(argv[i],"--",2)) {
    if (!strncmp(argv[i], "--log-file=", 11)) {
      if (logmethod_set) {
        log_warn("You've already set a log file!");
        exit(1);
      }
      if (log_set_method(LOG_METHOD_FILE,
                         (char *)argv[i]+11) < 0) {
        log_warn("Failed creating logfile.");
        exit(1);
      }
      logmethod_set=1;
    } else if (!strncmp(argv[i], "--log-min-severity=", 19)) {
      if (logsev_set) {
        log_warn("You've already set a min. log severity!");
        exit(1);
      }
      if (log_set_min_severity((char *)argv[i]+19) < 0) {
        log_warn("Error at setting logging severity");
        exit(1);
      }
      logsev_set=1;
    } else if (!strncmp(argv[i], "--no-log", 9)) {
        if (logsev_set) {
          printf("You've already set a min. log severity!\n");
          exit(1);
        }
        if (log_set_method(LOG_METHOD_NULL, NULL) < 0) {
          printf("Error at setting logging severity.\n");
          exit(1);
        }
        logsev_set=1;
    } else {
      log_warn("Unrecognizable obfsproxy argument '%s'", argv[i]);
      exit(1);
    }
    i++;
  }

  return i;
}

int
main(int argc, const char *const *argv)
{
  struct event *sig_int;
  struct event *sig_term;
  smartlist_t *configs = smartlist_create();
  const char *const *begin;
  const char *const *end;

  /* Handle optional obfsproxy arguments. */
  begin = argv + handle_obfsproxy_args(argv);

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
      smartlist_t *s = smartlist_create();
      char *joined;
      const char *const *p;
      for (p = begin; p < end; p++)
        smartlist_add(s, (void *)*p);
      joined = smartlist_join_strings(s, " ", 0, NULL);
      log_debug("Configuration %d: %s", smartlist_len(configs)+1, joined);
      free(joined);
      smartlist_free(s);
    }
    if (end == begin+1) {
      log_warn("No arguments for configuration %d", smartlist_len(configs)+1);
      usage();
    } else {
      config_t *cfg = config_create(end - begin, begin);
      if (!cfg)
        return 2; /* diagnostic already issued */
      smartlist_add(configs, cfg);
    }
    begin = end;
  } while (*begin);
  obfs_assert(smartlist_len(configs) > 0);

  /* Configurations have been established; proceed with initialization. */
  conn_initialize();

  /* Ugly method to fix a Windows problem:
     http://archives.seul.org/libevent/users/Oct-2010/msg00049.html */
#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(0x101, &wsaData);
#endif

  /* Initialize crypto */
  if (initialize_crypto() < 0) {
    log_error("Failed to initialize cryptography.");
  }

  /* Initialize libevent */
  the_event_base = event_base_new();
  if (!the_event_base) {
    log_error("Failed to initialize networking.");
  }

  /* ASN should this happen only when SOCKS is enabled? */
  if (init_evdns_base(the_event_base)) {
    log_error("Failed to initialize DNS resolver.");
  }

  /* Handle signals. */
#ifdef SIGPIPE
   signal(SIGPIPE, SIG_IGN);
#endif
  sig_int = evsignal_new(the_event_base, SIGINT,
                         handle_signal_cb, NULL);
  sig_term = evsignal_new(the_event_base, SIGTERM,
                          handle_signal_cb, NULL);
  if (event_add(sig_int,NULL) || event_add(sig_term,NULL)) {
    log_error("Failed to initialize signal handling.");
    return 1;
  }

  /* Open listeners for each configuration. */
  SMARTLIST_FOREACH(configs, config_t *, cfg, {
    if (!listener_open(the_event_base, cfg)) {
      log_error("Failed to open listeners for configuration %d", cfg_sl_idx+1);
      return 1;
    }
  });

  /* We are go for launch. */
  log_info("Obfsproxy process %lu now initialized",
           (unsigned long)getpid());

  event_base_dispatch(the_event_base);

  /* We have landed. */
  log_info("Exiting.");

  /* By the time we get to this point, all listeners and connections
     have already been freed. */

  SMARTLIST_FOREACH(configs, config_t *, cfg, config_free(cfg));
  smartlist_free(configs);

  evdns_base_free(get_evdns_base(), 0);
  event_free(sig_int);
  event_free(sig_term);
  event_base_free(the_event_base);

  cleanup_crypto();
  close_obfsproxy_logfile();

  return 0;
}
