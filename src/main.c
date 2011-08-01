/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"

#include "container.h"
#include "crypt.h"
#include "network.h"
#include "protocol.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>

#include <event2/event.h>
#include <event2/dns.h>

static struct event_base *the_event_base;

/**
   Prints the obfsproxy usage instructions then exits.
*/
static void ATTR_NORETURN
usage(void)
{
  int i;
  fputs("Usage: obfsproxy protocol_name [protocol_args] protocol_options "
        "protocol_name ...\n"
        "* Available protocols:\n", stderr);
  /* this is awful. */
  for (i=0;i<n_supported_protocols;i++)
    fprintf(stderr,"[%s] ", supported_protocols[i]->name);
  fprintf(stderr, "\n* Available arguments:\n"
          "--log-file=<file> ~ set logfile\n"
          "--log-min-severity=warn|info|debug ~ set minimum logging severity\n"
          "--no-log ~ disable logging\n");

  exit(1);
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
  int signum = (int) fd;
  static int got_sigint=0;

  switch (signum) {
  case SIGINT:
    free_all_listeners();
    if (!got_sigint) {
      log_info("Got SIGINT. Preparing shutdown.");
      start_shutdown(0);
      got_sigint++;
    } else {
      log_info("Got SIGINT for the second time. Terminating.");
      start_shutdown(1);
    }
    break;
  case SIGTERM:
    log_info("Got SIGTERM. Terminating.");
    start_shutdown(1);
    break;
  }
}

/** Stop obfsproxy's event loop. Final cleanup happens in main(). */
void
finish_shutdown(void)
{
  log_debug("Finishing shutdown.");
  event_base_loopexit(the_event_base, NULL);
}

/** Return 1 if 'name' is the name of a supported protocol, otherwise 0. */
static int
is_supported_protocol(const char *name)
{
  int i;
  for (i = 0; i < n_supported_protocols; i++)
    if (!strcmp(name, supported_protocols[i]->name))
      return 1;

  return 0;
}

/**
   Receives 'argv' and scans for any obfsproxy optional arguments and
   tries to set them in effect.

   If it succeeds it returns the number of argv arguments its caller
   should skip to get past the optional arguments we already handled.
   If it fails, it exits obfsproxy.
*/
static int
handle_obfsproxy_args(const char **argv)
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
main(int argc, const char **argv)
{
  struct event *sig_int;
  struct event *sig_term;

  /* Array of argument counts, one per listener. */
  int *listener_argcs = NULL;

  /* Array of pointers into argv. Each points to the beginning of a
     sequence of options for a particular listener. */
  const char *const **listener_argvs = NULL;

  /* Total number of listeners requested on the command line. */
  unsigned int n_listeners;

  /* Total number of listeners successfully created. */
  unsigned int n_good_listeners;

  /* Index of the first argv string after the optional obfsproxy
      arguments. Normally this should be where the listeners start. */
  int start_of_listeners;

  int cl, i;

  /* Handle optional obfsproxy arguments. */
  start_of_listeners = handle_obfsproxy_args(argv);

  if (!is_supported_protocol(argv[start_of_listeners]))
    usage();

  /* Count number of listeners and allocate space for the listener-
     argument arrays. We already know there's at least one. */
  n_listeners = 1;
  for (i = start_of_listeners+1; i < argc; i++)
    if (is_supported_protocol(argv[i]))
      n_listeners++;

  log_debug("%d listener%s on command line.",
            n_listeners, n_listeners == 1 ? "" : "s");
  listener_argcs = xzalloc(n_listeners * sizeof(int));
  listener_argvs = xzalloc(n_listeners * sizeof(char **));

  /* Each listener's argument vector consists of the entries in argv
     from its recognized protocol name, up to but not including
     the next recognized protocol name. */
  cl = 1;
  listener_argvs[0] = &argv[start_of_listeners];
  for (i = start_of_listeners + 1; i < argc; i++)
    if (is_supported_protocol(argv[i])) {
      listener_argcs[cl-1] = i - (listener_argvs[cl-1] - argv);
      if (listener_argcs[cl-1] == 1)
        log_warn("No arguments to listener %d", cl);

      listener_argvs[cl] = &argv[i];
      cl++;
    }

  listener_argcs[cl-1] = argc - (listener_argvs[cl-1] - argv);
  if (listener_argcs[cl-1] == 1)
    log_warn("No arguments to listener %d", cl);

  obfs_assert(cl == n_listeners);

  if (log_do_debug()) {
    smartlist_t *s = smartlist_create();
    char *joined;
    for (cl = 0; cl < n_listeners; cl++) {
      smartlist_clear(s);
      for (i = 0; i < listener_argcs[cl]; i++)
        smartlist_add(s, (void *)listener_argvs[cl][i]);
      joined = smartlist_join_strings(s, " ", 0, NULL);
      log_debug("Listener %d: %s", cl+1, joined);
    }
    smartlist_free(s);
  }

  /* argv has been chunked; proceed with initialization. */

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

  /* Open a new listener for each protocol. */
  n_good_listeners = 0;
  for (cl = 0; cl < n_listeners; cl++)
    if (create_listener(the_event_base,
                        listener_argcs[cl], listener_argvs[cl]))
      n_good_listeners++;

  /* If the number of usable listeners is not equal to the complete
     set specified on the command line, we have a usage error.
     Diagnostics have already been issued.  */
  log_debug("%d recognized listener%s on command line, %d with valid config",
            n_listeners, n_listeners == 1 ? "" : "s", n_good_listeners);
  if (n_listeners != n_good_listeners)
    return 2;

  /* We are go for launch. */
  event_base_dispatch(the_event_base);

  log_info("Exiting.");

  free_all_listeners();
  evdns_base_free(get_evdns_base(), 0);
  event_free(sig_int);
  event_free(sig_term);
  event_base_free(the_event_base);

  cleanup_crypto();

  close_obfsproxy_logfile();
  free(listener_argvs);
  free(listener_argcs);

  return 0;
}
