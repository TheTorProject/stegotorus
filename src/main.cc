/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
//#include "debug_new.h"

#include "connections.h"
#include "crypt.h"
#include "listener.h"
#include "modus_operandi.h"
#include "protocol.h"
#include "steg.h"
#include "subprocess.h"

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

static bool allow_kq = false;
static bool daemon_mode = false;
static string pidfile_name;
static string registration_helper;

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

/**
   This is called when we receive an asynchronous signal.
   It figures out the signal type and acts accordingly.

   Old behavior (never worked properly):
   SIGINT: On a single SIGINT we stop accepting new connections,
           keep the already existing connections open,
           and terminate when they all close.
           On a second SIGINT we shut down immediately but cleanly.
   Current behavior:
   SIGINT/SIGTERM: Shut down immediately but cleanly.
*/
static void
handle_signal_cb(evutil_socket_t fd, short, void *)
{
  //static int got_sigint = 0;
  int signum = (int) fd;

  log_assert(signum == SIGINT || signum == SIGTERM);
  start_shutdown(1, signum == SIGINT ? "SIGINT" : "SIGTERM");
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
   APRAdb registration hook.
*/
static void
call_registration_helper(string const& helper)
{
  vector<string> env = get_environ("ST_");
  env.push_back("ST_SERVER_KEY=placeholder_server_key");

  vector<listener_t*> const& listeners = get_all_listeners();
  vector<listener_t*>::const_iterator el;
  unsigned int n = 0;
  char buf[512];

  for (el = listeners.begin(); el != listeners.end(); el++, n++) {
    const steg_config_t *sc = (*el)->cfg->get_steg((*el)->index);
    if (!sc)
      continue;

    // The address is in the form x.y.z.w:port or [a:b:c...]:port.
    // We want IP and port in separate strings.  Also, in the latter
    // case, we want to get rid of the square brackets.
    string ap((*el)->address);
    size_t colon = ap.rfind(':');
    string addr(ap, 0, colon);
    string port(ap, colon+1);

    if (addr[0] == '[') {
      addr.erase(addr.size()-1, 1);
      addr.erase(0,1);
    }

    if (xsnprintf(buf, sizeof buf, "ST_LISTENER_%u=%s,tcp,%s,%s",
                  n, addr.c_str(), port.c_str(), sc->name()) == -1) {
      log_warn("listener %u info is too big", n);
      continue;
    }
    env.push_back(buf);
  }

  vector<string> args;
  args.push_back(helper);
  subprocess h = subprocess::call(args, env);
  if (h.state == CLD_DUMPED) {
    log_warn("%s: %s (core dumped)", helper.c_str(), strsignal(h.returncode));
  } else if (h.state == CLD_KILLED) {
    log_warn("%s: %s", helper.c_str(), strsignal(h.returncode));
  } else if (h.state == CLD_EXITED && h.returncode != 0) {
    log_warn("%s: exited unsuccessfully, status %d",
             helper.c_str(), h.returncode);
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
	  "--config-file=<file> ~ load the configuration file\n"
          "--log-file=<file> ~ set logfile\n"
          "--log-min-severity=warn|info|debug ~ set minimum logging severity\n"
          "--no-log ~ disable logging\n"
          "--timestamp-logs ~ add timestamps to all log messages\n"
          "--allow-kqueue ~ allow use of kqueue(2) (may be buggy)\n"
          "--registration-helper=<helper> ~ use <helper> to register with "
          "a relay database\n"
          "--pid-file=<file> ~ write process ID to <file> after startup\n"
          "--daemon ~ run as a daemon\n"
          "--version ~ show version details and exit\n");

  exit(1);
}

/**
   Receives 'argv' and scans for any non-protocol-specific optional
   arguments and tries to set them in effect.

   If it succeeds it returns the number of argv arguments its caller
   should skip to get past the optional arguments we already handled.
   If it fails, it exits the program.

   Note: this function should NOT use log_* to print diagnostics.
*/
static int
handle_generic_args(const char *const *argv,  modus_operandi_t &mo)
{
  bool logmethod_set = false;
  bool logsev_set = false;
  bool allow_kq_set = false;
  bool timestamps_set = false;
  bool registration_helper_set = false;
  bool pidfile_set = false;
  int i = 1;

  while (argv[i] && !strncmp(argv[i],"--",2)) {
    if (!strncmp(argv[i], "--config-file=", strlen("--config-file="))) {
      const char *path = argv[i]+strlen("--config-file=");
      mo.load_file(path);
      if (!mo.is_ok()){
        fprintf(stderr, "The configuration file  \"%s\" did not load smoothly!\n", path);
        exit(1);
      }
    } else if (!strncmp(argv[i], "--log-file=", 11)) {
      if (logmethod_set) {
        fprintf(stderr, "you've already set a log file!\n");
        exit(1);
      }
      if (log_set_method(LOG_METHOD_FILE,
                         (char *)argv[i]+11) < 0) {
        fprintf(stderr, "failed to open logfile '%s': %s\n", argv[i]+11,
                strerror(errno));
        exit(1);
      }
      logmethod_set=1;
    } else if (!strncmp(argv[i], "--log-min-severity=", 19)) {
      if (logsev_set) {
        fprintf(stderr, "you've already set a min. log severity!\n");
        exit(1);
      }
      if (log_set_min_severity(argv[i]+19) < 0) {
        fprintf(stderr, "invalid min. log severity '%s'", argv[i]+19);
        exit(1);
      }
      logsev_set = true;
    } else if (!strcmp(argv[i], "--no-log")) {
      if (logsev_set || logmethod_set) {
          fprintf(stderr, "can't ask for both some logs and no logs!\n");
          exit(1);
        }
      log_set_method(LOG_METHOD_NULL, NULL);
      logsev_set = true;
      logmethod_set = true;
    } else if (!strcmp(argv[i], "--timestamp-logs")) {
      if (timestamps_set) {
        fprintf(stderr, "you've already asked for timestamps!\n");
        exit(1);
      }
      log_enable_timestamps();
      timestamps_set = true;
    } else if (!strcmp(argv[i], "--allow-kqueue")) {
      if (allow_kq_set) {
        fprintf(stderr, "you've already allowed kqueue!\n");
        exit(1);
      }
      allow_kq = true;
      allow_kq_set = true;
    } else if (!strncmp(argv[i], "--registration-helper=", 22)) {
      if (registration_helper_set) {
        fprintf(stderr, "you've already set a registration helper!\n");
        exit(1);
      }
      registration_helper = string(argv[i]+22);
      registration_helper_set = true;
    } else if (!strncmp(argv[i], "--pid-file=", 11)) {
      if (pidfile_set) {
        fprintf(stderr, "you've already set a pid file!\n");
        exit(1);
      }
      pidfile_name = string(argv[i]+11);
      pidfile_set = true;
    } else if (!strcmp(argv[i], "--daemon")) {
      if (daemon_mode) {
        fprintf(stderr, "you've already requested daemon mode!\n");
        exit(1);
      }
      daemon_mode = true;
      
    } else {
      fprintf(stderr, "unrecognizable argument '%s'\n", argv[i]);
      exit(1);
    }
    i++;
  }

 /* if we have read in a valid modus_operandi
     then we need to look at the process options here;
     that are not acted upon in the reading process:
     -- daemon
     -- pid file
     -- logmethod_set

  */

  if(mo.is_ok()){
    daemon_mode = mo.daemon();
    logmethod_set = mo.logmethod_set();
    if(!mo.pid_file().empty()){
      pidfile_name = mo.pid_file();
      pidfile_set = true;
    }
  }
  
  /* Cross-option consistency checks. */
  if (daemon_mode && !logmethod_set) {
    log_warn("cannot log to stderr in daemon mode");
    log_set_method(LOG_METHOD_NULL, NULL);
  }

  return i;
}

int
main(int argc, const char *const *argv)
{
  struct event_config *evcfg;
  struct event *sig_int;
  struct event *sig_term;
  struct event *stdin_eof;
  vector<config_t *> configs;
  modus_operandi_t mo;
  const char *const *begin;
  const char *const *end;
  struct stat st;

  int cmd_options;
    
  /* Set the logging defaults before doing anything else.  It wouldn't
     be necessary, but some systems don't let you initialize a global
     variable to stderr. */
  log_set_method(LOG_METHOD_STDERR, NULL);

  /* Handle optional non-protocol-specific arguments. If we are given a config file,
     then it will be loaded into the modus_operandi_t object. Many of the config file options
     are set at the time of loading, in particular the schemes enabled/disabled.      
  */

  cmd_options = handle_generic_args(argv, mo);
  
  begin = argv + cmd_options;

  /* Find the subsets of argv that define each configuration.
     Each configuration's subset consists of the entries in argv from
     its recognized protocol name, up to but not including the next
     recognized protocol name. */
  if (!mo.is_ok() && (!*begin || !config_is_supported(*begin)))
    usage();
  if(cmd_options == argc){
    /* just using a configuration file */
    const char *const spec[] = { mo.protocol().c_str(),  NULL};
    config_t *cfg = config_create(1, spec, mo);
    if (!cfg)
      return 2; /* diagnostic already issued */
    configs.push_back(cfg);
  } else {
    /* oh goodie; hodge podge  */

  //crypto should be initialized before protocol so the protocols
  //can use encryption
  init_crypto();
 
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
      config_t *cfg = config_create(end - begin, begin, mo);
      if (!cfg)
        return 2; /* diagnostic already issued */
      configs.push_back(cfg);
    }
    begin = end;
  } while (*begin);
  
  }
  
  log_assert(configs.size() > 0);

  /* Configurations have been established; proceed with initialization. */
  if (daemon_mode)
    daemonize();

  pidfile pf(pidfile_name);
  if (!pf)
    log_warn("failed to create pid-file '%s': %s", pf.pathname().c_str(),
             pf.errmsg());

  /* Ugly method to fix a Windows problem:
     http://archives.seul.org/libevent/users/Oct-2010/msg00049.html */
#ifdef _WIN32
  {
    WSADATA wsaData;
    WSAStartup(0x101, &wsaData);
  }
#endif

  /* Configure and initialize libevent. */
  log_debug("initialize libevent");
  evcfg = event_config_new();
  if (!evcfg)
    log_abort("failed to initialize networking (evcfg)");

  /* The main reason we bother with an event_config object is that
     nobody's had time to track down the bugs that only the kqueue
     backend exposes and figure out whose fault they are. There is
     a command line switch waiting for the person who will do this
     detective work. */
  if (!allow_kq) {
    log_debug("avoiding kqueue method");
    if (event_config_avoid_method(evcfg, "kqueue"))
      log_abort("failed to initialize networking (avoiding kqueue)");
  }

  /* Possibly worth doing in the future: activating Windows IOCP and
     telling it how many CPUs to use. */

  struct event_base *the_event_base = event_base_new_with_config(evcfg);
  if (!the_event_base)
    log_abort("failed to initialize networking (evbase)");

  log_debug("initialize eventbase");
  /* Most events are processed at the default priority (0), but
     connection cleanup events are processed at low priority (1)
     to ensure that all pending I/O is handled first.  */
  if (event_base_priority_init(the_event_base, 2))
    log_abort("failed to initialize networking (priority queues)");

  conn_global_init(the_event_base);

  log_debug("initialize evdns");
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
       i++) {
    if (!listener_open(the_event_base, *i))
      log_abort("failed to open listeners for configuration %lu",
                (unsigned long)(i - configs.begin()) + 1);
  }

  if (!registration_helper.empty()) {
    call_registration_helper(registration_helper);
  }

  /* We are go for launch. As a signal to any monitoring process that may
     be running, close stdout now. */
  log_info("%s process %lu now initialized", argv[0], (unsigned long)getpid());

  fclose(stdout);

  event_base_dispatch(the_event_base);

  /* We have landed. */
  log_info("exiting");

  /* By the time we get to this point, all listeners and connections
     have already been freed. */

  log_debug("cleaning up configs");
  for (vector<config_t *>::iterator i = configs.begin(); i != configs.end();
       i++) {
    delete *i;
  }

  // Free events first
  log_debug("cleaning up events");
  event_free(sig_int);
  event_free(sig_term);

  // Free evdns base after that
  evdns_base_free(get_evdns_base(), 0);

  event_base_free(the_event_base);
  event_config_free(evcfg);

  log_debug("cleaning up config");
  free_crypto();
  log_close();

  if (stdin_eof) {
	free(stdin_eof); 
  }

  return 0;
}
