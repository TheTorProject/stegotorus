/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <event2/event.h>
#include "network.h"
#include "util.h"
#include "protocol.h"

#ifndef __GNUC__
#define __attribute__(x)
#endif

/* The character that seperates multiple listeners in the cli */
#define SEPARATOR "+"
/* Totally arbitrary. */
#define MAXPROTOCOLS 20

static void usage(void) __attribute__((noreturn));
static int handle_obfsproxy_args(const char **argv);

/* protocol.c */
extern char *supported_protocols[];
extern int n_supported_protocols;

/**
   Prints the obfsproxy usage instructions then exits.
*/
static void
usage(void)
{
  int i;
  fprintf(stderr,
          "Usage: obfsproxy protocol_name [protocol_args] protocol_options %s protocol_name ...\n"
          "* Available protocols:\n",
          SEPARATOR);
  /* this is awful. */
  for (i=0;i<n_supported_protocols;i++)
    fprintf(stderr,"[%s] ", supported_protocols[i]);
  fprintf(stderr, "\n* Available arguments:\n"
          "--log-file=<file> ~ set logfile\n"
          "--log-min-severity=warn|info|debug ~ set minimum logging severity\n"
          "--no-log ~ disable logging\n");

  exit(1);
}

/**
   This is called on SIGINT. It kills the event base loop, so that we
   start exiting.
*/
static void
handle_signal_cb(evutil_socket_t fd, short what, void *arg)
{
  struct event_base *base = arg;
  /* int signum = (int) fd; */
  
  log_info("Caught SIGINT.");
  event_base_loopexit(base, NULL);
}

/**
   This function visits 'n_options' command line arguments off 'argv'
   and writes them in 'options_string'.

   Returns 1 on success, -1 on fail.
*/
static void
populate_options(char **options_string, 
                 const char **argv, int n_options) 
{
  int g;
  for (g=0;g<=n_options-1;g++)
    options_string[g] = (char*) argv[g];
}

/**
   Returns 1 if 'name' is the nmae of a supported protocol, otherwise
   it returns 0.
*/ 
static int
is_supported_protocol(const char *name) {
  int f;
  for (f=0;f<n_supported_protocols;f++) {
    if (!strcmp(name,supported_protocols[f])) 
      return 1;
  }
  return 0;
}

/**
   Receives argv[1] as 'argv' and scans from thereafter for any
   obfsproxy optional arguments and tries to set them in effect.
   
   If it succeeds it returns the number of argv arguments its caller
   should skip to get past the optional arguments we already handled.
   If it fails, it exits obfsproxy.
*/
static int
handle_obfsproxy_args(const char **argv)
{
  int logmethod_set=0;
  int logsev_set=0;
  int i=0;

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
  struct event_base *base;
  struct event *sigevent;

  /* Yes, these are three stars right there. This is an array of
     arrays of strings! Every element of the array is an array of
     strings that contains all the options of a protocol.
     At runtime it should look like this:
     char protocol_options[<number of protocols>][<number of options>][<length of option>]
  */
  char ***protocol_options = NULL;
  /* This is an array of integers! Each integer is the number of
     options of the respective protocol. */
  int *n_options_array = NULL;
  /* This is an integer! It contains the number of protocols that we
     managed to recognize, by their protocol name.  Of course it's not
     the *actual* actual_protocols since some of them could have wrong
     options or arguments, but this will be resolved per-protocol by
     set_up_protocol(). */
  int actual_protocols=0;

  int start;
  int end;
  int n_options;
  void *temp;
  int i;

  /* The number of protocols. */
  unsigned int n_protocols=1;
  /* An array which holds the position in argv of the command line
     options for each protocol. */
  unsigned int *protocols=NULL;

  if (argc < 2) {
    usage();
  }

  /** "Points" to the first argv string after the optional obfsproxy
      arguments. Normally this should be where the protocols start. */
  int start_of_protocols;
  /** Handle optional obfsproxy arguments. */
  start_of_protocols = handle_obfsproxy_args(&argv[1]);

  protocols = malloc(sizeof(int)*(n_protocols+1));
  if (!protocols)
    exit(1);

  protocols[0] = start_of_protocols;

  /* Populate protocols and calculate n_protocols. */
  for (i=protocols[0];i<argc;i++) {
    if (!strcmp(argv[i],SEPARATOR)) {
      protocols[n_protocols] = i;
      n_protocols++;

      temp = realloc(protocols, sizeof(int)*(n_protocols+1));
      if (!temp)
        exit(1);
      protocols = temp;
    }
  }

  protocols[n_protocols] = argc;

  log_debug("Found %d protocol(s).", n_protocols);

  /* Iterate through protocols. */
  for (i=0;i<n_protocols;i++) {
    log_debug("Parsing protocol %d.", i+1);
    /* This "points" to the first argument of this protocol in argv. */
    start = protocols[i]+1;
    /* This "points" to the last argument of this protocol in argv. */
    end = protocols[i+1]-1;
    /* This is the number of options of this protocol. */
    n_options = end-start+1;

    if (start >= end) {
      log_warn("No protocol options were given on protocol %d.", i+1);
      continue;
    }

    /* First option should be protocol_name. See if we support it. */
    if (!is_supported_protocol(argv[start])) {
      log_warn("We don't support protocol: %s", argv[start]); 
      continue;
    }

    actual_protocols++;

    /* We now allocate enough space for our parsing adventures.

       We first allocate space for a pointer in protocol_options,
       which points to an array carrying the options of this protocol.
       We then allocate space for the array carrying the options of
       this protocol.
       Finally, we allocate space on the n_options_array so that we
       can put the number of options there.
    */ 
    /*XXXX (Why not actually allocate this before the start of the loop?)*/
    temp = 
      realloc(protocol_options, sizeof(char**)*actual_protocols);
    if (!temp)
      exit(1);
    protocol_options = temp;
    /* We should now allocate some space for all the strings
       carrying the protocol options. */
    protocol_options[actual_protocols-1] = 
      malloc(sizeof(char*)*(n_options));
    if (!protocol_options[actual_protocols-1])
      exit(1);
    temp = realloc(n_options_array, sizeof(int)*actual_protocols);
    if (!temp)
      exit(1);
    n_options_array = temp;
    n_options_array[actual_protocols-1] = n_options;

    /* Finally! Let's fill protocol_options. */
    populate_options(protocol_options[actual_protocols-1],
                     &argv[start], n_options);
  }

  /* Excellent. Now we should have protocol_options populated with all
     the protocol options we got from the user. */

  /*  Ugly method to fix a Windows problem:
      http://archives.seul.org/libevent/users/Oct-2010/msg00049.html */
#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(0x101, &wsaData);
#endif

  /* Initialize libevent */
  base = event_base_new();
  if (!base) {
    log_warn("Can't initialize Libevent; failing");
    return 1;
  }

  /* ASN should this happen only when SOCKS is enabled? */
  if (init_evdns_base(base) < 0) {
    log_warn("Can't initialize evdns; failing");
    return 1;
  }
  
  /* Handle signals */
#ifdef SIGPIPE
   signal(SIGPIPE, SIG_IGN);
#endif
  sigevent = evsignal_new(base, SIGINT, 
                          handle_signal_cb, (void*) base);
  if (event_add(sigevent,NULL)) {
    log_warn("We can't even add events for signals! Exiting.");
    return 1;
  }

  /*Let's open a new listener for each protocol. */ 
  int h;
  listener_t **listeners;
  listener_t *temp_listener;
  int n_listeners=0;
  protocol_params_t *proto_params=NULL;
  listeners = calloc(sizeof(listener_t*), actual_protocols);
  if (!listeners) {
    log_warn("Allocation failure: %s", strerror(errno));
    return 1;
  }

  for (h=0;h<actual_protocols;h++) {

    log_debug("Spawning listener %d!", h+1);

    /** normally free'd in listener_free() */
    proto_params = calloc(1, sizeof(protocol_params_t));
    if (set_up_protocol(n_options_array[h],protocol_options[h],
                        proto_params)<0) {
      free(proto_params);
      continue;
    }

    temp_listener = listener_new(base, proto_params);

    /** Free the space allocated for this protocol's options. */
    free(protocol_options[h]);

    if (!temp_listener)
      continue;
    
    log_info("Succesfully created listener %d.", h+1);
    listeners[n_listeners] = temp_listener;
    
    n_listeners++;
  }

  log_debug("From the original %d protocols only %d "
            "were parsed from main.c. In the end only "
            "%d survived.",
            n_protocols, actual_protocols,n_listeners);

  /* run the event loop if at least a listener was created. */
  if (n_listeners)
    event_base_dispatch(base);

  log_info("Exiting.");

  close_obfsproxy_logfile();

  /* We are exiting. Clean everything. */
  for (h=0;h<n_listeners;h++)
    listener_free(listeners[h]);
  free(protocol_options);
  free(n_options_array);
  free(protocols);

  return 0;
}
