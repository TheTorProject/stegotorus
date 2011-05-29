/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#include <stdlib.h>
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
#define SEPERATOR "+"
/* Totally arbitrary. */
#define MAXPROTOCOLS 20

static void usage(void) __attribute__((noreturn));

/* protocol.c */
extern char *supported_protocols[];
extern int n_supported_protocols;

static void
usage(void)
{
  int i;
  fprintf(stderr,
          "Usage: obfsproxy protocol_name [protocol_args] protocol_options %s protocol_name ...\n"
          "Available protocols:",
          SEPERATOR);
  /* this is awful. */
  for (i=0;i<n_supported_protocols;i++)
    fprintf(stderr," [%s]", supported_protocols[i]);
  fprintf(stderr,"\n");

  exit(1);
}

static void
handle_signal_cb(evutil_socket_t fd, short what, void *arg)
{
  struct event_base *base = arg;
  /* int signum = (int) fd; */
  
  event_base_loopexit(base, NULL);
}

/**
   This function visits all the command line arguments in 'argv' between
   'start' and 'end' and writes them in 'options_string'.
 */
static int
populate_options(char **options_string, 
                 const char **argv, int n_options) 
{
  int x,g;
  for (g=0;g<=n_options-1;g++) {
    options_string[g] = strdup(argv[g]);
    if (!options_string[x]) {
      return -1;
    }
  }
  return 0;
}

/**
   Runs through all the supported protocols and checks if 'name'
   matches with the name of any of them.
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

#define STUPID_BEAUTIFIER "===========================\n"

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
     options or arguments, but this will be resolved by
     set_up_protocol() and listener_new(). */
  int actual_protocols=0;

  int start;
  int end;
  int n_options;
  void *temp;
  int i;

  unsigned int n_protocols=1;
  unsigned int protocols[MAXPROTOCOLS+1];
  protocols[0] = 0;

  if (argc < 2) {
    usage();
  }

  /* Iterate through command line arguments and find protocols. */
  for (i=0;i<argc;i++) {
    if (!strcmp(argv[i],SEPERATOR)) {
      protocols[n_protocols] = i;
      n_protocols++;
      if (n_protocols > MAXPROTOCOLS) {
        printf("Sorry, we only allow %d protocols. Don't ask me why. "
               "Exiting.\n", MAXPROTOCOLS);
        return 5;
      }
    }
  }
  protocols[n_protocols] = argc;
  if (n_protocols > 1)
    printf("Found %d protocols.\n", n_protocols);

  /* Iterate through protocols. */
  for (i=0;i<n_protocols;i++) {
    /* This "points" to the first argument of this protocol in argv. */
    start = protocols[i]+1;
    /* This "points" to the last argument of this protocol in argv. */
    end = protocols[i+1]-1;
    n_options = end-start+1;

    if (!is_supported_protocol(argv[start])) {
      printf("We don't support crappy protocols, son.\n"); 
      continue;
    }

    /* Okay seems like we support this protocol. */
    actual_protocols++;

    /* We now allocate enough space for our parsing adventures.

       We first allocate space for a pointer in protocol_options,
       which points to an array carrying the options of this protocol.
       We then allocate space for the array carrying the options of
       this protocol.
       Finally, we allocate space on the n_options_array so that we
       can put the number of options there.
    */ 
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

  /* Initialize libevent */
  base = event_base_new();
  if (!base) {
    fprintf(stderr, "Can't initialize Libevent; failing\n");
    return 2;
  }

  /* ASN should this happen only when SOCKS is enabled? */
  if (init_evdns_base(base) < 0) {
    fprintf(stderr, "Can't initialize evdns; failing\n");
    return 3;
  }
  
  /* Handle signals */
  signal(SIGPIPE, SIG_IGN);
  sigevent = evsignal_new(base, SIGINT, handle_signal_cb, (void*) base);
  if (event_add(sigevent,NULL)) {
    printf("Oh come on! We can't even add events for signals! Exiting.\n");
    return 4;
  }

  /*Let's open a new listener for each protocol. */ 
  int h;
  listener_t *listeners[actual_protocols];
  listener_t *temp_listener;
  int n_listeners=0;
  for (h=0;h<actual_protocols;h++) {

    if (n_protocols > 1) {
      dbg((STUPID_BEAUTIFIER
           "Spawning listener %d!\n"
           STUPID_BEAUTIFIER, h+1));
    }

    temp_listener = listener_new(base, n_options_array[h], protocol_options[h]);

    /** Free the space allocated for this protocol's options. */
    for (i=0;i<n_options_array[h];i++)
      free(protocol_options[h][i]);
    free(protocol_options[h]);

    if (!temp_listener) {
      continue;
    }
    
    dbg(("Succesfully created listener.\n"));
    listeners[n_listeners] = temp_listener;
    
    n_listeners++;
  }

  if (n_protocols > 1) {
    dbg((STUPID_BEAUTIFIER           
         "From the original %d protocols only %d were parsed from main.c. "
         "In the end only %d survived.\n\nStarting up...\n"
         STUPID_BEAUTIFIER, 
         n_protocols, actual_protocols,n_listeners));
  }

  /* run the event loop if at least a listener was created. */
  if (n_listeners)
    event_base_dispatch(base);

  /* We are exiting. Clean everything. */
  for (h=0;h<n_listeners;h++)
    listener_free(listeners[h]);
  free(protocol_options);
  free(n_options_array);

  return 0;
}

#undef STUPID_BEAUTIFIER
