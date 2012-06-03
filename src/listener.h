/* Copyright 2011 Nick Mathewson, George Kadianakis
 * See LICENSE for other credits and copying information
 */
#ifndef LISTENER_H
#define LISTENER_H

#include <vector>

/**
  This struct defines the state of a listener on a particular address.
 */
struct listener_t
{
  config_t *cfg;
  struct evconnlistener *listener;
  char *address;
  size_t index;
};

/* returns 1 on success, 0 on failure */
int listener_open(struct event_base *base, config_t *cfg);
void listener_close_all(void);

std::vector<listener_t *> const& get_all_listeners();

#endif
