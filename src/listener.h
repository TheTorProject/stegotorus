/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef LISTENER_H
#define LISTENER_H

/* returns 1 on success, 0 on failure */
int listener_open(struct event_base *base, config_t *cfg);
void listener_close_all(void);

#endif
