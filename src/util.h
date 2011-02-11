/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#ifndef UTIL_H
#define UTIL_H

struct sockaddr_storage;

int resolve_address_port(const char *address,
                         int nodns, int passive,
                         struct sockaddr_storage *addr_out,
                         int *addrlen_out,
                         const char *default_port);

#ifdef DEBUG
#define dbg(x) printf x
#else
#define dbg(x) ((void)0)
#endif

#endif
