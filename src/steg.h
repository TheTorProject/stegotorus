/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information
*/

#ifndef STEG_H
#define STEG_H

/** A steganography instance stores all its state in one of these
    structures.  Most of the state is private to the module. */
struct steg_t
{
  steg_vtable *vtable;
  rng_t *rng;
  unsigned int is_clientside : 1;
  /* module may extend as necessary using embedding-as-inheritance */
};

/** A steganography module must define all of the fields of this
    pseudo-vtable structure.  Note that they are not all object methods
    in the C++ sense. */
struct steg_vtable
{
  /** Name of the steganography module. Must be a valid C identifier. */
  const char *name;

  /** Maximum data rate, in bytes per second, that this module can
      reasonably absorb when transmitting client-to-server. */
  size_t max_c2s_rate;

  /** Maximum data rate server-to-client. */
  size_t max_s2c_rate;

  /** Maximum number of concurrent connections to any single IP address
      that should be made using one instance of this module.
      If this value is greater than one, the module proposes to
      generate _correlated_ traffic across all concurrent connections.
      Only relevant for client-to-server traffic. */
  unsigned int max_corr_conns_per_ip;

  /** Maximum number of IP addresses that should be simultaneously
      connected to using one instance of this module. Again,
      if this value is greater than one, the module proposes to
      generate correlated traffic across all concurrent connections.
      Only relevant for client-to-server traffic. */
  unsigned int max_corr_ips;

  /** Detect whether the inbound traffic from CONN is disguised using
      the steganography this module implements.  Do not consume any
      data from CONN's inbound buffer, regardless of success or
      failure.  Return 1 if your brand of steg is detected,
      0 otherwise.  */
  unsigned int (*detect)(conn_t *conn);

  /** Prepare to handle new connections.
      More arguments may be added to this method later. */
  steg_t *(*state_new)(rng_t *rng, unsigned int is_clientside);

  /** Destroy a steg_t object created by this module. */
  void (*state_del)(steg_t *state);

  /** Report the maximum number of bytes that could be transmitted on
      connection CONN at this time.  You must be prepared to handle a
      subsequent request to transmit any _smaller_ number of bytes on
      this connection.  */
  size_t (*transmit_room)(steg_t *state, conn_t *conn);

  /** Consume all of the data in SOURCE, disguise it, and write it to
      the outbound buffer for CONN. Return 0 on success, -1 on failure. */
  int (*transmit)(steg_t *state, struct evbuffer *source, conn_t *conn);

  /** The data in CONN's inbound buffer should have been disguised by
      the peer instance to STATE.  Unmask it and write it to DEST.

      If this returns anything other than RECV_GOOD, it must not write
      anything to DEST.  Furthermore, if it returns RECV_INCOMPLETE,
      it must either not consume any data, or be prepared to resume
      where it left off. */
  enum recv_ret (*receive)(steg_t *state, conn_t *conn, struct evbuffer *dest);
};

steg_t *steg_new(const char *name);
steg_t *steg_detect(conn_t *conn);
void steg_del(steg_t *state);
size_t steg_transmit_room(steg_t *state, conn_t *conn);
int steg_transmit(steg_t *state, struct evbuffer *source, conn_t *conn);
enum recv_ret steg_receive(steg_t *state, conn_t *conn, struct evbuffer *dest);

#endif
