
/** Opaque to this layer; make up accessor APIs as necessary */

/** Cryptographically secure pseudo-random number generator.
    Implements random byte streams, uniform integers, and
    as many non-uniform distributions as you want. */
typedef struct rng_t rng_t;

/** Peer connection.  Has two "evbuffer" objects representing
    the inbound and outbound channels of the TCP connection. */
typedef struct conn_t conn_t;

  /** Get the inbound buffer for a connection. */
  struct evbuffer *conn_get_inbound(conn_t *conn);

  /** Get the outbound buffer for a connection. */
  struct evbuffer *conn_get_outbound(conn_t *conn);

  /** Get a printable name for the remote peer. */
  const char *conn_get_peername(conn_t *conn);

  /** The peer is expected to close CONN without any further
      transmissions. */
  void conn_expect_close(conn_t *conn);

  /** The peer is expected to close CONN after its next transmission,
      and we should not transmit any more data after the current
      outbound queue has drained. */
  void conn_expect_close_after_response(conn_t *conn);

  /** Close CONN after all pending data is transmitted. */
  void conn_close_after_transmit(conn_t *conn);

  /** We must transmit something on this connection within TIMEOUT
      milliseconds. */
  void conn_transmit_soon(conn_t *conn, unsigned long timeout);


/** A steganography instance stores all its state in one of these
    structures.  Most of the state is private to the module. */
typedef struct steg_state_t
{
  steg_vtable *vtable;
  rng_t *rng;
  bool is_clientside;
  /* module may extend as necessary using embedding-as-inheritance */
} steg_state_t;

/** A steganography module must define all of the fields of this
    pseudo-vtable structure.  Note that they are not all object methods
    in the C++ sense. */
typedef struct steg_vtable
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

  /** Prepare to handle outbound (client-to-server) connections. */
  steg_state_t *new_clientside(rng_t *rng, ...);

  /** Prepare to handle inbound (server-to-client) connections. */
  steg_state_t *new_serverside(rng_t *rng, ...);

  /** Destroy a steg_state_t object created by this module. */
  void state_free(steg_state_t *to_destroy);

  /** Detect whether the inbound traffic from CONN is disguised using
      the steganography this module implements.  Do not consume any
      data from CONN's inbound buffer.  This will only be called once
      per connection (unless it returns 'need_more_data', in which case
      it might be called again when more is available). */
  enum { yes = 0, no, need_more_data }
    is_my_steg(conn_t *conn);

  /** Report the maximum number of bytes that could be transmitted on
      connection CONN at this time.  You must be prepared to handle a
      subsequent request to transmit any _smaller_ number of bytes on
      this connection.  */
  size_t transmit_room(steg_state_t *steg, conn_t *conn);

  /** Consume all of the data in SOURCE, disguise it, and write it to
      the outbound buffer for CONN. */
  enum { success = 0, encode_error }
    transmit(steg_state_t *state, struct evbuffer *source, conn_t *conn);

  /** The data in CONN's inbound buffer should have been disguised by
      the peer instance to STATE.  Unmask it and write it to DEST.
      CRITICAL: If this returns 'need_more_data', it must either not
      consume any data, or be prepared to restart where it left off. */
  enum { success = 0, decode_error, need_more_data }
    receive(steg_state_t *state, conn_t *conn,
            struct evbuffer *dest);

} steg_vtable;
