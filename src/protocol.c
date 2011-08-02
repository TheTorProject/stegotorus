/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "network.h"
#include "protocol.h"

#include "protocols/dummy.h"
/*#include "protocols/obfs2.h"*/

/**
    All supported protocols should be put in this array.
    It's used by main.c.
*/
const protocol_vtable *const supported_protocols[] =
{
  &dummy_vtable,
  /*&obfs2_vtable,*/
};
const size_t n_supported_protocols =
  sizeof(supported_protocols)/sizeof(supported_protocols[0]);

/**
   This function dispatches (by name) creation of a |listener_t|
   to the appropriate protocol-specific initalization function.
 */
listener_t *
proto_listener_create(int n_options, const char *const *options)
{
  size_t i;
  for (i = 0; i < n_supported_protocols; i++)
    if (!strcmp(*options, supported_protocols[i]->name))
      /* Remove the first element of 'options' (which is always the
         protocol name) from the list passed to the init method. */
      return supported_protocols[i]->listener_create(n_options - 1, options + 1);

  return NULL;
}

/**
   This function destroys the protocol-specific part of a listener object.
*/
void
proto_listener_free(listener_t *lsn)
{
  obfs_assert(lsn);
  obfs_assert(lsn->vtable);
  obfs_assert(lsn->vtable->listener_free);
  lsn->vtable->listener_free(lsn);
}

/**
   This function is called once per connection and creates a protocol
   object to be used during the session.

   Return a 'protocol_t' if successful, NULL otherwise.
*/
conn_t *
proto_conn_create(listener_t *lsn)
{
  obfs_assert(lsn);
  obfs_assert(lsn->vtable);
  obfs_assert(lsn->vtable->conn_create);
  return lsn->vtable->conn_create(lsn);
}

/**
   This function does the protocol handshake.
   Not all protocols have a handshake.
*/
int
proto_handshake(conn_t *conn, void *buf) {
  obfs_assert(conn);
  obfs_assert(conn->vtable);
  obfs_assert(conn->vtable->handshake);
  return conn->vtable->handshake(conn, buf);
}

/**
   This function is responsible for sending protocol data.
*/
int
proto_send(conn_t *conn, void *source, void *dest) {
  obfs_assert(conn);
  obfs_assert(conn->vtable);
  obfs_assert(conn->vtable->send);
  return conn->vtable->send(conn, source, dest);
}

/**
   This function is responsible for receiving protocol data.
*/
enum recv_ret
proto_recv(conn_t *conn, void *source, void *dest) {
  obfs_assert(conn);
  obfs_assert(conn->vtable);
  obfs_assert(conn->vtable->recv);
  return conn->vtable->recv(conn, source, dest);
}

/**
   This function destroys 'conn'.
   It's called everytime we close a connection.
*/
void
proto_conn_free(conn_t *conn) {
  obfs_assert(conn);
  obfs_assert(conn->vtable);
  obfs_assert(conn->vtable->conn_free);
  conn->vtable->conn_free(conn);
}
