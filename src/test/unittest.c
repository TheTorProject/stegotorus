/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "crypt.h"
#include "tinytest.h"

extern struct testcase_t container_tests[];
extern struct testcase_t crypt_tests[];
extern struct testcase_t socks_tests[];
extern struct testcase_t dummy_tests[];
/*extern struct testcase_t obfs2_tests[];*/
extern struct testcase_t s_x_http_tests[];

struct testgroup_t groups[] = {
  { "container/", container_tests },
  { "crypt/", crypt_tests },
  { "socks/", socks_tests },
  { "dummy/", dummy_tests },
  /*{ "obfs2/", obfs2_tests },*/
  { "steg/x_http/", s_x_http_tests },
  END_OF_GROUPS
};

void
finish_shutdown(void)
{
}

int
main(int argc, const char **argv)
{
  int rv;

  /* Ugly method to fix a Windows problem:
     http://archives.seul.org/libevent/users/Oct-2010/msg00049.html */
#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(0x101, &wsaData);
#endif

  initialize_crypto();
  conn_initialize();
  rv = tinytest_main(argc, argv, groups);
  conn_start_shutdown(1);
  cleanup_crypto();
  return rv;
}
