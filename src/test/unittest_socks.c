#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tinytest.h"
#include "tinytest_macros.h"

#include <event2/buffer.h>

#include "../socks.c"
#include "../crypt.h"
#include "../util.h"
#include "../crypt_protocol.h"

static void
test_socks_send_negotiation(void *data)
{
  struct evbuffer *dest = NULL;
  struct evbuffer *source = NULL;
  dest = evbuffer_new();
  source = evbuffer_new();
  
  socks_state_t *state;
  state = socks_state_new();
  tt_assert(state);
  
  /* First test:
     Only one method: NOAUTH.
     SOCKS proxy should like this. */
     
  uchar req1[2];
  req1[0] = 1;
  req1[1] = 0;
  
  evbuffer_add(source, req1, 2);
  
  tt_int_op(1, ==, socks5_handle_negotiation(source,dest,state));
  
  /* Second test:
     Ten methods: One of them NOAUTH */
  uchar req2[10];
  req2[0] = 9;
  memset(req2+1,0x42,8);
  req2[9] = 0;
  
  evbuffer_add(source, req2, 10);
  
  tt_int_op(1, ==, socks5_handle_negotiation(source,dest,state));
  
  /* Third test:
     100 methods: No NOAUTH */
  uchar req3[100];
  req3[0] = 99;
  memset(req3+1,0x42,99);
  
  evbuffer_add(source, req3, 100);
  
  tt_int_op(-1, ==, socks5_handle_negotiation(source,dest,state));
  
  /* Fourth test:
     nmethods field = 4 but 3 actual methods */
  uchar req4[4];
  req4[0] = 4;
  memset(req4+1,0x0,3);
  
  evbuffer_add(source, req4, 4);
  
  tt_int_op(-1, ==, socks5_handle_negotiation(source,dest,state));

  /* Fifth test:
     nmethods field = 3 but 4 actual methods */
  uchar req5[5];
  req5[0] = 3;
  memset(req5+1,0x0,4);
  
  evbuffer_add(source, req5, 5);
  
  tt_int_op(-1, ==, socks5_handle_negotiation(source,dest,state));
  
 end:
  if (state)
    socks_state_free(state);

  if (source)
    evbuffer_free(source);
  if (dest)
    evbuffer_free(dest);
}

static void
test_socks_send_request(void *data)
{

  struct evbuffer *dest = NULL;
  struct evbuffer *source = NULL;
  dest = evbuffer_new();
  source = evbuffer_new();
  
  socks_state_t *state;
  state = socks_state_new();
  tt_assert(state);
  
  int addr = 16777343; /* 127.0.0.1 */
  u_int16_t port = 20480;    /* 80 */
  
  /* First test:
     Broken IPV4 req packet with no destport */
  struct parsereq pr1;
  uchar req1[7];
  req1[0] = 1;
  req1[1] = 0;
  req1[2] = 1;
  memcpy(req1+3,&addr,4);
  
  evbuffer_add(source, req1, 7);
  tt_int_op(-1, ==, socks5_handle_request(source,&pr1));
  
  /* emptying source buffer before next test  */
  size_t buffer_len = evbuffer_get_length(source);
  tt_int_op(0, ==, evbuffer_drain(source, buffer_len));

  /* Second test:
     Broken FQDN req packet with no destport */
  uchar req2[7];
  req2[0] = 1;
  req2[1] = 0;
  req2[2] = 3;
  req2[3] = 15;
  memcpy(req1+4,&addr,3);
  
  evbuffer_add(source, req2, 7);
  tt_int_op(-1, ==, socks5_handle_request(source,&pr1));
  
  /* emptying source buffer before next test  */
  buffer_len = evbuffer_get_length(source);
  tt_int_op(0, ==, evbuffer_drain(source, buffer_len));
  
  /* Third test:
     Correct IPV4 req packet. */
  uchar req3[9];
  req3[0] = 1;
  req3[1] = 0;
  req3[2] = 1;
  memcpy(req3+3,&addr,4);  
  memcpy(req3+7,&port,2);
  
  evbuffer_add(source, req3, 9);
  tt_int_op(1, ==, socks5_handle_request(source,&pr1));
  tt_assert(strcmp(pr1.addr, "127.0.0.1") == 0);    
  tt_assert(strcmp(pr1.port, "80") == 0);
  
  /* emptying source buffer before next test  */
  buffer_len = evbuffer_get_length(source);
  tt_int_op(0, ==, evbuffer_drain(source, buffer_len));
  
  /* Fourth test:
     Correct FQDN req packet. */
  const char fqdn[17] = "www.test.example";
  uchar req4[23];
  req4[0] = 1;
  req4[1] = 0;
  req4[2] = 3;
  req4[3] = 17;
  strcpy((char *)req4+4,fqdn);
  memcpy(req4+21,&port,2);
  
  evbuffer_add(source, req4, 23);
  tt_int_op(1, ==, socks5_handle_request(source,&pr1));
  tt_assert(strcmp(pr1.addr, "www.test.example") == 0);  
  tt_assert(strcmp(pr1.port, "80") == 0);

 end:
  if (state)
    socks_state_free(state);

  if (source)
    evbuffer_free(source);
  if (dest)
    evbuffer_free(dest);
     
}

#define T(name, flags) \
  { #name, test_socks_##name, (flags), NULL, NULL }

struct testcase_t socks_tests[] = {
  T(send_negotiation, 0),
  T(send_request, 0),
  END_OF_TESTCASES
};
