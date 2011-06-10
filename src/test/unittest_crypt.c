/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tinytest.h"
#include "tinytest_macros.h"

#include <openssl/aes.h>

#include "../protocols/obfs2_crypt.h"

struct crypt_t {
  AES_KEY key;
  uchar ivec[AES_BLOCK_SIZE];
  uchar ecount_buf[AES_BLOCK_SIZE];
  unsigned int pos;
};

/* Test vectors for sha256 */
static void
test_crypt_hashvec(void *data)
{
  digest_t *d;
  uchar output[32];

  /* First SHA256 test vector:
     Test for '\x00' */
  d = digest_new();
  digest_update(d, (unsigned char*)"", 0);
  digest_getdigest(d, output, 32);
  tt_int_op(0, ==, memcmp(output,
                          "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8"
                          "\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c"
                          "\xa4\x95\x99\x1b\x78\x52\xb8\x55", 32));

  /* Second SHA256 test vector:
     Test for the 256-bit entry of:
     http://csrc.nist.gov/groups/STM/cavp/#03 */
  d = digest_new();
  digest_update(d,
                (unsigned char*)"\x8c\xf5\x3d\x90\x07\x7d\xf9\xa0\x43\xbf\x8d"
                "\x10\xb4\x70\xb1\x44\x78\x44\x11\xc9\x3a\x4d\x50\x45\x56\x83"
                "\x4d\xae\x3e\xa4\xa5\xbb", 32);
  digest_getdigest(d, output, 32);
  tt_int_op(0, ==, memcmp(output,
                          "\x56\x05\x9e\x8c\xb3\xc2\x97\x8b\x19\x82\x08\xbf"
                          "\x5c\xa1\xe1\xea\x56\x59\xb7\x37\xa5\x06\x32\x4b"
                          "\x7c\xec\x75\xb5\xeb\xaf\x05\x7d", 32));

  /* Third SHA test vector:
     Test for the 1304-bit entry of:
     http://csrc.nist.gov/groups/STM/cavp/#03 */
  d = digest_new();
  digest_update(d,
                (unsigned char*)"\xeb\xac\xcc\x34\xd6\xd6\xd3\xd2\x1e\xd0\xad"
                "\x2b\xa7\xc0\x7c\x21\xd2\x53\xc4\x81\x4f\x4a\xd8\x9d\x32\x36"
                "\x92\x37\x49\x7f\x47\xa1\xad\xab\xfa\x23\x98\xdd\xd0\x9d\x76"
                "\x9c\xc4\x6d\x3f\xd6\x9c\x93\x03\x25\x1c\x13\xc7\x50\x79\x9b"
                "\x8f\x15\x11\x66\xbc\x26\x58\x60\x98\x71\x16\x8b\x30\xa4\xd0"
                "\xa1\x62\xf1\x83\xfb\x36\x0f\x99\xb1\x72\x81\x15\x03\x68\x1a"
                "\x11\xf8\x13\xc1\x6a\x44\x62\x72\xba\x6f\xd4\x85\x86\x34\x45"
                "\x33\xb9\x28\x08\x56\x51\x9c\x35\x70\x59\xc3\x44\xef\x17\x18"
                "\xdb\xaf\x86\xfa\xe5\xc1\x07\x99\xe4\x6b\x53\x16\x88\x6f\xb4"
                "\xe6\x80\x90\x75\x78\x90\x53\x96\x17\xe4\x03\xc5\x11\xa4\xf7"
                "\x8a\x19\xc8\x18\xc2\xea\x2e\x9d\x4e\x2d\xe9\x19\x0c\x9d\xdd"
                "\xb8\x06", 163);
  digest_getdigest(d, output, 32);
  tt_int_op(0, ==, memcmp(output,
                          "\xc9\x07\x18\x04\x43\xde\xe3\xcb\xcc\xb4\xc3\x13"
                          "\x28\xe6\x25\x15\x85\x27\xa5\x93\xb8\x78\xde\x1b"
                          "\x8e\x4b\xa3\x7f\x1d\x69\xfb\x66", 32));

  /* XXX Try doing init, update, update, output. */
  /* XXX add a base16-decode function so we can implement a tt_mem_op or
     something */

 end:
  if (d)
    digest_free(d);
}

static void
test_crypt_aes1(void *data)
{
  /* Trying AES_ctr128_encrypt(x,x,...) to see if in-place encryption works.
     Seems like it's working alright.
     Test vector taken from:
     http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors
     maybe we should find something a bit more NIST-ish */
  uchar key[16] = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
  uchar iv[16] = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
  uchar vec[16] = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a";

  crypt_t *crypt;

  crypt = crypt_new(key, sizeof(key));
  crypt_set_iv(crypt, iv, sizeof(iv));
  stream_crypt(crypt, vec, sizeof(vec));

  tt_int_op(0, ==, memcmp(vec,
                          "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d"
                          "\xb6\xce", 16));

  /* XXX test longer streams too; the failure modes for stream crypto are not
   * visible in a single block. */

 end:
  if (crypt)
    crypt_free(crypt);
}

static void
test_crypt_aes2(void *data)
{
  /* Trying stream_crypt() */
  uchar key1[16] = "aesunittest1_key";
  uchar key2[16] = "aesunittest2_key";

  uchar res1[16] = "aestest1_message";
  uchar res2[16] = "aestest2_message";

  crypt_t *crypt1;
  crypt_t *crypt2;

  crypt1 = crypt_new(key1, sizeof(key1));
  crypt2 = crypt_new(key2, sizeof(key2));

  stream_crypt(crypt1, res1, 16);
  stream_crypt(crypt2, res2, 16);

  tt_int_op(0, !=, memcmp(res1, res2, 16));

 end:
  if (crypt1)
    crypt_free(crypt1);

  if (crypt2)
    crypt_free(crypt2);
}

static void
test_crypt_rng(void *data)
{
  /* Not really easy to unit test openssl's RNG, me thinks.
     An entropy test wouldn't really help either.
     I guess I'll just copy Tor's unit test methodology here :3 */

  uchar data1[100],data2[100];

  tt_int_op(0, ==, random_bytes(data1, 100));
  tt_int_op(0, ==, random_bytes(data2, 100));

  tt_int_op(0, !=, memcmp(data1, data2, 100));

 end:
  ;
}


#define T(name, flags) \
  { #name, test_crypt_##name, (flags), NULL, NULL }

struct testcase_t crypt_tests[] = {
  T(hashvec, 0),
  T(aes1,0),
  T(aes2,0),
  T(rng,0),
  END_OF_TESTCASES
};


