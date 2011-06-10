/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "config.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <openssl/opensslv.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define CRYPT_PRIVATE
#include "obfs2_crypt.h"

#if OPENSSL_VERSION_NUMBER >= 0x0090800f
#define USE_OPENSSL_RANDPOLL 1
#define USE_OPENSSL_SHA256 1
#include <openssl/sha.h>
#else
#define STMT_BEGIN do {
#define STMT_END } while (0)
static void
set_uint32(void *ptr, uint32_t val)
{
  memcpy(ptr, &val, 4);
}
static uint32_t
get_uint32(const void *ptr)
{
  uint32_t val;
  memcpy(&val, ptr, 4);
  return val;
}
#define LTC_ARGCHK(x) assert((x))
#include "../sha256.c"
#endif

int
initialize_crypto(void)
{
  ERR_load_crypto_strings();

#ifdef USE_OPENSSL_RANDPOLL
  return RAND_poll() == 1 ? 0 : -1;
#else
  /* XXX Or maybe fall back to the arc4random implementation in libevent2? */
  {
    char buf[32];
    int fd, n;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
      perror("open");
      return -1;
    }
    n = read(fd, buf, sizeof(buf));
    if (n != sizeof(buf)) {
      close(fd);
      return -1;
    }
    RAND_seed(buf, sizeof(buf));
    close(fd);
    return 0;
  }
#endif
}

void
cleanup_crypto(void)
{
  ERR_free_strings();
}

/* =====
   Digests
   ===== */

#ifdef USE_OPENSSL_SHA256
struct digest_t {
  SHA256_CTX ctx;
};
digest_t *
digest_new(void)
{
  digest_t *d = malloc(sizeof(digest_t));
  SHA256_Init(&d->ctx);
  return d;
}
void
digest_update(digest_t *d, const uchar *buf, size_t len)
{
  SHA256_Update(&d->ctx, buf, len);
}
size_t
digest_getdigest(digest_t *d, uchar *buf, size_t len)
{
  uchar tmp[SHA256_LENGTH];
  int n = 32;
  SHA256_Final(tmp, &d->ctx);
  if (len < 32)
    n = len;
  memcpy(buf, tmp, n);
  memset(tmp, 0, sizeof(tmp));
  return n;
}
#else
struct digest_t {
  sha256_state ctx;
};
digest_t *
digest_new(void)
{
  digest_t *d = malloc(sizeof(digest_t));
  sha256_init(&d->ctx);
  return d;
}
void
digest_update(digest_t *d, const uchar *buf, size_t len)
{
  sha256_process(&d->ctx, buf, len);
}
size_t
digest_getdigest(digest_t *d, uchar *buf, size_t len)
{
  uchar tmp[SHA256_LENGTH];
  int n = 32;
  sha256_done(&d->ctx, tmp);
  if (len < 32)
    n = len;
  memcpy(buf, tmp, n);
  memset(tmp, 0, sizeof(tmp));
  return n;
}
#endif

void
digest_free(digest_t *d)
{
  memset(d, 0, sizeof(digest_t));
  free(d);
}

/* =====
   Stream crypto
   ===== */

crypt_t *
crypt_new(const uchar *key, size_t keylen)
{
  crypt_t *k;
  if (keylen < AES_BLOCK_SIZE)
    return NULL;

  k = calloc(1, sizeof(crypt_t));
  if (k == NULL)
    return NULL;

  AES_set_encrypt_key(key, 128, &k->key);

  return k;
}
void
crypt_set_iv(crypt_t *key, const uchar *iv, size_t ivlen)
{
  assert(ivlen == sizeof(key->ivec));
  memcpy(key->ivec, iv, ivlen);
}
void
stream_crypt(crypt_t *key, uchar *buf, size_t len)
{
  AES_ctr128_encrypt(buf, buf, /* XXX make sure this is okay to do. */
                     len,
                     &key->key, key->ivec, key->ecount_buf,
                     &key->pos);
}
void
crypt_free(crypt_t *key)
{
  memset(key, 0, sizeof(key));
  free(key);
}

/* =====
   PRNG
   ===== */

int
random_bytes(uchar *buf, size_t buflen)
{
  return RAND_bytes(buf, buflen) == 1 ? 0 : -1;
}
