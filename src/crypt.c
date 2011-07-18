/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#define CRYPT_PRIVATE
#include "crypt.h"
#include "util.h"

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#if OPENSSL_VERSION_NUMBER >= 0x0090800f
#define USE_OPENSSL_RANDPOLL 1
#define USE_OPENSSL_SHA256 1
#include <openssl/sha.h>
#else
#include "sha256.h"
#endif

/**
   Initializes the obfs2 crypto subsystem.
*/
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

/**
   Cleans up the obfs2 crypto subsystem.
*/
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

/**
   Returns a new SHA256 digest container.
*/
digest_t *
digest_new(void)
{
  digest_t *d = xmalloc(sizeof(digest_t));
  SHA256_Init(&d->ctx);
  return d;
}

/**
   Updates the contents of the SHA256 container 'd' with the first
   'len' bytes of 'buf'.
*/
void
digest_update(digest_t *d, const uchar *buf, size_t len)
{
  SHA256_Update(&d->ctx, buf, len);
}

/**
   Returns the digest stored in 'd' into 'buf' of length 'len'.
*/
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
  digest_t *d = xmalloc(sizeof(digest_t));
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

/**
   Initializes the AES cipher with 'key'.
*/
crypt_t *
crypt_new(const uchar *key, size_t keylen)
{
  crypt_t *k;

  obfs_assert(keylen == AES_BLOCK_SIZE);
  k = xzalloc(sizeof(crypt_t));
  AES_set_encrypt_key(key, AES_BLOCK_SIZE * CHAR_BIT, &k->key);

  return k;
}

/**
   Sets the IV of 'key' to 'iv'.
*/
void
crypt_set_iv(crypt_t *key, const uchar *iv, size_t ivlen)
{
  obfs_assert(ivlen == sizeof(key->ivec));
  memcpy(key->ivec, iv, ivlen);
}

/*
  In-place encrypts 'buf' with 'key'.
*/
void
stream_crypt(crypt_t *key, uchar *buf, size_t len)
{
  AES_ctr128_encrypt(buf, buf, len,
                     &key->key, key->ivec, key->ecount_buf,
                     &key->pos);
}

/**
   Deallocates memory space of 'key'.
*/
void
crypt_free(crypt_t *key)
{
  memset(key, 0, sizeof(key));
  free(key);
}

/* =====
   PRNG
   ===== */

/**
   Fills 'buf' with 'buflen' random bytes and returns 0 on success.
   Returns -1 on failure.
*/
int
random_bytes(uchar *buf, size_t buflen)
{
  return RAND_bytes(buf, buflen) == 1 ? 0 : -1;
}
