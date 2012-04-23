#include "util.h"
#include "zpack.h"
#include "zlib.h"
#include "crc32.h"

#define CHUNK 16384

/* Compress from file source to file dest until EOF on source.
   def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_STREAM_ERROR if an invalid compression
   level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
   version of the library linked do not match, or Z_ERRNO if there is
   an error reading or writing the files. */

ssize_t
def(const char *source, size_t slen, char *dest, size_t dlen, int level)
{
  int ret, flush;
  size_t have;
  z_stream strm;
  unsigned char in[CHUNK];
  unsigned char out[CHUNK];
  size_t dlen_orig = dlen;

  if (slen > SIZE_T_CEILING || dlen > SIZE_T_CEILING)
    return -1;

  /* allocate deflate state */
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  ret = deflateInit(&strm, level);
  if (ret != Z_OK)
    return ret;

  /* compress until end of file */
  do {
    if (slen > CHUNK)
      strm.avail_in = CHUNK;
    else
      strm.avail_in = slen;

    memcpy (in, source, strm.avail_in);
    slen = slen - strm.avail_in;
    source = source + strm.avail_in;

    flush = (slen == 0) ? Z_FINISH : Z_NO_FLUSH;
    strm.next_in = in;

    /* run deflate() on input until output buffer not full, finish
       compression if all of source has been read in */
    do {
      strm.avail_out = CHUNK;
      strm.next_out = out;
      ret = deflate(&strm, flush);    /* no bad return value */
      log_assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
      have = CHUNK - strm.avail_out;

      if (dlen < have) {
        log_warn("dest buf too small - have %lu, need %lu",
                 (unsigned long)dlen, (unsigned long)have);
        return Z_ERRNO;
      }

      memcpy(dest, out, have);
      dest += have;
      dlen = dlen - have;
    } while (strm.avail_out == 0);
    log_assert(strm.avail_in == 0);     /* all input will be used */

    /* done when last data in file processed */
  } while (flush != Z_FINISH);
  log_assert(ret == Z_STREAM_END);        /* stream will be complete */

  /* clean up and return */
  deflateEnd(&strm);
  return (dlen_orig - dlen);
}

/* Decompress from file source to file dest until stream ends or EOF.
   inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files. */

ssize_t
inf(const char *source, size_t slen, char *dest, size_t dlen)
{
  int ret;
  size_t have;
  z_stream strm;
  unsigned char in[CHUNK];
  unsigned char out[CHUNK];
  size_t dlen_orig = dlen;

  if (slen > SIZE_T_CEILING || dlen > SIZE_T_CEILING)
    return -1;

  /* allocate inflate state */
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;
  ret = inflateInit(&strm);
  if (ret != Z_OK)
    return ret;

  /* decompress until deflate stream ends or end of file */
  do {
    if (slen == 0)
      break;

    if (slen > CHUNK)
      strm.avail_in = CHUNK;
    else
      strm.avail_in = slen;

    memcpy(in, source, strm.avail_in);
    slen = slen - strm.avail_in;
    source = source + strm.avail_in;
    strm.next_in = in;

    /* run inflate() on input until output buffer not full */
    do {
      strm.avail_out = CHUNK;
      strm.next_out = out;
      ret = inflate(&strm, Z_NO_FLUSH);
      log_assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
      switch (ret) {
      case Z_NEED_DICT:
      case Z_DATA_ERROR:
      case Z_MEM_ERROR:
        inflateEnd(&strm);
        return ret;
      }
      have = CHUNK - strm.avail_out;

      if (dlen < have) {
        log_warn("dest buf too small - have %lu, need %lu",
                 (unsigned long)dlen, (unsigned long)have);
        return Z_ERRNO;
      }

      memcpy(dest, out, have);
      dest += have;
      dlen = dlen - have;

    } while (strm.avail_out == 0);

    /* done when inflate() says it's done */
  } while (ret != Z_STREAM_END);

  /* clean up and return */
  inflateEnd(&strm);

  if (ret == Z_STREAM_END)
    return dlen_orig - dlen;
  return Z_DATA_ERROR;
}

/* assumes that we know there is exactly 10 bytes of gzip header */

ssize_t
gzInflate(const char *source, size_t slen, char *dest, size_t dlen)
{
  int ret;
  size_t have;
  z_stream strm;
  unsigned char in[CHUNK];
  unsigned char out[CHUNK];
  size_t dlen_orig = dlen;

  if (slen > SIZE_T_CEILING || dlen > SIZE_T_CEILING)
    return -1;

  /* allocate inflate state */
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;

  ret = inflateInit2(&strm, -MAX_WBITS);
  if (ret != Z_OK)
    return ret;

  source = source + 10;
  slen -= 10;

  /* decompress until deflate stream ends or end of file */
  do {
    if (slen == 0)
      break;

    if (slen > CHUNK)
      strm.avail_in = CHUNK;
    else
      strm.avail_in = slen;

    memcpy(in, source, strm.avail_in);
    slen = slen - strm.avail_in;
    source = source + strm.avail_in;
    strm.next_in = in;

    /* run inflate() on input until output buffer not full */
    do {
      strm.avail_out = CHUNK;
      strm.next_out = out;
      ret = inflate(&strm, Z_NO_FLUSH);
      log_assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
      switch (ret) {
      case Z_NEED_DICT:
        ret = Z_DATA_ERROR;     /* and fall through */
      case Z_DATA_ERROR:
      case Z_MEM_ERROR:
        inflateEnd(&strm);
        return ret;
      }
      have = CHUNK - strm.avail_out;

      if (dlen < have) {
        log_warn("dest buf too small - have %lu, need %lu",
                 (unsigned long)dlen, (unsigned long)have);
        return Z_ERRNO;
      }

      memcpy(dest, out, have);
      dest += have;
      dlen = dlen - have;

    } while (strm.avail_out == 0);

    /* done when inflate() says it's done */
  } while (ret != Z_STREAM_END);

  /* clean up and return */
  inflateEnd(&strm);

  if (ret == Z_STREAM_END)
    return dlen_orig - dlen;
  return Z_DATA_ERROR;
}

ssize_t
gzDeflate(const char *source, size_t slen, char *dest, size_t dlen,
          time_t mtime)
{
  unsigned char *c;
  unsigned long crc;
  z_stream z;

  if (slen > SIZE_T_CEILING || dlen > SIZE_T_CEILING)
    return -1;

  z.zalloc = Z_NULL;
  z.zfree = Z_NULL;
  z.opaque = Z_NULL;

  if (Z_OK != deflateInit2(&z,
                           Z_DEFAULT_COMPRESSION,
                           Z_DEFLATED,
                           -MAX_WBITS,  /* supress zlib-header */
                           8,
                           Z_DEFAULT_STRATEGY))
    return -1;

  z.next_in = (Bytef *)source;
  z.avail_in = slen;
  z.total_in = 0;

  /* write gzip header */

  c = (unsigned char *)dest;
  c[0] = 0x1f;
  c[1] = 0x8b;
  c[2] = Z_DEFLATED;
  c[3] = 0; /* options */
  c[4] = (mtime >>  0) & 0xff;
  c[5] = (mtime >>  8) & 0xff;
  c[6] = (mtime >> 16) & 0xff;
  c[7] = (mtime >> 24) & 0xff;
  c[8] = 0x00; /* extra flags */
  c[9] = 0x03; /* UNIX */

  z.next_out = c + 10;
  z.avail_out = dlen - 10 - 8;
  z.total_out = 0;

  if (deflate(&z, Z_FINISH) != Z_STREAM_END) {
    deflateEnd(&z);
    return -1;
  }

  crc = generate_crc32c(source, slen);

  c = (unsigned char *)dest + 10 + z.total_out;
  c[0] = (crc >>  0) & 0xff;
  c[1] = (crc >>  8) & 0xff;
  c[2] = (crc >> 16) & 0xff;
  c[3] = (crc >> 24) & 0xff;
  c[4] = (z.total_in >>  0) & 0xff;
  c[5] = (z.total_in >>  8) & 0xff;
  c[6] = (z.total_in >> 16) & 0xff;
  c[7] = (z.total_in >> 24) & 0xff;

  if (deflateEnd(&z) != Z_OK)
    return -1;
  return 10 + z.total_out + 8;
}
