/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */
#include "util.h"
#include "zpack.h"
#include "zlib.h"

#include <limits>

#define CHUNK 16384

/* Compress from file source to file dest until EOF on source.
   def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_STREAM_ERROR if an invalid compression
   level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
   version of the library linked do not match, or Z_ERRNO if there is
   an error reading or writing the files. */

ssize_t
def(const uint8_t *source, size_t slen, uint8_t *dest, size_t dlen, int level)
{
  int ret, flush;
  size_t have;
  z_stream strm;
  uint8_t in[CHUNK];
  uint8_t out[CHUNK];
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
inf(const uint8_t *source, size_t slen, uint8_t *dest, size_t dlen)
{
  int ret;
  size_t have;
  z_stream strm;
  uint8_t in[CHUNK];
  uint8_t out[CHUNK];
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
gzInflate(const uint8_t *source, size_t slen, uint8_t *dest, size_t dlen)
{
  int ret;
  size_t have;
  z_stream strm;
  uint8_t in[CHUNK];
  uint8_t out[CHUNK];
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
gzDeflate(const uint8_t *source, size_t slen, uint8_t *dest, size_t dlen,
          time_t mtime)
{
  uint32_t crc;
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

  z.next_in = const_cast<uint8_t*>(source);
  z.avail_in = slen;
  z.total_in = 0;

  /* write gzip header */

  dest[0] = 0x1f;
  dest[1] = 0x8b;
  dest[2] = Z_DEFLATED;
  dest[3] = 0; /* options */
  dest[4] = (mtime >>  0) & 0xff;
  dest[5] = (mtime >>  8) & 0xff;
  dest[6] = (mtime >> 16) & 0xff;
  dest[7] = (mtime >> 24) & 0xff;
  dest[8] = 0x00; /* extra flags */
  dest[9] = 0x03; /* UNIX */

  z.next_out = dest + 10;
  z.avail_out = dlen - 10 - 8;
  z.total_out = 0;

  if (deflate(&z, Z_FINISH) != Z_STREAM_END) {
    deflateEnd(&z);
    return -1;
  }

  crc = generate_crc32c(source, slen);

  dest = dest + 10 + z.total_out;
  dest[0] = (crc >>  0) & 0xff;
  dest[1] = (crc >>  8) & 0xff;
  dest[2] = (crc >> 16) & 0xff;
  dest[3] = (crc >> 24) & 0xff;
  dest[4] = (z.total_in >>  0) & 0xff;
  dest[5] = (z.total_in >>  8) & 0xff;
  dest[6] = (z.total_in >> 16) & 0xff;
  dest[7] = (z.total_in >> 24) & 0xff;

  if (deflateEnd(&z) != Z_OK)
    return -1;
  return 10 + z.total_out + 8;
}

uint32_t
generate_crc32c(const uint8_t *string, size_t length)
{
  // zlib doesn't believe in size_t. When size_t is bigger than uInt,
  // we theoretically could break the operation up into uInt-sized
  // chunks to support the full range of size_t, but I doubt we will
  // ever need to crc32 more than 2^32 bytes, so I'm not bothering.
  // -- zw, 2012
  log_assert(length <= std::numeric_limits<uInt>::max());

  uLong crc = crc32(crc32(0, 0, 0), string, length);

  // zlib also doesn't believe 'long' can be more than 32 bits wide.
  // This shouldn't ever fire unless there is a bug in zlib.
  log_assert(crc <= std::numeric_limits<uint32_t>::max());

  return crc;
}
