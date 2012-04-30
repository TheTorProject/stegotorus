/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */
#include "util.h"
#include "zpack.h"
#include "zlib.h"

#include <limits>

// zlib doesn't believe in size_t. When size_t is bigger than uInt, we
// theoretically could break operations up into uInt-sized chunks to
// support the full range of size_t, but I doubt we will ever need to
// compress, decompress, or crc32 more than 2^32 bytes in one
// operation, so I'm not bothering.  -- zw, 2012
//
// The indirection through ZLIB_UINT_MAX makes some versions of gcc
// not produce a 'comparison is always (true/false)' warning.
const size_t ZLIB_UINT_MAX = std::numeric_limits<uInt>::max();
const size_t ZLIB_CEILING = (SIZE_T_CEILING > ZLIB_UINT_MAX
                             ? ZLIB_UINT_MAX : SIZE_T_CEILING);

// Compress from 'source' to 'dest', producing 'zlib' (RFC 1950) format,
// with compression level 'level'.
ssize_t
def(const uint8_t *source, size_t slen, uint8_t *dest, size_t dlen, int level)
{
  if (slen > ZLIB_CEILING || dlen > ZLIB_CEILING)
    return -1;

  z_stream strm;
  memset(&strm, 0, sizeof strm);
  int ret = deflateInit(&strm, level);
  if (ret != Z_OK) {
    log_warn("compression failure (initialization): %s", strm.msg);
    return -1;
  }

  strm.next_in = const_cast<Bytef*>(source);
  strm.avail_in = slen;
  strm.next_out = dest;
  strm.avail_out = dlen;

  ret = deflate(&strm, Z_FINISH);
  if (ret != Z_STREAM_END) {
    log_warn("compression failure: %s", strm.msg);
    deflateEnd(&strm);
    return -1;
  }

  deflateEnd(&strm);
  return strm.total_out;
}

// Decompress 'zlib'-format data from 'source' to 'dest'.
ssize_t
inf(const uint8_t *source, size_t slen, uint8_t *dest, size_t dlen)
{
  if (slen > ZLIB_CEILING || dlen > ZLIB_CEILING)
    return -1;

  /* allocate inflate state */
  z_stream strm;
  memset(&strm, 0, sizeof strm);
  int ret = inflateInit(&strm);
  if (ret != Z_OK) {
    log_warn("decompression failure (initialization): %s", strm.msg);
    return -1;
  }

  strm.next_in = const_cast<Bytef*>(source);
  strm.avail_in = slen;
  strm.next_out = dest;
  strm.avail_out = dlen;

  ret = inflate(&strm, Z_FINISH);
  if (ret != Z_STREAM_END) {
    log_warn("decompression failure: %s", strm.msg);
    inflateEnd(&strm);
    return -1;
  }

  inflateEnd(&strm);
  return strm.total_out;
}

ssize_t
gzInflate(const uint8_t *source, size_t slen, uint8_t *dest, size_t dlen)
{
  if (slen > ZLIB_CEILING || dlen > ZLIB_CEILING)
    return -1;

  z_stream strm;
  memset(&strm, 0, sizeof strm);
  int ret = inflateInit2(&strm, MAX_WBITS|16); // 16 = decode gzip (only)

  if (ret != Z_OK) {
    log_warn("decompression failure (initialization): %s", strm.msg);
    return -1;
  }

  strm.next_in = const_cast<Bytef*>(source);
  strm.avail_in = slen;
  strm.next_out = dest;
  strm.avail_out = dlen;

  ret = inflate(&strm, Z_FINISH);
  if (ret != Z_STREAM_END) {
    log_warn("decompression failure: %s", strm.msg);
    inflateEnd(&strm);
    return -1;
  }

  inflateEnd(&strm);
  return strm.total_out;
}

ssize_t
gzDeflate(const uint8_t *source, size_t slen, uint8_t *dest, size_t dlen,
          time_t mtime)
{
  if (slen > ZLIB_CEILING || dlen > ZLIB_CEILING)
    return -1;

  z_stream strm;
  memset(&strm, 0, sizeof strm);
  int ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                         MAX_WBITS|16, // compress as gzip
                         8, Z_DEFAULT_STRATEGY);
  if (ret != Z_OK) {
    log_warn("compression failure (initialization): %s", strm.msg);
    return -1;
  }

  gz_header gzh;
  memset(&gzh, 0, sizeof gzh);
  gzh.time = mtime;
  gzh.os = 0xFF; // "unknown"
  ret = deflateSetHeader(&strm, &gzh);
  if (ret != Z_OK) {
    log_warn("compression failure (initialization): %s", strm.msg);
    return -1;
  }

  strm.next_in = const_cast<Bytef*>(source);
  strm.avail_in = slen;
  strm.next_out = dest;
  strm.avail_out = dlen;

  ret = deflate(&strm, Z_FINISH);
  if (ret != Z_STREAM_END) {
    log_warn("compression failure: %s", strm.msg);
    deflateEnd(&strm);
    return -1;
  }

  deflateEnd(&strm);
  return strm.total_out;
}

uint32_t
generate_crc32c(const uint8_t *string, size_t length)
{
  log_assert(length <= std::numeric_limits<uInt>::max());

  uLong crc = crc32(crc32(0, 0, 0), string, length);

  // zlib also doesn't believe 'long' can be more than 32 bits wide.
  // This shouldn't ever fire unless there is a bug in zlib.
  log_assert(crc <= std::numeric_limits<uint32_t>::max());

  return crc;
}
