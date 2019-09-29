/* Copyright 2012-2019 The Tor Project Inc.
 * Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */
#include <zlib.h>
#include <limits>

#include "util.h"
#include "compression.h"

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

ssize_t
compress(const uint8_t *source, size_t source_len,
         uint8_t *dest, size_t dest_len,
         compression_format fmt)
{
  log_assert(fmt == c_format_zlib || fmt == c_format_gzip);

  if (source_len > ZLIB_CEILING || dest_len > ZLIB_CEILING)
    return -1;

  z_stream strm;
  memset(&strm, 0, sizeof strm);

  int wbits = MAX_WBITS;
  if (fmt == c_format_gzip)
    wbits |= 16; // magic number 16 = compress as gzip

  int ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                         wbits, 8, Z_DEFAULT_STRATEGY);
  if (ret != Z_OK) {
    log_warn("compression failure (initialization): %s", strm.msg);
    return -1;
  }

  if (fmt == c_format_gzip) {
    gz_header gzh;
    memset(&gzh, 0, sizeof gzh);
    gzh.os = 0xFF; // "unknown"
    ret = deflateSetHeader(&strm, &gzh);
    if (ret != Z_OK) {
      log_warn("compression failure (initialization): %s", strm.msg);
      return -1;
    }
  }

  strm.next_in = const_cast<Bytef*>(source);
  strm.avail_in = source_len;
  strm.next_out = dest;
  strm.avail_out = dest_len;

  ret = deflate(&strm, Z_FINISH);
  if (ret != Z_STREAM_END) {
    log_warn("compression failure: %s", strm.msg);
    deflateEnd(&strm);
    return -1;
  }

  deflateEnd(&strm);
  return strm.total_out;
}

ssize_t
decompress(const uint8_t *source, size_t source_len, uint8_t *dest, size_t dest_len)
{
  if (source_len > ZLIB_CEILING || dest_len > ZLIB_CEILING)
    return -1;

  /* allocate inflate state */
  z_stream strm;
  memset(&strm, 0, sizeof strm);
  int ret = inflateInit2(&strm, MAX_WBITS|32); /* autodetect gzip/zlib */
  if (ret != Z_OK) {
    log_warn("decompression failure (initialization): %s", strm.msg);
    return -1;
  }

  strm.next_in = const_cast<Bytef*>(source);
  strm.avail_in = source_len;
  strm.next_out = dest;
  strm.avail_out = dest_len;

  ret = inflate(&strm, Z_FINISH);
  if (ret == Z_BUF_ERROR) {
    inflateEnd(&strm);
    return -2; // need more space
  }
  if (ret != Z_STREAM_END) {
    log_warn("decompression failure: %s", strm.msg);
    inflateEnd(&strm);
    return -1;
  }

  inflateEnd(&strm);
  return strm.total_out;
}
