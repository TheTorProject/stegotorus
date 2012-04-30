/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */
#ifndef _COMPRESSION_H
#define _COMPRESSION_H

enum compression_format {
  c_format_zlib = 0,
  c_format_gzip = 1
};

/**
 * Compress SLEN bytes of data from the buffer at SOURCE into the
 * buffer at DEST.  There are DLEN bytes of available space at the
 * destination.  FMT specifies the desired format of the compressed
 * data: currently 'zlib' (RFC 1950) and 'gzip' (RFC 1952) formats are
 * supported.
 *
 * Returns the amount of data actually written to DEST, or -1 on error.
 */
ssize_t compress(const uint8_t *source, size_t slen,
                 uint8_t *dest, size_t dlen,
                 compression_format fmt);

/**
 * Decompress SLEN bytes of data from the buffer at SOURCE into the
 * buffer at DEST.  There are DLEN bytes of available space at the
 * destination.  Automatically detects the compression format in use.
 *
 * Returns the amount of data actually written to DEST, or -1 on error.
 */
ssize_t decompress(const uint8_t *source, size_t slen,
                   uint8_t *dest, size_t dlen);

#endif
