/* Copyright 2012-2019 The Tor Project Inc.
 * Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */
#ifndef _COMPRESSION_H
#define _COMPRESSION_H

enum compression_format {
  c_format_zlib = 0,
  c_format_gzip = 1
};

/**
 * compresses SOURCE_LEN bytes of data from the buffer at SOURCE into the
 * buffer at DEST.  There are DEST_LEN bytes of available space at the
 * destination.  FMT specifies the desired format of the compressed
 * data: currently 'zlib' (RFC 1950) and 'gzip' (RFC 1952) formats are
 * supported.
 *
 * Returns the amount of data actually written to DEST, or -1 on error.
 */
ssize_t compress(const uint8_t *source, size_t source_len,
                 uint8_t *dest, size_t dest_len,
                 compression_format fmt);

/**
 * decompresses SOURCE_LEN bytes of data from the buffer at SOURCE into the
 * buffer at DEST.  There are DEST_LEN bytes of available space at the
 * destination.  Automatically detects the compression format in use.
 *
 * Returns the amount of data actually written to DEST, or -1 on error.
 */
ssize_t decompress(const uint8_t *source, size_t source_len,
                   uint8_t *dest, size_t dest_len);

#endif
