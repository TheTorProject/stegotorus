/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */
#ifndef _ZPACK_H
#define _ZPACK_H

ssize_t def(const uint8_t *source, size_t slen,
            uint8_t *dest, size_t dlen,
            int level);
ssize_t inf(const uint8_t *source, size_t slen,
            uint8_t *dest, size_t dlen);

ssize_t gzInflate(const uint8_t *source, size_t slen,
                  uint8_t *dest, size_t dlen);
ssize_t gzDeflate(const uint8_t *source, size_t slen,
                  uint8_t *dest, size_t dlen,
                  time_t mtime);

uint32_t generate_crc32c(const uint8_t *string, size_t length);

#endif
