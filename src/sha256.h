/* See the LICENSE file for licensing information */

/**
 * \file sha256.h
 * \brief Headers for sha256.c.
 **/

#ifndef SHA256_H
#define SHA256_H

typedef struct sha256_state {
    uint64_t length;
    uint32_t state[8], curlen;
    unsigned char buf[64];
} sha256_state;

int sha256_init(sha256_state * md);
int sha256_process(sha256_state * md, const unsigned char *in,
                   unsigned long inlen);
int sha256_done(sha256_state * md, unsigned char *out);

#endif
