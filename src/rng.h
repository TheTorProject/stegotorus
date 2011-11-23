/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information
*/

#ifndef RNG_H
#define RNG_H

/** Set b to contain n random bytes. */
int rng_bytes(uint8_t *b, size_t n);

/** Return a random integer in the range [0, max).
 * 'max' must be between 1 and INT_MAX+1, inclusive.
 */
int rng_int(unsigned int max);

/** Return a random integer in the range [min, max).
 *  'max' must be at least one greater than 'min' and no greater than
 *  INT_MAX+1.
 */
int rng_range(unsigned int min, unsigned int max);

#endif
