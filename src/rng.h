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

/** Return a random integer in the range [0, hi), geometrically
 *  distributed over that range, with expected value 'xv'.
 *  (The rate parameter 'lambda' that's usually used to characterize
 *  the geometric/exponential distribution is equal to 1/xv.)
 *  'hi' must be no more than INT_MAX+1, as for 'rng_range'.
 *  'xv' must be greater than 0 and less than 'hi'.
 */
int rng_range_geom(unsigned int hi, unsigned int xv);

#endif
