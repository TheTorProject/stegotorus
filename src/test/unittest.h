/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef UNITTEST_H
#define UNITTEST_H

#include "tinytest_macros.h"

/* Master group list - defined in unitgrplist.c (which is generated). */
extern const struct testgroup_t unittest_groups[];

#define ALEN(x) (sizeof x/sizeof x[0])

#endif
