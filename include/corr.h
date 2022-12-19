/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#ifndef _CORR_H
#define _CORR_H

#define CORR_MIN_SAMPLES	10

/* correlate tunables via id + netns cookie */
struct corr_key {
	__u64 id;
	unsigned long netns_cookie;
};

struct corr {
	__u64 n;
	__u64 sum_x;
	__u64 sum_x_sq;
	__u64 sum_y;
	__u64 sum_y_sq;
	__u64 sum_prod_x_y;
};

static inline void corr_update(struct corr *c, __u64 x, __u64 y)
{
	c->n++;
	c->sum_x += x;
	c->sum_x_sq += (x*x);
	c->sum_y += y;
	c->sum_y_sq += (y*y);
	c->sum_prod_x_y += (x*y);
}

#ifndef __KERNEL__

#include <math.h>

/* covar(x,y) = sum((x - mean(x))(y - mean(y)))/(N-1)
 *
 * the above numerator simplifies to
 *
 * sum(x*y) + (N*mean(x)*mean(y)) - (2*sum(x)*mean(y)) - (2*sum(y)*mean(x))
 * -> ...since mean(x) = sum(x)/N...
 * sum(x*y) + (sum(x)*sum(y)/N - sum(x)*sum(y)/N - sum(y)*sum(x)/N
 *
 * So
 * covar(x,y) =
 * ->
 * ((sum(x*y)) - (sum(x)*sum(y)))/N/(N-1)
 */
static inline long double covar_compute(struct corr *c)
{
	long double result;

	if (c->n < CORR_MIN_SAMPLES)
		return 0;

	result = (long double)c->sum_prod_x_y -
		 ((long double)(c->sum_x * c->sum_y)/c->n);
	result /= (c->n - 1);

	return result;
}

static inline long double corr_compute(struct corr *c)
{
	long double cov = covar_compute(c);
	long double var_x, var_y;

	if (c->n < 2)
		return 0;
	var_x = ((long double)c->sum_x_sq -
		 ((long double)(c->sum_x * c->sum_x)/c->n))/
		(c->n - 1);
	var_y = ((long double)c->sum_y_sq -
		 ((long double)(c->sum_y * c->sum_y)/c->n))/
		(c->n - 1);

	if (var_x == 0 || var_y == 0)	
		return 0;
	return cov/(sqrtl(var_x)*sqrtl(var_y));
}
#endif /* __KERNEL__ */

#endif /* _CORR_H */
