/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#ifndef _CORR_H
#define _CORR_H

#define CORR_MIN_SAMPLES	10

/* threshold at which we determine correlation is significant */
#define CORR_THRESHOLD		((long double)0.75)
#define CORR_HIGH_THRESHOLD	((long double)0.9)

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

static inline void corr_reset(struct corr *c)
{
	__builtin_memset(c, 0, sizeof(*c));
}

/* reset correlation if we overflow any values */
#define corr_update_var(c, var, delta)			\
	do {						\
		if (((c->var) + (delta)) < c->var) {	\
			corr_reset(c);			\
			return;				\
		}					\
		(c->var) += (delta);			\
	} while (0)

static inline void corr_update(struct corr *c, __u64 x, __u64 y)
{
	corr_update_var(c, n, 1);
	corr_update_var(c, sum_x, x);
	corr_update_var(c, sum_x_sq, x*x);
	corr_update_var(c, sum_y, y);
	corr_update_var(c, sum_y_sq, y*y);
	corr_update_var(c, sum_prod_x_y, x*y);
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

	if (c->n < CORR_MIN_SAMPLES)
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

static inline int corr_update_user(int map, __u64 id,
				   __u64 netns_cookie,
				   __u64 x, __u64 y)
{
	struct corr_key key = { .id = id, .netns_cookie = netns_cookie };
	struct corr corr = {};

	bpf_map_lookup_elem(map, &key, &corr);
	corr_update(&corr, x, y);
	return bpf_map_update_elem(map, &key, &corr, 0);
}

#endif /* __KERNEL__ */

#endif /* _CORR_H */
