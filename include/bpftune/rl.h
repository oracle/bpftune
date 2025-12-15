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
 * License along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _RL_H
#define _RL_H

#ifdef __KERNEL__

/* choose random state every epsilon states */
static __always_inline int epsilon_greedy(__u32 greedy_state, __u32 num_states,
					  __u32 epsilon)
{
	__u32 r = bpf_get_prandom_u32();

	if (r % epsilon)
		return greedy_state;
	/* need a fresh random number, since we already know r % epsilon == 0. */
	r = bpf_get_prandom_u32();
	return r % num_states;
}

#endif /* __KERNEL__ */

/* simple RL update for a value function; use gain to update value function
 * using bitshift scaling for learning rate.
 */
static __always_inline __u64 rl_update(__u64 value, __u64 gain, __u8 bitshift)
{
	if (!value)
		return gain;
	if (gain > value)
		return value + ((gain - value) >> bitshift);
	else if (gain < value)
		return value - ((value - gain) >> bitshift);
	else
		return value;
}

#endif /* _RL_H */
