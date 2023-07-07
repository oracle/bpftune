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

#define __KERNEL__
#if defined(__TARGET_ARCH_x86)
#include <bpftune/vmlinux_x86_64.h>
#elif defined(__TARGET_ARCH_arm64)
#include <bpftune/vmlinux_aarch64.h>
#endif

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

extern __u32 LINUX_KERNEL_VERSION __kconfig;

#ifndef NULL
#define	NULL	((void *)0)
#endif

#define STATIC_ASSERT(x, msg)	_Static_assert(x, msg)

#ifndef __bpf_printk
#define __bpf_printk(fmt, ...)				\
({							\
	static const char ____fmt[] = fmt;	\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})
#endif

/* provide BPF_KPROBE/BPF_KRETPROBE to simplify legacy support */

#ifndef BPF_KPROBE
#define BPF_KPROBE(name, args...)                                           \
name(struct pt_regs *ctx);                                                  \
static __attribute__((always_inline)) typeof(name(0))                       \
____##name(struct pt_regs *ctx, ##args);                                    \
typeof(name(0)) name(struct pt_regs *ctx)                                   \
{                                                                           \
        _Pragma("GCC diagnostic push")                                      \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")              \
        return ____##name(___bpf_kprobe_args(args));                        \
        _Pragma("GCC diagnostic pop")                                       \
}                                                                           \
static __attribute__((always_inline)) typeof(name(0))                       \
____##name(struct pt_regs *ctx, ##args)
#endif /* BPF_KPROBE */

#ifndef BPF_KRETPROBE
#define ___bpf_kretprobe_args0() ctx
#define ___bpf_kretprobe_args1(x) \
        ___bpf_kretprobe_args0(), (void *)PT_REGS_RC(ctx)
#define ___bpf_kretprobe_args(args...) \
        ___bpf_apply(___bpf_kretprobe_args, ___bpf_narg(args))(args)

/*
 * BPF_KRETPROBE is similar to BPF_KPROBE, except, it only provides optional
 * return value (in addition to `struct pt_regs *ctx`), but no input
 * arguments, because they will be clobbered by the time probed function
 * returns.
 */
#define BPF_KRETPROBE(name, args...)                                        \
name(struct pt_regs *ctx);                                                  \
static __attribute__((always_inline)) typeof(name(0))                       \
____##name(struct pt_regs *ctx, ##args);                                    \
typeof(name(0)) name(struct pt_regs *ctx)                                   \
{                                                                           \
        _Pragma("GCC diagnostic push")                                      \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")              \
        return ____##name(___bpf_kretprobe_args(args));                     \
        _Pragma("GCC diagnostic pop")                                       \
}                                                                           \
static __always_inline typeof(name(0)) ____##name(struct pt_regs *ctx, ##args)
#endif /* BPF_KRETPROBE */

#ifdef BPFTUNE_LEGACY
#define BPF_FENTRY(func, args...)				\
	SEC("kprobe/" #func)					\
	int BPF_KPROBE(entry__##func, ##args)

#else
#define BPF_FENTRY(func, args...)				\
	SEC("fentry/" #func)					\
	int BPF_PROG(entry__##func, ##args)
#endif /* BPFTUNE_LEGACY */

#if LIBBPF_DEPRECATED_APIS
#define BPF_MAP_DEF(_name, _type, _key_size, _value, _max_entries)	\
	struct bpf_map_def SEC("maps") _name = {			\
		.type = _type,						\
		.key_size = sizeof(_key),				\
		.value_size = sizeof(_value),				\
		.max_entries = _max_entries,				\
	}

#define BPF_RINGBUF(_name, _max_entries)				\
	struct bpf_map_def SEC("maps") _name = {			\
		.type = BPF_MAP_TYPE_RINGBUF,				\
		.max_entries = _max_entries,				\
	}
#else
#define BPF_MAP_DEF(_name, _type, _key, _value, _max_entries)		\
        struct {							\
		__uint(type, _type);					\
		__type(key, _key);					\
		__type(value, _value);					\
		__uint(max_entries, _max_entries);			\
        } _name SEC(".maps")

#define BPF_RINGBUF(_name, _max_entries)				\
	struct {							\
		__uint(type, BPF_MAP_TYPE_RINGBUF);			\
		__uint(max_entries, _max_entries);			\
	} _name SEC(".maps")
#endif /* BPFTUNE_LEGACY */

/* used to save data on entry to be retrieved on return  */
#define save_entry_data(save_map, save_struct, save_field, save_data)	\
	do {								\
		struct save_struct __s = {};				\
		__u64 current = bpf_get_current_task();			\
		__s.save_field = save_data;				\
		bpf_map_update_elem(&save_map, &current, &__s, 0);	\
	} while (0)

#define get_entry_struct(save_map, save_result)				\
	do {								\
		__u64 current = bpf_get_current_task();                 \
                save_result =						\
			bpf_map_lookup_elem(&save_map, &current);	\
	} while (0)

#define get_entry_data(save_map, save_struct, save_field, save_result)	\
	do {								\
		__u64 current = bpf_get_current_task();			\
		struct save_struct *__s = bpf_map_lookup_elem(&save_map,\
							     &current);	\
		if (__s)						\
			save_result = __s->save_field;			\
		else							\
			save_result = 0;				\
	} while (0)

#define del_entry_struct(save_map)					\
	do {								\
		__u64 current = bpf_get_current_task();			\
		bpf_map_delete_elem(&save_map, &current);		\
	} while (0)

/* must be specified prior to including bpftune.h */
unsigned short bpftune_learning_rate;

#include <bpftune/bpftune.h>
#include <bpftune/corr.h>

BPF_RINGBUF(ring_buffer_map, 128 * 1024);

BPF_MAP_DEF(netns_map, BPF_MAP_TYPE_HASH, __u64, __u64, 65536);

unsigned int tuner_id;
unsigned int bpftune_pid;
/* init_net value used for older kernels since __ksym does not work */
unsigned long bpftune_init_net;

/* TCP buffer tuning */
#ifndef SO_SNDBUF
#define SO_SNDBUF       	7
#endif
#ifndef SO_RCVBUF
#define SO_RCVBUF       	8
#endif

#ifndef SOCK_SNDBUF_LOCK
#define SOCK_SNDBUF_LOCK	1
#endif
#ifndef SOCK_RCVBUF_LOCK
#define SOCK_RCVBUF_LOCK	2
#endif

#ifndef SK_MEM_QUANTUM
#define SK_MEM_QUANTUM		4096
#endif
#ifndef SK_MEM_QUANTUM_SHIFT
#define SK_MEM_QUANTUM_SHIFT	ilog2(SK_MEM_QUANTUM)
#endif

#ifndef SOL_TCP
#define SOL_TCP        		6
#endif

#ifndef TCP_CONGESTION
#define TCP_CONGESTION		13
#endif

#ifndef AF_INET
#define AF_INET			2
#endif
#ifndef AF_INET6
#define AF_INET6		10
#endif

#define sk_family		__sk_common.skc_family
#define sk_rmem_alloc		sk_backlog.rmem_alloc
#define sk_state		__sk_common.skc_state
#define sk_daddr		__sk_common.skc_daddr
#define sk_v6_daddr		__sk_common.skc_v6_daddr
#define sk_net			__sk_common.skc_net
#define sk_prot			__sk_common.skc_prot

#ifndef s6_addr32
#define s6_addr32		in6_u.u6_addr32
#endif

/* TCP congestion algorithm tuning */
#ifndef TCP_CA_NAME_MAX
#define TCP_CA_NAME_MAX		16
#endif

/* neigh table tuning */
#ifndef NUD_PERMANENT
#define NUD_PERMANENT	0x80
#endif
#ifndef NTF_EXT_LEARNED
#define NTF_EXT_LEARNED	0x10
#endif

#define EINVAL		22

bool debug;

#define bpftune_log(...)	__bpf_printk(__VA_ARGS__)
#define bpftune_debug(...)	if (debug) __bpf_printk(__VA_ARGS__)

extern const void init_net __ksym;

static __always_inline int __strncmp(char *s1, char *s2, size_t n)
{
	size_t i;
#pragma clang loop unroll(full)
	for (i = 0; i < n; i++) {
		if (s1[i] != s2[i])
			return s1[i] - s2[i];
	}
	return 0;
}

static __always_inline long get_netns_cookie(struct net *net)
{
	if (bpf_core_field_exists(net->net_cookie))
		return BPF_CORE_READ(net, net_cookie);
	if (net == &init_net || net == (void *)bpftune_init_net)
		return 0;
	/* not global ns, no cookie support. */
	return -1;
}
 
#define last_event_key(nscookie, tuner, event)	\
	((__u64)nscookie | ((__u64)event << 32) |((__u64)tuner <<48))

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u64);
} last_event_map SEC(".maps");

static __always_inline long send_net_sysctl_event(struct net *net,
						  int scenario_id, int event_id,
						  long *old, long *new,
						  struct bpftune_event *event)
{
	__u64 now = bpf_ktime_get_ns();
	__u64 event_key = 0;
	long nscookie = 0;
	__u64 *last_timep = NULL;
	int ret = 0;

	nscookie = get_netns_cookie(net);
	if (nscookie < 0)
		return nscookie;

	event_key = last_event_key(nscookie, tuner_id, event_id);
	/* avoid sending same event for same tuner+netns in < 25msec */
	last_timep = bpf_map_lookup_elem(&last_event_map, &event_key);
	if (last_timep) {
		if ((now - *last_timep) < (25 * MSEC))
			return 0;
		*last_timep = now;
	} else {
		bpf_map_update_elem(&last_event_map, &event_key, &now, 0);
	}

	event->tuner_id = tuner_id;
	event->scenario_id = scenario_id;
	event->netns_cookie = nscookie;
	event->update[0].id = event_id;
	event->update[0].old[0] = old[0];
	event->update[0].old[1] = old[1];
	event->update[0].old[2] = old[2];
	event->update[0].new[0] = new[0];
	event->update[0].new[1] = new[1];
	event->update[0].new[2] = new[2];
	ret = bpf_ringbuf_output(&ring_buffer_map, event, sizeof(*event), 0);
	bpftune_debug("tuner [%d] scenario [%d]: event send: %d ",
		    tuner_id, scenario_id, ret);
	bpftune_debug("\told '%ld %ld %ld'\n", old[0], old[1], old[2]);
	bpftune_debug("\tnew '%ld %ld %ld'\n", new[0], new[1], new[2]);
	return 0;
}

static __always_inline long send_sk_sysctl_event(struct sock *sk,
                                              int scenario_id, int event_id,
                                              long *old, long *new,
                                              struct bpftune_event *event)
{
	struct net *net = BPF_CORE_READ(sk, sk_net.net);

	return send_net_sysctl_event(net, scenario_id, event_id,
				     old, new, event);
}

static inline void corr_update_bpf(void *map, __u64 id,
				   __u64 netns_cookie,
				   __u64 x, __u64 y)
{
	struct corr_key key = { .id = id, .netns_cookie = netns_cookie };
	struct corr *corrp = bpf_map_lookup_elem(map, &key);

	if (!corrp) {
		struct corr corr = {};

		bpf_map_update_elem(map, &key, &corr, 0);

		corrp = bpf_map_lookup_elem(map, &key);
		if (!corrp)
			return;
	}
	corr_update(corrp, x, y);
}

char _license[] SEC("license") = "GPL v2";
