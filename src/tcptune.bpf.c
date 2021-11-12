/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#include "vmlinux.h"

#include "tcptune.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef SO_SNDBUF
#define SO_SNDBUF	7
#endif
#ifndef SO_RCVBUF
#define SO_RCVBUF	8
#endif

#ifndef SOL_TCP
#define SOL_TCP		6
#endif

#ifndef TCP_CONGESTION
#define TCP_CONGESTION	13
#endif

#ifndef TCP_CA_NAME_MAX
#define TCP_CA_NAME_MAX 16
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__uint(value_size, sizeof(struct tcptune_info));
	__uint(key_size, sizeof(int));
} tcptune_info_map SEC(".maps");

static __always_inline struct tcptune_info *get_tcptune_info(int param)
{
	return bpf_map_lookup_elem(&tcptune_info_map, &param);
}

SEC("kprobe/tcp_chrono_start")
int tcp_chrono_start(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
	enum tcp_chrono type = (enum tcp_chrono)PT_REGS_PARM2_CORE(ctx);
	struct tcptune_info *info, new = { };

	if (type != TCP_CHRONO_SNDBUF_LIMITED)
		return 0;

	info = get_tcptune_info(TCP_SNDBUF_LIMITED);
	if (info) {
		__bpf_printk("sk %llx type %d", sk, type);
	}
	return 0;
}

SEC("cgroup/setsockopt")
int setsockopt(struct bpf_sockopt_kern *ctx)
{
	__u8 *optval_end = ctx->optval_end;
	__u8 *optval = ctx->optval;
	struct sock *sk = ctx->sk;
	int optname = ctx->optname;
	int level = ctx->level;
	__u32 val;

	//__bpf_printk("setsockopt %d\n", optname);

	if (optname != SO_SNDBUF && optname != SO_RCVBUF)
		return 1;

	if (optval + sizeof(__u32) > optval_end)
                        return 1; /* EPERM, bounds check */

	//__bpf_printk("setsockopt %d %llu\n", optname,
	//	     optval ? *((__u32 *)optval) : 0);
	return 1;
}

SEC("kprobe/tcp_sndbuf_expand")
int sendbuf_expand(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
	int sndbuf;

	sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
	//__bpf_printk("expanding send buffer for sock %llx, current %d\n",
	//	     sk, sndbuf);
	return 0;
}

__u32 srtt_threshold;

SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *ops)
{
	char dctcp[TCP_CA_NAME_MAX] = "dctcp";
	char bbr[TCP_CA_NAME_MAX] = "bbr";
	int ret = 0;

	switch (ops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		if (ops->srtt_us == 0)
			return 0;
		break;
	default:
		return 0;
	}
	if (ops->srtt_us > srtt_threshold) {
		ret = bpf_setsockopt(ops, SOL_TCP, TCP_CONGESTION,
				     &bbr, sizeof(bbr));
		__bpf_printk("bpf sockops (srtt_us %d), cong bbr result %d\n",
			     ops->srtt_us, ret);
	} else {
		ret = bpf_setsockopt(ops, SOL_TCP, TCP_CONGESTION,
				     &dctcp, sizeof(dctcp));
		 __bpf_printk("bpf sockops (srtt_us %d), cong dctcp result %d\n",
			      ops->srtt_us, ret);
	}

	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
