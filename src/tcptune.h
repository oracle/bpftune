/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

/* min tuning interval in seconds */
#define TCP_TUNE_MIN_INTERVAL	10

enum tcptune_param {
	TCP_SNDBUF_LIMITED,
};

struct tcptune_info {
	__u64	timestamp;
	__u64	val;	
};
