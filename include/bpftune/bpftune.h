/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#ifndef __BPFTUNE_H
#define __BPFTUNE_H


#define BPFTUNE_MAX_TUNERS		64

/* max # of tunables per tuner */
#define BPFTUNE_MAX_TUNABLES		16

#define BPFTUNE_MAX_SCENARIOS		16

#define BPFTUNE_DELTA_MIN		0	/* 1% */
#define BPFTUNE_DELTA_MAX		4	/* 25% */

extern unsigned short bpftune_learning_rate;

#ifndef min
#define min(a, b)       ((a) < (b) ? (a) : (b))
#endif

/*
 * convert learning rate to bitshift value
 *
 * 4 -> bitshift of 2 (25%)
 * 3 -> bitshift of 3 (12.5%)
 * 2 -> bitshift of 4 (6.25%)
 * 1 -> bitshift of 5 (3.125%)
 * 0 -> bitshift of 6 (1.0625%)
 */
#define BPFTUNE_BITSHIFT	\
	((BPFTUNE_DELTA_MAX + 2) - min(bpftune_learning_rate, BPFTUNE_DELTA_MAX))

#define BPFTUNE_GROW_BY_DELTA(val)    ((val) + ((val) >> BPFTUNE_BITSHIFT))

/* shrink by delta (default 25%) */
#define BPFTUNE_SHRINK_BY_DELTA(val)  ((val) - ((val) >> BPFTUNE_BITSHIFT))

#define MSEC				((__u64)1000000)
#define SECOND				((__u64)1000000000)
#define MINUTE				(60 * SECOND)
#define HOUR				(3600 * SECOND)

#define NEARLY_FULL(val, limit) \
	((val) >= (limit) || (val) + ((limit) >> BPFTUNE_BITSHIFT) >= (limit))

enum bpftunable_type {
	BPFTUNABLE_SYSCTL,
	BPFTUNABLE_OTHER,
	BPFTUNABLE_MAX,
};

enum bpftune_state {
	BPFTUNE_INACTIVE,
	BPFTUNE_ACTIVE,		/* actively being tuned. */
	BPFTUNE_MANUAL,		/* manual intervention observed. */
	BPFTUNE_GONE,		/* resource gone */
};

struct bpftunable_scenario {
	unsigned int id;
	const char *name;
	const char *description;
};

/* some tunables are defined as triples */

#define BPFTUNE_MAX_VALUES	3

struct bpftunable_desc {
	unsigned int id;
	enum bpftunable_type type;
	const char *name;
	bool namespaced;	/* settable in non-global namespace? */
	__u8 num_values;
};

struct bpftunable_stats {
	unsigned long global_ns[BPFTUNE_MAX_SCENARIOS];
	unsigned long nonglobal_ns[BPFTUNE_MAX_SCENARIOS];
};

struct bpftunable {
	struct bpftunable_desc desc;
	enum bpftune_state state;
	long initial_values[BPFTUNE_MAX_VALUES];
	long current_values[BPFTUNE_MAX_VALUES];
	struct bpftunable_stats stats;
};

struct bpftunable_update {
	unsigned int id;
	__s64 old[BPFTUNE_MAX_VALUES];
	__s64 new[BPFTUNE_MAX_VALUES];
};

#define BPFTUNE_MAX_NAME	128
#define BPFTUNE_MAX_DATA	128

#define BPFTUNE_MAX_UPDATES	4

struct bpftune_event {
	unsigned int tuner_id;
	unsigned int scenario_id;
	unsigned long netns_cookie;
	int pid;
	union {
		struct bpftunable_update update[BPFTUNE_MAX_UPDATES];
		char str[BPFTUNE_MAX_NAME];
		__u8 raw_data[BPFTUNE_MAX_DATA];
	};
};

struct bpftuner_netns {
	struct bpftuner_netns *next;	
	unsigned long netns_cookie;
	enum bpftune_state state;
};

struct bpftuner {
	unsigned int id;
	enum bpftune_state state;
	struct bpftuner_netns netns;
	const char *path;
	void *handle;
	const char *name;
	struct bpf_object_skeleton *skeleton;
	bool bpf_legacy;
	void *skel;
	void *obj;
	int (*init)(struct bpftuner *tuner);
	void (*fini)(struct bpftuner *tuner);
	void *ring_buffer_map;
	int ring_buffer_map_fd;
	void *corr_map;
	int corr_map_fd;
	void *netns_map;
	int netns_map_fd;
	void (*event_handler)(struct bpftuner *tuner,
			      struct bpftune_event *event, void *ctx);
	unsigned int num_tunables;
	struct bpftunable *tunables;
	unsigned int num_scenarios;
	struct bpftunable_scenario *scenarios;
};

/* from include/linux/log2.h */
/**
 * ilog2 - log of base 2 of 32-bit or a 64-bit unsigned value
 * @n - parameter
 *
 * constant-capable log of base 2 calculation
 * - this can be used to initialise global variables from constant data, hence
 *   the massive ternary operator construction
 *
 * selects the appropriately-sized optimised version depending on sizeof(n)
 */
#ifndef ilog2
#define ilog2(n)                                \
(						\
                (n) < 2 ? 0 :                   \
                (n) & (1ULL << 63) ? 63 :       \
                (n) & (1ULL << 62) ? 62 :       \
                (n) & (1ULL << 61) ? 61 :       \
                (n) & (1ULL << 60) ? 60 :       \
                (n) & (1ULL << 59) ? 59 :       \
                (n) & (1ULL << 58) ? 58 :       \
                (n) & (1ULL << 57) ? 57 :       \
                (n) & (1ULL << 56) ? 56 :       \
                (n) & (1ULL << 55) ? 55 :       \
                (n) & (1ULL << 54) ? 54 :       \
                (n) & (1ULL << 53) ? 53 :       \
                (n) & (1ULL << 52) ? 52 :       \
                (n) & (1ULL << 51) ? 51 :       \
                (n) & (1ULL << 50) ? 50 :       \
                (n) & (1ULL << 49) ? 49 :       \
                (n) & (1ULL << 48) ? 48 :       \
                (n) & (1ULL << 47) ? 47 :       \
                (n) & (1ULL << 46) ? 46 :       \
                (n) & (1ULL << 45) ? 45 :       \
                (n) & (1ULL << 44) ? 44 :       \
                (n) & (1ULL << 43) ? 43 :       \
                (n) & (1ULL << 42) ? 42 :       \
                (n) & (1ULL << 41) ? 41 :       \
                (n) & (1ULL << 40) ? 40 :       \
                (n) & (1ULL << 39) ? 39 :       \
                (n) & (1ULL << 38) ? 38 :       \
                (n) & (1ULL << 37) ? 37 :       \
                (n) & (1ULL << 36) ? 36 :       \
                (n) & (1ULL << 35) ? 35 :       \
                (n) & (1ULL << 34) ? 34 :       \
                (n) & (1ULL << 33) ? 33 :       \
                (n) & (1ULL << 32) ? 32 :       \
                (n) & (1ULL << 31) ? 31 :       \
                (n) & (1ULL << 30) ? 30 :       \
                (n) & (1ULL << 29) ? 29 :       \
                (n) & (1ULL << 28) ? 28 :       \
                (n) & (1ULL << 27) ? 27 :       \
                (n) & (1ULL << 26) ? 26 :       \
                (n) & (1ULL << 25) ? 25 :       \
                (n) & (1ULL << 24) ? 24 :       \
                (n) & (1ULL << 23) ? 23 :       \
                (n) & (1ULL << 22) ? 22 :       \
                (n) & (1ULL << 21) ? 21 :       \
                (n) & (1ULL << 20) ? 20 :       \
                (n) & (1ULL << 19) ? 19 :       \
                (n) & (1ULL << 18) ? 18 :       \
                (n) & (1ULL << 17) ? 17 :       \
                (n) & (1ULL << 16) ? 16 :       \
                (n) & (1ULL << 15) ? 15 :       \
                (n) & (1ULL << 14) ? 14 :       \
                (n) & (1ULL << 13) ? 13 :       \
                (n) & (1ULL << 12) ? 12 :       \
                (n) & (1ULL << 11) ? 11 :       \
                (n) & (1ULL << 10) ? 10 :       \
                (n) & (1ULL <<  9) ?  9 :       \
                (n) & (1ULL <<  8) ?  8 :       \
                (n) & (1ULL <<  7) ?  7 :       \
                (n) & (1ULL <<  6) ?  6 :       \
                (n) & (1ULL <<  5) ?  5 :       \
                (n) & (1ULL <<  4) ?  4 :       \
                (n) & (1ULL <<  3) ?  3 :       \
                (n) & (1ULL <<  2) ?  2 :       \
                1 )
#endif

#endif /* __BPFTUNE_H */
