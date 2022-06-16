#ifndef __BPFTUNE_H
#define __BPFTUNE_H


#define BPFTUNE_MAX_TUNERS		64

/* max # of tunables per tuner */
#define BPFTUNE_MAX_TUNABLES		10

/* grow by 25% */
#define BPFTUNE_GROW_BY_QUARTER(val)    ((val) + ((val) >> 2))

enum bpftunable_type {
	BPFTUNABLE_SYSCTL,
	BPFTUNABLE_CONGESTION_CONTROL,
	BPFTUNABLE_MAX,
};

enum bpftune_state {
	BPFTUNE_INACTIVE,
	BPFTUNE_ACTIVE,		/* actively being tuned. */
	BPFTUNE_MANUAL,		/* manual intervention observed. */
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

struct bpftunable {
	struct bpftunable_desc desc;
	enum bpftune_state state;
	long initial_values[BPFTUNE_MAX_VALUES];
	long current_values[BPFTUNE_MAX_VALUES];
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
	void *skel;
	int (*init)(struct bpftuner *tuner, int ringbuf_map_fd);
	void (*fini)(struct bpftuner *tuner);
	void *ringbuf_map;
	int ringbuf_map_fd;
	void (*event_handler)(struct bpftuner *tuner,
			      struct bpftune_event *event, void *ctx);
	unsigned int num_tunables;
	struct bpftunable *tunables;
	const char **scenarios;
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
