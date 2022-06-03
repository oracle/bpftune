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

#endif /* __BPFTUNE_H */
