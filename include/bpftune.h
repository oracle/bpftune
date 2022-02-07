#define BPFTUNE_MAX_TUNERS		64

/* max # of tunables per tuner */
#define BPFTUNE_MAX_TUNABLES		10

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
	__s64 initial_values[BPFTUNE_MAX_VALUES];
	__s64 current_values[BPFTUNE_MAX_VALUES];
};

struct bpftunable_update {
	unsigned int id;
	__s64 old;
	__s64 new;
};

struct bpftune_event {
	unsigned int tuner_id;
	unsigned int scenario_id;
	struct bpftunable_update update[BPFTUNE_MAX_TUNABLES];
};

struct bpftuner {
	unsigned int id;
	enum bpftune_state state;
	const char *path;
	void *handle;
	const char *name;
	void *tuner_bpf;
	void *skel;
	int (*init)(struct bpftuner *tuner, int perf_map_fd);
	void (*fini)(struct bpftuner *tuner);
	void *perf_map;
	int perf_map_fd;
	void (*event_handler)(struct bpftuner *tuner,
			      struct bpftune_event *event, void *ctx);
	unsigned int num_tunables;
	struct bpftunable *tunables;
	const char **scenarios;
};
