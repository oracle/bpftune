#define BPFTUNE_MAX_TUNERS		64

/* max # of tunables per tuner */
#define BPFTUNE_MAX_TUNABLES		10

enum bpftunable_type {
	BPFTUNABLE_SYSCTL,
	BPFTUNABLE_CONGESTION_CONTROL,
	BPFTUNABLE_MAX,
};

struct bpftunable {
	unsigned int id;
	enum bpftunable_type type;
	const char *name;
};

enum bpftuner_state {
	BPFTUNER_INACTIVE,
	BPFTUNER_ACTIVE,
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
	enum bpftuner_state state;
	const char *path;
	void *handle;
	const char *name;
	void *skel;
	int (*init)(struct bpftuner *tuner, int perf_map_fd);
	void (*fini)(struct bpftuner *tuner);
	int perf_map_fd;
	void (*event_handler)(struct bpftuner *tuner,
			      struct bpftune_event *event, void *ctx);
	struct bpftunable tunables[BPFTUNE_MAX_TUNABLES];
	const char **scenarios;
};
