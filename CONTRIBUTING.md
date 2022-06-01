# Contributing to bpftune

The architecture used is

- a core daemon, src/bpftune.c
- a library, libbpftune which consists of functions used by core daemon
  and tuners, such as logging, BPF setup etc, src/libbpftune.c; and
- a set of plug-in shared object tuners which are loaded when bpftune
  starts; sysctl_tuner.[bpf.]c, neigh_table_tuner.[bpf.]c

# Adding a tuner

Tuners are added as plug-in .so objects built as tuner_name.c, and each tuner
has a BPF program named tuner_name.bpf.c.  To add a new tuner, add these
files and simply add tuner_name to TUNERS in src/Makefile.

# BPF component (tuner_name.bpf.c)

The BPF code must

```
#include bpftune.bpf.h
```

...since that header includes all relevant definitions and includes
the definition of the BPF ring buffer that tuners use to communicate
with userspace:

```
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 64 * 1024);
} ringbuf_map SEC(".maps");

```

On startup BPF reuses the map fd across all BPF objects; in other
words they all share this ring buffer to communication with bpftune.

It also include a global variable:

```
unsigned int tuner_id;
```

When bpftune loads the tuner, it assigns this tuner id to the
BPF object.  This allows us to send events from the BPF programs
in that object which identify the tuner source.  The tuner id
in the ringbuf event allows us to call the event handler callback
in the appropriate tuner.

# Userspace component - tuner_name.c

It should #include <libbpftune.h>, and must consist of the following
functions

```
int init(struct bpftuner *tuner, int ringbuf_map_fd);

void fini(struct bpftuner *tuner);

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   void *ctx);
```

The init function is called on tuner initialization, and is passed
the fd referring to the ring buffer map which is shared across tuners.
The init() function should do any additional BPF attachment not covered
by SEC() names (such as attaching to a cgroup), and initialize any
global variables.  All tuners should call

```
bpftuner_bpf_init(tuner_name, ringbuf_map_fd);
```

...since this loads the associated BPF skeleton.  In addition, if
the tuner auto-tunes any sysctls, an array of "struct bpftunable_desc":

```
struct bpftunable_desc {
        unsigned int id;
        enum bpftunable_type type;
        const char *name;
        __u8 num_values;
};
```

...should be added naming them, and

```
	bpftuner_tunables_init(tuner, num_descs, descs);
```

...should be called.  This informs bpftune so that if the sysctl
tuner sees a modification of a sysctl that should be auto-tuned,
we can disable the associated tuner.  So for example if the
neigh_table_tuner manages sysctl "net.ipv4.neigh.default.gc_thresh3",
so if the sysctl BPF program sees it being modified, we can disable
the associated neigh_table_tuner.

If any data structures are common across userspace and BPF, they
should be added to a tuner_name.h file which both include.

# Events

When an event the user-space component needs to know about occurs,
a ringbuf event should be sent.  The event structure is:

```
struct bpftune_event {
        unsigned int tuner_id;
        unsigned int scenario_id;
        union {
                struct bpftunable_update update[BPFTUNE_MAX_TUNABLES];
                char str[BPFTUNE_MAX_NAME];
                __u8 raw_data[BPFTUNE_MAX_DATA];
        };
};
```

The scenario refers to the event type (seen packet loss to remote
system), and the payload can be a string, a raw data structure etc.

# Overhead

When choosing BPF events to instrument, please try to avoid very
high-frequency events.  Try to use fentry instead of kprobe,
tp_btf instead of tracepoint etc as these perform much better.
