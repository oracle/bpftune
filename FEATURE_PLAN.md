# Plan for features, completed and to-do

## Completed tasks (June 3 2022)

### Basic bpftune framework support
 - add configurable logging support syslog/stdout (tested)
 - add support for adding tuners dynamically via shared object
 - add support for adding BPF programs via skeleton
 - add support for specifying tunables associated with tuner

### sysctl tuner
 - add support for dynamically disabling relevant tuner if tunables change
   via sysctl tuner (tested)

### neighbour table tuner
 - tuner watches for neigh table adds, and increases table size
   if we approach full such that we do not drop neighbour information.
   Done on a per-table basis via netlink to target changes to
   tables which need it (tested)

### congestion tuner
 - tuner counts retransmissions keyed by remote IP, and if we see
   a lot of retransmits in the last hour to a remote host, we apply
   BBR on connection setup to ensure we do not over-estimate
   congestion (and thus under-estimate link capacity) (tested)

### TCP buffer size tuner
 - tuner watches for tcp_expand_sndbuf() and checks if we approach
   tcp_wmem[2] max buffer size; if so increase buffer size to
   accommodate more data since app needs more space. (tested)
 
### Test suite

 - tests should validate core features and tunable behaviour

 - tests should run quickly (<5min)

 - tests should not require remote system to run (use netns)

### Documentation

- document bpftune + options with manual page
- document each tuner with manual page
- add CONTRIBUTING.md to describe how to contribute, goals and key
  design constraints

## To do tasks

### container-specific tuning (end June 2022)

We want bpftune to be able to handle auto-tuning for containers
as well as the global namespace.

 - Rework framework to support per-namespace bpftune, so tuners
   can associate with a specific bpftune instance which consists
   of a specific cgroup, net namespace id etc.  This would allow
   us to auto-tune on a container-level granularity.  Tuner init
   will be passed a "struct bpftune" containing ring buffer fd
   for events, cgroup path, net namespace id, etc.  BPF programs
   may need to be multiply attached for each bpftune instance
   (each cgroup).  BPF programs will contain a bpftune id also;
   this allows bpfune to figure out which bpftune instance a
   per-cgroup event is destined for.

 - Need to enhance fentry/tp-based programs that attach globally
   to do per-namespace events. The associated BPF programs could
   set netns id in events such that bpftune can map from netns
   to the bpftune instance (and associated tuner) that should
   handle the event

 - so event is sent containing either a bpftune id (cgroup bpf)
   or a netns id (tp/fentry); in the latter case we map
   netns id to bpftune id to find the bpftune instance associated
   with the entry, then we can handle tunables on a per-netns
   basis.

 - need infrastructure to set tunables on a per-netns basis,
   both netlink and sysctl.

 - catch namespace creation, pair to cgroup and create bpftune
   instance automatically

### neigh table tuner (end July 2022)

- look at gc frequency and churn; optimize this also?

### tcp tuner
 - initial snd buffer sizing; tune by service/remote system
   to optimize?
 - look at SO_[SND|RCV]BPF setting; does that need to be
   overridden?
