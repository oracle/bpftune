# Plan for features, completed, to-do and possible future work

## Completed tasks (June 3 2022)

### Basic bpftune framework support
 - add configurable logging support syslog/stdout (tested)
 - add support for adding tuners dynamically via shared object
 - add support for adding BPF programs via skeleton
 - add support for specifying tunables associated with tuner
 - bpftune systemd service specification

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
 
### netns tuner
 - tuner iterates over network namespaces at init and watches
   for netns add/remove events so that we can maintain tuner
   state for non-global network namespaces also.

### Packaging
 - added a "make pkg" target which creates rpm

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

### set up project packaging and signing (end June 2022)

### neigh table tuner (end July 2022)

- look at gc frequency and churn; optimize this also?

- should we enable drop_gratuitous_arp if we see a lot of
  entries added?

### tcp tuner
 - initial snd buffer sizing; tune by service/remote system
   to optimize?
 - look at SO_[SND|RCV]BPF setting; does that need to be
   overridden?


## Future work

- kernel tunables (numa balancing, pid max, threads_max, etc)
- vm tunables?

