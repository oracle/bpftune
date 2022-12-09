# Plan for features, completed, to-do and possible future work

## Completed tasks (June 20 2022)

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
 - tuner watches for tcp_rcv_space_adjust() and if we approach
   tcp_rmem[2] increase buffer size to accommodate more space. (tested)
 - tuner watches for tcp memory pressure/exhaustion.  For the former
   we scale up all tcp_mem[2] value, for the latter we reduce
   tcp_[wr]mem[2], since we want to avoid memory exhaustion if
   possible (tested)
 
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

### set up project packaging and signing

### TCP buffer tuner
- look at pulling buffer values back down based on longer latency
  (potential bufferbloat)
- look at netdev_max_backlog; tune that too?
- initial buffer sizing: can we find a heuristic to minimize an
  error signal (number of updates to buffer size?).  Problem:
  this could devolve into simply setting [wr]mem[1] = [wr]mem[2].
  Pole balancing problem?  Set by well-know service history?
  If we stash the buffer sizes on connection destroy, we can
  learn.
- look at SO_[SND|RCV]BPF setting; does that need to be
  overridden? If we can trace cases where more buffer would
  help maybe we can learn which well-known ports do buffer
  sizing wrong?

### neigh table tuner (end July 2022)

- look at gc frequency and churn; optimize this also?

- should we enable drop_gratuitous_arp if we see a lot of
  entries added?

## Future work

- kernel tunables (numa balancing, pid max, threads_max, etc)
- vm tunables?
- limiting ulimit? see
	https://bug.oraclecorp.com/pls/bug/webbug_print.show?c_rptno=29123482
	issue SR# 3-30085302261 / BUG: 34378084 - Excessive Locking after switch back : EMA: 119404

