# Plan for features, completed, to-do and possible future work

## Completed tasks (Jan 9 2023)

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
   >3% retransmission for a connection to a remote host, we apply
   BBR on connection setup to ensure we do not over-estimate
   congestion (and thus under-estimate link capacity) (tested)

### TCP buffer size tuner
 - tuner watches for tcp_expand_sndbuf() and checks if we approach
   tcp_wmem[2] max buffer size; if so increase buffer size to
   accommodate more data since app needs more space.  Also watch
   for correlation between [wr]mem and smoothed round-trip time;
   if we see these correlate, we are introducing latency so stop
   increasing buffer size (tested)
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

### Summary mode on exit
 - bpftune reports what changes were made to tunables on exit
   as a kind of summarization mode.

### Packaging
 - added a "make pkg" target which creates rpm
 - set up other/bpftune for ol8 builds

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

### add support for aarch64/uek6
- currently we only support x86_64+UEK7/LUCI/upstream due to
  use of recent features (fentry/fexit, iterators etc).  Add
  legacy kprobe support also as this will be needed for
  UEK7 aarch64 support and UEK6 support where fentry does
  not exist.  Also need to have an alternative to iterator
  support for setting congestion control value; tcp-bpf
  based seems the only workable way; enable retransmit
  events for all connections and set cong control for
  those that see >1 percent retransmits.  Downside is it
  will not work for existing connections like iSCSI.

### switch off tuners on per-ns basis
- we should not switch of global tuner if someone fiddles with
  a tunable in a namespace, so make sure we have per-namespace
  disable for tuners.  Also do we need to spot initial namespace
  config of tunables from sysctl.conf and ignore it?

### set up project packaging and signing
- filed https://ca-labops-help.us.oracle.com/show_bug.cgi?id=28072
- package builds working now at other/bpftune
- to do: ol7, ol9: for ol7 need to have alternative to skel
  generation/stash newer bpftool; for ol9 need set up with
  libbpf[-devel] as per ol7/8.

### add a configurable learning rate
- currently we check for limit approach and up values based
  on a 25% value; i.e. within 25% of limit, adjust up by 25%.
  This is computed efficiently via (limit - (limit >> 2)). We
  could make the bitshift configurable, ranging from a learning
  rate that works like this:

	- 1; equivalent to limit >> 6, i.e. 1.5625% learning rate
	- 2; equivalent to limit >> 5, i.e. 3.125% learning rate
	- 3; equivlanet to limit >> 4, i.e. 6.25% learning rate
	- 4; equivalent to limit >> 3, i.e  12.5% learning rate
	- 5; equivalent to limit >> 2, i.e. 25% learning rate

At the lower end of the scale, change would be more frequent but
also more gradual, so probably better for the risk-averse; we
would only update buffer sizes for example if we came within
1.5% of buffer limit, and only increase buffer size by 1.5%.

### TCP buffer tuner improvements
- one problem is hard to have a one max buffer size to fit all;
  can we use snd buffer clamping (via bpf_setsockopt) to clamp for
  small flows? this would be a good strategy to mimimize overhead
  for non-critical flows during memory crunches. tp->snd_cwnd_clamp
  and tp->window_clamp are clamping values for send/receive windows.
  use TCP_BPF_SNDCWND_CLAMP, TCP_WINDOW_CLAMP for these.  Problem:
  "moderate rcvbuf" behaviour alters window clamp so may need to
  be a send-side only approach.
- look at netdev_max_backlog; tune that too?
- initial buffer sizing: can we find a heuristic to minimize an
  error signal (number of updates to buffer size?).  Problem:
  this could devolve into simply setting [wr]mem[1] = [wr]mem[2].
  Pole balancing problem?  Set by well-know service history?
  If we stash the buffer sizes on connection destroy, we can
  learn and use sockops prog to set initial buffer size.
  use BPF_SOCK_OPS_RWND_INIT to set default recieve buffer size
  and bpf_setsockopt(.., TCP_BPF_IW, ..) to set send buffer size.
- look at SO_[SND|RCV]BPF setting; does that need to be
  overridden? If we can trace cases where more buffer would
  help maybe we can learn which well-known ports do buffer
  sizing wrong? Perhaps at a minimum we should catch cases
  where SO_[SND|RCV]BUF is not honoured do to [wr]mem_max
  settings and adjust [wr]mem_max?

### Congestion tuner improvements
- use htcp for large bandwidth-delay product links - a large
BDP is > 10^5, so use htcp for those cases.  Use rate estimates
to generate BDP estimate.  Problem - h-tcp is terrible at
high loss rates so investigate sweet spot of loss rate/perf
for h-tcp, otherwise use BBR.

### neigh table tuner

- look at gc frequency and churn; optimize this also?

- should we enable drop_gratuitous_arp if we see a lot of
  entries added?

## Future work

- mem tuning (min_free_kbytes etc)?
- kernel tunables (numa balancing, pid max, threads_max, etc)
- vm tunables?
- limiting ulimit? see
	https://bug.oraclecorp.com/pls/bug/webbug_print.show?c_rptno=29123482
	issue SR# 3-30085302261 / BUG: 34378084 - Excessive Locking after switch back : EMA: 119404

