# Plan for features, completed, to-do and possible future work

## Completed tasks

### Basic bpftune framework support
 - add configurable logging support syslog/stdout
 - add support for adding tuners dynamically via shared object
 - add support for adding BPF programs via skeleton
 - add support for specifying tunables associated with tuner
 - bpftune systemd service specification
 - add support for legacy tuner fallback; if the system does
   not support BPF features required, fall back to legacy version
   of tuner if available.
 - switch off tuners on per-ns basis; we should not switch off
   global tuners if someone fiddles with a tunable in a network
   namespace; make sure we have per-namespace disable for tuners.
   This assumes any customizations for namespace config of tunables
   on container bringup will stop us auto-tuning; this may need to
   be revisited in the future.
 - configurable learning rate: learning can be specified to bpftune
   via the "-r" parameter; this ranges from 0-4.  The learning
   rate values relate to when changes are made; i.e. within a
   specific % of a limit, we increase the limit by the same %; so
	- learning rate 0: within 1% of a limit, increase it by 1%
	- learning rate 1: within 3% of a limit, increase it by 3%
	- learning rate 2: withing 6% of a limit, increase it by 6%
	- learning rate 3: within 12% of a limit, increase it by 12%
	- learning rate 4: within 25% of a limit, increase it by 25%
   There is an inherent tradeoff in learning rate selection; a
   higher rate will make larger changes less frequently, while a lower
   rate will make smaller changes more frequently, but only if limits
   are closely approached.
 - we notice new tuners appearing/disappearing from /usr/lib64/bpftune
   via inotify.  We watch the above directory for tuner addition or
   removal to allow packages to separately deliver their own tuners.
 - make (lib)bpftune assume capabilities as needed; this reduces the
   threat surface of a service that requires CAP_SYS_ADMIN.
 - We deliver a bpftune-devel package to support separate tuner
   development.
 - And also show a sample standalone tuner in sample_tuner/ ; it
   demonstrates how to build a tuner .so and install it in
   /usr/local/lib64/bpftune; it is monitored for tuner appearance
   and disappearance also.

### sysctl tuner
 - add support for dynamically disabling relevant tuner if tunables change
   via sysctl tuner (tested)

### neighbour table tuner
 - tuner watches for neigh table adds, and increases table size
   if we approach full such that we do not drop neighbour information.
   Done on a per-table basis via netlink to target changes to
   tables which need it (tested)

### connection tuner
 - tuner monitors min RTT, max delivery rate on a per-host basis
   in order to identify which congestion control algorithm
   approaches the ideal rate where it fills the pipe but does
   not under- or over-estimate congestion.  Reinforcement learning
   is used to select actions that minimize cost (which is defined
   as divergence from optimal min RTT/max delivery rate).

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
   for netns add events so that we can maintain tuner state
   for non-global network namespaces also.

### Summary mode on exit
 - bpftune reports what changes were made to tunables on exit
   as a kind of summarization mode.

### Rollback mode

 - If run with "-R" (rollback), sysctl changes will be undone,
   so the user can explore what auto-tuning is done without
   making long-term changes.

### Packaging
 - added a "make pkg" target which creates rpm
 - set up other/bpftune for ol8 builds

### add support for aarch64/older kernels
- Add legacy kprobe support also as this will be needed for
  aarch64 which did not get BPF trampoline until 6.5; legacy
  is needed for older kernels that do not have fentry/fexit or
  iterators.  Added "bpftune -S" support that auto-detects
  level of support provided, and legacy tuners are used
  if full support is not possible.
  This support is now present and each tuner builds a
  legacy version, using definition BPFTUNE_LEGACY to
  distinguish.  This replaces fentry with kprobes etc.
  See CONTRIBUTING.md for more details on how to support
  legacy mode.

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

### TCP buffer tuner improvements
- one problem is hard to have a one max buffer size to fit all;
  can we use snd buffer clamping (via bpf_setsockopt) to clamp for
  small flows? this would be a good strategy to mimimize overhead
  for non-critical flows during memory crunches. tp->snd_cwnd_clamp
  and tp->window_clamp are clamping values for send/receive windows.
  use TCP_BPF_SNDCWND_CLAMP, TCP_WINDOW_CLAMP for these.  Problem:
  "moderate rcvbuf" behaviour alters window clamp so may need to
  be a send-side only approach.
- look at netdev_max_backlog; tune that too? Tune up when we
  see drops, also set net.core.flow_limit_cpu_bitmap to enable
  per-flow limits; these orient drops towards busier flows, ensuring
  that small flows get prioritized; see
  https://www.kernel.org/doc/html/latest/networking/scaling.html
  Initial implementation in net_buffer_tuner for netdev_max_backlog
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

### Connection tuner improvements
- done; see bpftune-tcp-conn (8)

### neigh table tuner

- look at gc frequency and churn; optimize this also?

- should we enable drop_gratuitous_arp if we see a lot of
  entries added?

## Future work

- assessing tuner strategy: are we helping or making things
  worse? Support multiple strategies per tuner, explore the
  best?  Multiple strategy support has landed, not used yet.
- kernel support for tunable override via bpf? Have decision points
  in kernel be over-rideable by BPF; would need to have sysctl
  denote "this is BPF tuned" somehow...
- mem tuning (min_free_kbytes etc)?
- kernel tunables (numa balancing, pid max, threads_max, etc)
- vm tunables?
- limiting ulimit? see OraBug 29123482
	OraBug 34378084 - Excessive Locking after switch back
- have a dedicated bpftune user, and make bpftune only executable
  by that user so we start with the right privilege set

