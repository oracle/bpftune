# bpftune - BPF driven auto-tuning

bpftune aims to provide lightweight, always-on auto-tuning of system
behaviour.  The key benefit it provides are

- by using BPF observability features, we can continuously monitor
  and adjust system behaviour
- because we can observe system behaviour at a fine grain (rather
  than using coarse system-wide stats), we can tune at a finer grain
  too (individual socket policies, individual device policies etc)

# The problem

The Linux kernel contains a large number of tunables; these
often take the form of sysctl(8) parameters, and are usually
introduced for situations where there is no one "right" answer
for a configuration choice.  The number of tunables available
is quite daunting.  On a 6.2 kernel we see

```
# sysctl --all 2>/dev/null|wc -l
1624
```

At the same time, individual systems get a lot less care
and adminstrator attention than they used to; phrases like
"cattle not pets" exemplify this.  Given the modern cloud
architectures used for most deployments, most systems never
have any human adminstrator interaction after initial
provisioning; in fact given the scale requirements, this
is often an explicit design goal - "no ssh'ing in!".

These two observations are not unrelated; in an earlier
era of fewer, larger systems, tuning by administrators was
more feasible.

These trends - system complexity combined with minimal
admin interaction suggest a rethink in terms of tunable
management.

A lot of lore accumulates around these tunables, and to help
clarify why we developed bpftune, we will use a straw-man
version of the approach taken with tunables:

"find the set of magic numbers that will work for the
 system forever"

This is obviously a caricature of how administrators
approach the problem, but it does highlight a critical
implicit assumption - that systems are static.

And that gets to the "BPF" in bpftune; BPF provides means
to carry out low-overhead observability of systems. So
not only can we observe the system and tune appropriately,
we can also observe the effect of that tuning and re-tune
if necessary.

# Key design principles

- Minimize overhead.  Use observability features sparingly; do not
  trace very high frequency events.
- Be explicit about policy changes providing both a "what" - what
  change was made - and a "why" - how does it help? syslog logging
  makes policy actions explicit with explanations
- Get out of the way of the administrator.  We can use BPF
  observability to see if the admin sets tunable values that we
  are auto-tuning; if they do, we need to get out of the way and
  disable auto-tuning of the related feature set.
- Don't replace tunables with more tunables! bpftune is designed to
  be zero configuration; there are no options, and we try to avoid
  magic numbers where possible.
- Use push-pull approaches. For example, with tcp buffer sizing,
  we often want to get out of the way of applications and bump
  up tcp sndbuf and rcvbuf, but at a certain point we run the
  risk of exhausting TCP memory.  We can however monitor if we
  are approaching TCP memory pressure and if so we can tune down
  values that we've tuned up.  In this way, we can let the system
  find a balance between providing resources and exhausting them.
  In some cases, we won't need to tune up values; they may be fine
  as they are. But in other cases limits block optimal performance,
  and if they are raised safely - with awareness of global memory
  limits - we can get out the way of improved performance.  Another
  concern is that increasing buffer size leads to latency - to
  handle that, we correlate buffer size changes and TCP smoothed
  round-trip time; if the correlation between these exceeds a
  threshould (0.7) we stop increasing buffer size.

# Concepts

The key components are

- tuners: each tuner manages tunables and handles events sent
  from BPF programs to userspace via the shared ring buffer.
  Each tuner has an associated set of tunables that it manages.

- events specify a
	- tuner id: which tuner the event is destined for
	- a scenario: what happened
	- an associated netns (if supported)
	- information about the event (IP address etc)

- the tuner then responds to the event with a strategy; increase
  or decrease a tunable value, etc.  Describing the event
  in the log is key; this allows an admin to understand what
  changed and why.

# Architecture

- bpftune is a daemon which manages a set of .so plugin tuners;
  each of these is a shared object that is loaded on start-up.
- tuners can be enabled or disabled; a tuner is automatically
  disabled if the admin changes associated tunables manually.
- tuners share a global BPF ring buffer which allows posting of
  events from BPF programs to userspace.  For example, if the
  sysctl tuner sees a systl being set, it posts an event.
- each tuner has an associated id (set when it is loaded),
  and events posted contain the tuner id.
- each tuner has a BPF component (built using a BPF skeleton)
  and a userspace component.  The latter has init(), fini()
  and event_handler() entrypoints.  When an event is
  received, the tuner id is used to identify the appropriate
  event handler and its event_handler() callback function is run.
- init, fini and event_handler functions are loaded from the
  tuner .so object.
- BPF components should include bpftune.bpf.h; it contains
  the common map definitions (ringbuf, etc) and shared variables
  such as learning rate and tuner ids that each tuner needs.

# Supported tuners

- congestion tuner: auto-tune choice of congestion control algorithm.
  See bpftune-cong (8).
- neighbour table tuner: auto-tune neighbour table sizes by growing
  tables when approaching full. See bpftune-neigh (8).
- sysctl tuner: monitor sysctl setting and if it collides with an
  auto-tuned sysctl value, disable the associated tuner.  See
  bpftune-sysctl (8).
- TCP buffer tuner: auto-tune max and initial buffer sizes.  See
  bpftune-tcp-buffer (8).
- netns tuner: notices addition and removal of network namespaces,
  which helps power namespace awareness for bpftune as a whole.
  Namespace awareness is important as we want to be able to auto-tune
  containers also.  See bpftune-netns (8).

# Code organization

Both core bpftune.c and individual tuners use the libbpftune library.
It handles logging, tuner init/fini, and BPF init/fini.

Each tuner shared object defines an init(), fini() and event_handler()
function. These respectively set up and clean up BPF and handle events
that originate from the BPF code.

# Tests

Tests are supplied for each tuner in the tests/ subdirectory.
"make tests" runs all the tests.  Tests use network namespaces
to simulate interactions with remote hosts. See ./TESTING.md
for more details.

# Does my system support bpftune?

Simply run "bpftune -S" to see:

```
$ bpftune -S
bpftune works fully
bpftune supports per-netns policy (via netns cookie)
```

Two aspects are important here

- does the system support fentry/fexit etc? If so full support
  is likely.
- does the system support network namespace cookies? If so
  per-network-namespace policy is supported.

# Demo

In one window, set tcp rmem max to a too-low value, and run bpftune
as a program logging to stdout/stderr (-s):

```
$ sudo sysctl -w net.ipv4.tcp_rmem="4096 131072 1310720"
net.ipv4.tcp_rmem = 4096 131072 1310720
$ sudo bpftune -s
```

In another window, wget a large file:

```
$ wget https://yum.oracle.com/ISOS/OracleLinux/OL8/u7/x86_64/OracleLinux-R8-U7-x86_64-dvd.iso
```

In the first window, we see bpftune tuning up rmem:

```
bpftune: bpftune works in legacy mode
bpftune: bpftune does not support per-netns policy (via netns cookie)
bpftune: Scenario 'need to increase TCP buffer size(s)' occurred for tunable 'net.ipv4.tcp_rmem' in global ns. Need to increase buffer size(s) to maximize throughput
bpftune: Due to need to increase max buffer size to maximize throughput change net.ipv4.tcp_rmem(min default max) from (4096 131072 1310720) -> (4096 131072 1638400)
```

This occurs multiple times, and on exit (Ctrl+C) we see
the summary of changes made:

```
bpftune: Summary: scenario 'need to increase TCP buffer size(s)' occurred 9 times for tunable 'net.ipv4.tcp_rmem' in global ns. Need to increase buffer size(s) to maximize throughput
bpftune: sysctl 'net.ipv4.tcp_rmem' changed from (4096 131072 1310720 ) -> (4096 131072 9765625 )
```

# For more info

See the docs/ subdirectory for manual pages covering bpftune
and assoiated tuners.
