# bpftune tests

Tests aim to exercise the behaviour of tuners and compare baseline/test
to assess performance improvements or overheads.  Per-tuner tests
cover the various tuners, along with general logging tests.

Tests should cover both normal and legacy mode where appropriate.

Tests operate locally using network namespaces and veth pairs
to generate traffic.

Network namespace awareness requires support for netns cookies,
which is not available in 5.4 kernels.  In such cases, tests
requiring netns cookie support are skipped automatically.

# Configuration

Install packages used to facilitate testing:

```
$ sudo dnf install iperf3 qperf proxyt kernel-uek-modules-extra clang llvm bpftool libbpf-devel libcap-devel 
$ sudo dnf module install container-tools:ol8
```

iperf3, qperf are needed for perf testing; kernel-uek-modules-extra is
needed for sch-netem; proxyt is used by podman to connect to the container
registry; may not be needed depending on the network connectivity/podman
config used.  If podman is not installed or registry reachable, tests
will be skipped.

The latter 5 packages are needed to build the sample tuner.

podman is optional and is used to verify container support in bpftune.

Package names may differ for different distros.

# General tests

## Support test

Ensure "bpftune -S" shows right support level (none/legacy/full)
for system, and shows if per-netns policy is supported (via
netns cookie).

## Logging tests

Verify logging works with syslog, stdout/stderr.

## Service test

Verify enabling/disabling bpftune via service works and bpftune
is running/logging.

## Capabilities test

Ensure capabilities are dropped after initialization using
getpcaps(8).

## Inotify tests

Verify that removing or adding a tuner is noticed and the tuner
is cleaned up/initialized appropriately.

## Sample tests

We provide a bare-bones sample tuner in sample_tuner/ ; it is
an example of a user-provided tuner that is built using
bpftune-devel and is installed in /usr/local/lib64/bpftune.
The test verifies that
 - installing it after bpftune has started triggers inotify
   events to load the tuner
 - events are successfully triggered for the tuner once
   loaded
 - it is unloaded on remove from the directory

# Per-tuner tests

## sysctl tests

Verify that calling sysctl with a tuner-managed value switches off
the tuner in question (getting out of the way of the admin).
Also verify that when a tunable is modified in a network namespace,
only the network namespace tuning is switched off.

## neigh_table tests (gc_thresh[2])

Ensure that the neigh table tuner notices the ARP/IPv6 neighbour
table filling up and expands it via netlink request.

## neigh_table_shrink tests (gc_thresh[2])

Ensure that the neigh table shrink tuner notices an expanded ARP/IPv6
neighbour table getting emptied and shrinks it via netlink request.

## mem_pressure tests (tcp_mem[1])

With artificially low memory pressure value, generate traffic
and ensure mem pressure (tcp_mem[1]) is bumped up.

## mem exhaustion tests (tcp_mem[2])

With artificially low memory exhaustion value, generate traffic
and ensure mem exhaustion value (tcp_mem[2]) is bumped up.

## rmem tests (tcp_rmem[2])

check rmem max is increased when limit reached for receive buffer
size for global and non-global netns (where netns support is
present).  Use an artifically low max to trigger bpftune tuning.

## wmem tests (tcp_wmem[2])

check wmem max is increased when limit reached for send buffer
size for global and non-global netns (where netns support is
present).  Use an artificially low max to trigger buftune tuning.

## cong tests

Use tc to generate lossy connection and ensure that BBR is
used as congestion control algorithm when loss rate exceeds 1%.

# Performance tests

## iperf3 tests

Measure baseline versus test (bpftune running) throughput.

## qperf tests

Measure baseline versus test (bpftune running) throughput/latency.

## TBD yum install

Measure baseline versus test for package download.

## TBD large file wget

Measure baseline versus test for large file download.
