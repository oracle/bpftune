# bpftune tests

Tests aim to exercise the behaviour of tuners and compare baseline/test
to assess performance improvements or overheads.  Per-tuner tests
cover the various tuners, along with general logging tests.

Tests should cover both normal and legacy mode where appropriate.

Tests operate locally using network namespaces and veth pairs
to generate traffic.

# General tests

## Logging tests

Verify logging works with syslog, stdout/stderr.

# Per-tuner tests

## sysctl tests

Verify that calling sysctl with a tuner-managed value switches off
the tuner in question (getting out of the way of the admin).

## neigh_table tests (gc_thresh[2])

Ensure that the neigh table tuner notices the ARP/IPv6 neighbour
table filling up and expands it via netlink request.

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
