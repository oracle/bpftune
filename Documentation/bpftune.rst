================
BPFTUNE
================
-------------------------------------------------------------------------------
tool for auto-tuning of Linux kernel parameters via BPF
-------------------------------------------------------------------------------

:Manual section: 8

SYNOPSIS
========

	**bpftune** [*OPTIONS*]

	*OPTIONS* := { { **-V** | **--version** } | { **-h** | **--help** }
	| { [**-P** | **--pages**] nr_pages} | { [**-c** | **--cgroup**] cgroup} |
        { [**-c** | **--cgroup** ] cgroup} | [{ **-d** | **--debug** }] }

DESCRIPTION
===========
	*bpftune* supports a set of "tuners" for sysctl parameters,
        congestion control algorithms etc to optimize performance.

        **bpftune** requires *CAP_BPF* and *CAP_TRACING* capabilities.

OPTIONS
=======
        -h, --help
                  Show help information
        -V, --version
                  Show version.
        -d, --debug
                  Show debug output.
        -c, --cgroup
                  Filter events for cgroup.
        -P, --pages
                  Specify number of pages used per-CPU for perf event
                  collection.  Default is 8.

EXAMPLES
========
