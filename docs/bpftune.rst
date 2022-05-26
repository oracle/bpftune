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
	| { [**-s** | **--stderr** } | { [**-c** | **--cgroup**] cgroup} |
        { [**-l** | **--libdir** ] libdir} | [{ **-d** | **--debug** }] }

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
        -s, --stderr
                  Log to standard error instead of syslog.
        -l, --libdir
                  bptune plugin directory; defaults to
                  /usr/lib64
        

