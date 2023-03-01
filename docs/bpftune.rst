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
        { [**-S** | **--support** ]}

DESCRIPTION
===========
	*bpftune* supports a set of "tuners" for sysctl parameters,
        congestion control algorithms etc to optimize performance
        and avoid imposing unnecessary limits on tunables.

        **bpftune** requires *CAP_BPF* and *CAP_TRACING* capabilities,
        or *CAP_SYS_ADMIN* on older systemes.  It is run via a systemd
        service, but can also be run standalone if required.  To probe
        if your system supports the BPF features required for bpftune,
        run "bpftune -S".  Basic bptune support requires BPF ring buffer,
        BPF hashmap and BPF sock ops and k[ret]probe support.  On more
        modern systems, BPF tracing programs and BPF iterators are used.
        Individual tuners support legacy mode operation where possible.
        In order to support per-network-namespace tuning, netns cookie
        support is required; without that, only global tuning is
        supported.

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
        -S, --support
                  Scan system to see what level of bpftune support is present.
        -l, --libdir
                  bptune plugin directory; defaults to
                  /usr/lib64
        

