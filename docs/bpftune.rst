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
        { [**-r** | **--learning_rate** ] learning_rate}
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
                  bptune extra plugin directory; defaults to
                  /usr/local/lib64/bpftune . Both /usr/lib64/bpftune and
                  /usr/local/lib64/bpftune can be used to install plugin tuners;
                  if an alternative to /usr/local/lib64/bpftune is wanted,
                  it must be specified via library path.

        -r, --learning_rate

                  Specify learning rate; supported values range from

                        0: tunables are changed by/within 1.0625 % of limit

                        1: tunables are changed by/within 3.125% of limit

                        2: tunables are changed by/within 6.25% of limit

                        3: tunables are changed by/within 12.5% of limit

                        4: tunables are changed by/within 25% of limit

                So for example at rate 4, if we are within 25% of a limit,
                the limit is increased by 25%.  Default learning rate is 4.
                Lower values are more conservative as they change only when
                closer to limits, but may require more frequent changes as
                a result

