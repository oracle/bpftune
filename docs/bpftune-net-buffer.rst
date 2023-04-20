==================
BPFTUNE-NET-BUFFER
==================
-------------------------------------------------------------------------------
Networking buffer bpftune plugin for managing net core buffers
-------------------------------------------------------------------------------

:Manual section: 8


DESCRIPTION
===========
        A backlog queue is used to buffer incoming traffic and its
        length is controlled by net.core.netdev_max_backlog.  On
        fast connections (10Gb/s or higher) the default backlog length
        of 1024 can be insufficient; here the backlog length is increased
        if 1/16 of current backlog size in the last minute is dropped
        (drops occur when the backlog limit is reached).  In addition,
        backlog drops can avoid small flows; the tunable
        net.core.flow_limit_cpu_bitmap can be used to set this on a
        per-cpu basis; when we see sufficient drops on a CPU, the
        appropriate bit is set in the CPU bitmask to prioritize small
        flows for drop avoidance.

        Tunables:

        - net.core.netdev_max_backlog: maximum per-cpu backlog queue length;
          default 1024.
        - net.core.flow_limit_cpu_bitmap: avoid drops for small flows on
          a per-cpu basis; default 0.
