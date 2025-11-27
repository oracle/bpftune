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
        if 1/32 of current backlog size in the last minute is dropped
        (drops occur when the backlog limit is reached).  In addition,
        backlog drops can avoid small flows; the tunable
        net.core.flow_limit_cpu_bitmap can be used to set this on a
        per-cpu basis; when we see sufficient drops on a CPU, the
        appropriate bit is set in the CPU bitmask to prioritize small
        flows for drop avoidance.

        When NAPI polls to handle multiple packets, the number of packets
        is limited by net.core.netdev_budget while the time is limited
        by net.core.netdev_budget_usecs.  If we hit the limit of number
        of packets processed without using the usecs budget the time_squeezed
        softnet stat is bumped; if we see increases in time_squeezed, bump
        netdev_budget/netdev_budget_usecs.

        However, we want to limit such increases if they lead to longer
        task scheduling wait times, so we monitor the ratio of time tasks
        spend waiting versus running across all processors, and if we see
        correlations between increases in netdev budget and wait/run ratio
        increases, netdev budget is tuned down.

        Tunables:

        - net.core.netdev_max_backlog: maximum per-cpu backlog queue length;
          default 1024.
        - net.core.flow_limit_cpu_bitmap: avoid drops for small flows on
          a per-cpu basis; default 0.
        - net.core.netdev_budget: maximum number of packets processed in
          a NAPI cycle
        - net.core.netdev_budget_usecs: maximum amount of time in microseconds
          for a NAPI cycle
