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
        if 1/8 of traffic in the last minute is dropped (drops occur when
        the backlog limit is reached).

        Tunables:

        - net.core.netdev_max_backlog: maximum per-cpu backlog queue length;
          default 1024.
