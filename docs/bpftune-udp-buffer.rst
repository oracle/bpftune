==================
BPFTUNE-UDP-BUFFER
==================
-------------------------------------------------------------------------------
UDP buffer bpftune plugin for managing UDP buffer sizes, memory limits
-------------------------------------------------------------------------------

:Manual section: 8


DESCRIPTION
===========

        For UDP - like TCP - a triple of min, pressure, max
        represents UDP memory limits and is specified in

          net.ipv4.udp_mem

        If receive fails with -ENOBUFS this indicates memory
        limits are being reached; we adaptively increase pressure and
        max to ensure that memory exhaustion does not occur (as long
        as we do not approach real memory exhaustion).  As memory
        exhaustion is approached and we can no longer increase
        overall memory limits, reduce net.core.rmem* values to limit
        socket memory overheads.

        For UDP receive buffer memory, bump net.core.rmem_max if
        a socket experiences receive buffer drops within range of
        the rmem_max_value.  Similarly bump rmem_default if sockets are
        within range of it and do not have a locked (via setsockopt)
        value.

        Tunables:

        - net.ipv4.udp_mem: min, pressure, max UDP memory
        - net.core.rmem_max: max rcvbuf size specifiable via setsockopt()
        - net.core.rmem_default: default rcvbuf size where none was set
