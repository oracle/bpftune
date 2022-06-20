==================
BPFTUNE-TCP_BUFFER
==================
-------------------------------------------------------------------------------
bpftune plugin for auto-tuning TCP bufffer size
-------------------------------------------------------------------------------

:Manual section: 8


DESCRIPTION
===========
        TCP has a number of buffer size tunables; auto-tuning is provided for
        them.

        net.ipv4.tcp_wmem is a triple of min, default, max.  By instrumenting
        tcp_sndbuf_expand() we can see where expansion is close to hitting
        the max, and we can adjust it up appropriately to allow for additional
        buffer space.

        Similarly, for net.ipv4.tcp_rmem we monitor and increase the limit
        when expansion is close to hitting the limit.

        In both cases, we want to avoid the situation that increasing these
        limits leads to TCP memory exhaustion.  The BPF programs that detect
        approach to those limits will not request increases if we close to
        either TCP memory pressure or TCP memory exhaustion.

        net.ipv4.tcp_mem represents the min, pressure, max values for overall
        TCP memory use in pages.

        When in TCP memory pressure mode, we reclaim socket memory more
        aggressively until we fall below the tcp_mem min value.  We reclaim
        the forward-allocated memory for example.  On startup, TCP mem values
        are initialized as ~4.6%, 6.25% and 9.37% of nr_free_buffer_pages().
        nr_free_buffer_pages() counts the number of pages beyond the high
        watermark in ZONE_DMA and ZONE_NORMAL.

        As with watermark scaling, if we enter TCP memory pressure, bpftune
        will scale up min/pressure/max as required.  If we enter memory
        exhaustion it will scale up max since systems are often unstable
        in memory exhaustion mode.
