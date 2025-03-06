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
        buffer space.  This will not be done for cases where memory is low,
        and if we approach memory exhaustion and cannot increase overall
        tcp memory exhaustion limit (see below), the wmem max value will
        be decreased.

        Similarly, for net.ipv4.tcp_rmem, we monitor and increase the limit
        when expansion is close to hitting the limit, with the same exceptions
        applying as above.

        In both cases, we want to avoid the situation that increasing these
        limits leads to TCP memory exhaustion.  The BPF programs that detect
        approach to those limits will not request increases if we are close to
        either TCP memory pressure or TCP memory exhaustion; in fact wmem/rmem
        will be reduced as part of an effort to decrease TCP memory usage
        if TCP memory exhaustion is approached and that value cannot be
        raised.

        Similarly we want to avoid the other negative consequence of allocating
        too many buffers - latencies due to waiting to send/receive with longer
        queues.  A blocking sender app that sends a lot of traffic will
        see less ENOBUFS errors and silently dropped packets, while a
        non-blocking app will see less EAGAIN messages.  In those cases,
        facilitating sending will always be quicker and critically lead to
        a reduction in overall numbers of system calls.  Similarly, a latency-
        sensitive app will likely prefer sends to succeed than have to retry.
        From the receive side, we have to consider the effect of a larger
        receive queue (and receive window).  By default, we advertise
        half of the recieve buffer size as receive window; this allows for
        apps to use the rest as buffer space.  This ratio of app space to
        window size can be adjusted via the sysctl tcp_adv_win_scale, which
        defaults to 1.  A negative value means the receive window is
        scaled by the factor specified; so -2 means 1/4 of recieve buffer size
        is available for TCP window. A positive value of 2 means that
        3/4 of receive buffer size is available for the TCP window.

        So for slow apps, a negative value might make sense.

        In combination with changes to net.ipv4.tcp_rmem, we ensure that
        net.ipv4.tcp_moderate_rcvbuf is set to auto-tune receive buffer sizes
        when changes to rcvbuf size are made.

        net.ipv4.tcp_mem represents the min, pressure, max values for overall
        TCP memory use in pages.

        When in TCP memory pressure mode, we reclaim socket memory more
        aggressively until we fall below the tcp_mem min value.  We reclaim
        the forward-allocated memory for example.  On startup, TCP mem values
        are initialized as ~4.6%, 6.25% and 9.37% of nr_free_buffer_pages().
        nr_free_buffer_pages() counts the number of pages beyond the high
        watermark in ZONE_DMA and ZONE_NORMAL.

        As with watermark scaling, if we enter TCP memory pressure, bpftune
        will scale up min/pressure/max as needed, with limits of 6%/9% on min,
        pressure and 25% of available memory for the memory exhaustion max.
        We attempt to avoid memory exhaustion where possible, but if we
        hit the limit of memory exhaustion and cannot increase it further,
        wmem and rmem max values are decreased to reduce per-socket overhead.

        When near memory exhaustion, per-path TCP metrics are disabled by setting
        net.ipv4.tcp_no_metrics_save and net.ipv4.tcp_no_ssthresh_metrics_save to
        1; this limits memory overheads associated with allocating per-path metrics.
