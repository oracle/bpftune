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

