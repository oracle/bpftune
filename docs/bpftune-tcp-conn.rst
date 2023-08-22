================
BPFTUNE-TCP-CONG
================
--------------------------------------------------------------------------------
TCP connection bpftune plugin for auto-selection of congestion control algorithm
--------------------------------------------------------------------------------

:Manual section: 8


DESCRIPTION
===========
        The TCP connection algorithm tuner sets congestion control algorithm on
        TCP sockets.  Linux uses cubic by default, and it works well in a wide
        range of settings, however it can under-perform in lossy networks.

        If we observe retransmits to a remote host, we anticipate more drops
        to that host may occur; these can lead the default congestion algorithm
        (cubic) to assume such drops imply congestion, and we end up with a
        pessimistic congestion algorithm that greatly underperforms with respect
        to potential bandwitdh.

        With the above in mind, we count retransmission events by remote host,
        if we see >1% socket retransmits to the host in the last hour, we use
        BBR as the congestion algorithm instead, anticipating these sorts of
        losses may result in us under-estimating bandwidth potential.

        Note that BBR retransmits more than other algorithms, so if we switch
        to it we will likely see more retransmits, and potentially stay with
        it for a length of time until such losses shake out.

        We use the tracepoint tcp_retransmit_skb to count retransmits by
        remote host, and a BPF iterator program to set congestion control
        algorithm, since it allows us to update congestion control for
        existing connections such as an iSCSI connection, which may exist
        prior to bpftune starting.  For legacy bpftune - where iterators
        are not present - we fall back to using tcpbpf, but at a price;
        only connections that are created after bpftune starts are supported
        since we need to enable the retransmit sock op.

        Reference: https://blog.apnic.net/2020/01/10/when-to-use-and-not-use-bbr

