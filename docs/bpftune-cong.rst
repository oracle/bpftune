================
BPFTUNE-CONG
================
-------------------------------------------------------------------------------
Congestion bpftune plugin for auto-selection of congestion control algorithm
-------------------------------------------------------------------------------

:Manual section: 8


DESCRIPTION
===========
        The congestion algorithm tuner sets congestion control algorithm on
        TCP sockets.  Linux uses cubic by default, and it works well in a wide
        range of settings, however it can under-perform in lossy networks.

        If we observe retransmits to a remote host, we anticipate that more drops
        to that host may occur; these can lead the default congestion algorithm
        (cubic) to assume such drops imply congestion, and we end up with a
        pessimistic congestion algorithm that greatly underperforms with respect
        to potential bandwitdh.

        With the above in mind, we count retransmission events by remote host,
        and if we see > 100 in the last hour, we utilize BBR as the congestion
        algorithm instead, anticipating these sorts of losses may result in
        us under-estimating bandwitdh potential.

        Note that BBR retransmits more than other algorithms, so if we switch
        to it we will likely see more retransmits, and potentially stay with
        it for a length of time until such losses shake out.

        We use the tracepoint tcp_retransmit_skb to count retransmits by
        remote host, and a TCP-BPF sockops program to set congestion control
        algorithm on connect/accept.

        Reference: https://blog.apnic.net/2020/01/10/when-to-use-and-not-use-bbr/

