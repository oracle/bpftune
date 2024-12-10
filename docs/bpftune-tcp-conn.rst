================
BPFTUNE-TCP-CONN
================
--------------------------------------------------------------------------------
TCP connection bpftune plugin for auto-selection of congestion control algorithm
--------------------------------------------------------------------------------

:Manual section: 8


DESCRIPTION
===========
        The TCP connection algorithm tuner sets congestion control algorithm on
        TCP sockets.  Linux uses cubic by default, and it works well in a wide
        range of settings.

        However, in situations where losses are observed, it can underestimate 
        network capacity and as a result throughput can drop excessively.  In
        such cases, BBR is a good fit since it continuously estimates bottleneck
        bandwidth and attempts to fit the congestion algorithm to it.

        When we have limited information about a remote host - i.e. we have
        not had > REMOTE_HOST_MIN_INSTANCES connections involving it,
        the only auto-selection involved is to use BBR in cases where
        loss rates exceed 1/32 of the packet sent rate - in such scenarions,
        BBR performs much better than other congestion control algorithms.

        For cases where we connect multiple times we can try different
        algorithms to select the best.

        In selecting the appropriate congestion control algorithm, a reinforcement
        reinforcement learning-based method is used whereby we choose the
        congestion control algorithm that best fits the optimal bandwidth
        delay product (BDP)::

         BDP = BottleneckBandwidth * MinRoundTripTime

        The algorithm works as follows; BPF maintains a map of metrics keyed
        by remote IP address.  For each remote IP address, we track the
        minimum RTT observed across all TCP connections and the max bandwidth
        observed.  The former tells us - as closely as we can determine -
        what the true RTT of the link is.  The latter estimates the
        bandwidth limit of the link.  Knowing both of these allows us to
        determine the optimum operating state for a congestion control
        algorithm, where we feed the pipe enough to reach bandwidth limits but
        do not overwhelm it.

        Tracking both of these allows us to determine that optimum BDP, so any
        loss function we use for optimization should drive us towards congestion
        control algorithms that realize that optimal BDP by being as close
        as possible to the minimum RTT and as close as possible to the maximum
        packet delivery rate.  We cannot use raw BDP alone because it is
        composed of the delivery rate and the RTT, so instead the metric used
        is::

         (current_min_rtt - overall_min_rtt)*S/overall_min_rtt +
         (overall_max_delivery_rate - cong_alg_max_delivery_rate)*S/overall_max_delivery_rate

        Both denominators are scaled by a scaling factor S to ensure integer
        division yields nonzero values.  See ../src/tcp_conn_tuner.h for the
        metric compuatation.

        Note that while we use the current RTT for the connection, we use the
        maximum delivery rate observed for the congestion algorithm to compare
        with the overall maximum.  The reasoning here is that because the
        delivery rate fluctuates so much for different connections (depending
        on service type etc), it is too unstable to use it on a per-connection
        basis. RTT is less variable across connections so we can use the
        current RTT in metric calcuation.

        For a TCP connection with optimal BDP (minimum RTT + max delivery rate),
        the loss function yields 0.  Otherwise it yields a positive cost.  This
        is used to update the cost for that congestion control algorithm via
        the usual reinforcement learning algorithm, i.e.::

         cong_alg_cost = cong_alg_cost +
                         learning_rate*(curr_cost - cong_alg_cost)

        We use an epsilon-greedy approach, whereby the vast majority of the time
        the lowest-cost algorithm is used, but 5% of the time we randomly select
        an algorithm.  This ensures that if network conditions change we can
        adapt accordingly - without this, we can get stuck and never discover
        that another algorithm is doing better.

        How does this work in practice? To benchmark this we tested iperf3
        performance between network namespaces on the same system, with a 10%
        loss rate imposed via netem.  What we see is that bpftune converges
        to using BBR::

         IPAddress      CongAlg     Metric    Count   Greedy   MinRtt MaxRtDlvr
         192.168.168.1    cubic    2338876        9        9        3     1737
         192.168.168.1      bbr     923173       61       59        3    10024
         192.168.168.1     htcp    2318283        5        4        3      620
         192.168.168.1    dctcp    3506360        3        1        9      160

        Note that we selected the BBR congestion control algorithm 61 out of 78
        times and its associated cost was less than half of that of other
        algorithms.  This due to it exhibiting the maximum delivery rate and
        lowest RTT.
        
        iperf3 performance also improved as a result of selecting BBR, from a
        baseline of 58MBit/Sec (running the Linux default cubic algorithm) to
        490MBit/Sec running bpftune and auto-selecting BBR.

        So this approach appears to find the right answer and converge quickly
        under loss conditions; what about normal network conditions?
        
        We might worry that grounding our model in assumptions closely tied to
        BBR's design might unduly favour BBR in all circumstances; do we see
        this in practice outside of conditions where BBR is optimal?

        Thankfully no; we see a convergence to dctcp as the optimal congestion
        control algorithm; again it has the maximum delivery rate and minimum
        RTT::

         IPAddress      CongAlg     Metric    Count   Greedy   MinRtt MaxRtDlvr
         192.168.168.1    cubic    1710535        6        4        3     8951
         192.168.168.1      bbr    2309881        1        1        7      206
         192.168.168.1     htcp    3333333        3        3        3     8784
         192.168.168.1    dctcp    1466296       71       70        3     9377

        Note however that it is a close-run thing; the metric for cubic is close
        and it matches dctcp for minimum RTT (3us) and maximum delivery rate is
        close (9377 for dctcp, 8951 for cubic).

        References:

        BBR: Congestion-Based Congestion Control
        
        https://queue.acm.org/detail.cfm?id=3022184

