===============
BPFTUNE-IP-FRAG
===============
-------------------------------------------------------------------------------
IP fragmentation bpftune plugin for managing fragment reassembly memory limits
-------------------------------------------------------------------------------

:Manual section: 8


DESCRIPTION
===========

        For IPv[46] fragmentation reassembly, memory is capped at

          net.ipv[46].ip[6]frag_high_thresh

        Fragmentation reassembly can fail if this value is set too low;
        monitor for fragmentation reassembly and bump value if needed.

        Avoid bumping it if assembly faiures constitute too high a
        proportion of reassembly events; this may signify a DoS.

        Tunables:

        - net.ipv4.ipfrag_high_thresh: number of bytes devoted to
          IPv4 fragmentation reassembly; default 4MB
        - net.ipv6.ip6frag_high_thresh: number of bytes devoted to
          IPv6 fragmentation reassembly; default 4MB
