================
BPFTUNE-NEIGH
================
-------------------------------------------------------------------------------
Neighbor table bpftune plugin for managing neighbor table sizing
-------------------------------------------------------------------------------

:Manual section: 8


DESCRIPTION
===========
        The neighbor table contains layer 3 -> layer 2 mappings and
        reachability information on remote systems.  We look up via
        layer 3 address (IP address) to find layer 2 address associated.

        The table is populated with both static and garbage-collected values.
        When adding entries we can specify that they should be PERMANENT,
        in which case they are not (exempt from) garbage-collected.

        Periodic garbage collection happens for non-permanent failed or
        expired entries; it is run immediately if we cannot alloc a
        new neighbor table entry.

        There are a few pathologies we want to avoid here, principally

        - neighbor table full: if we see /var/log/messages
          "Neighbour table overflow." we have run out of space.
          Can occur if garbage collection isn't run quickly enough
          or we are full with entries not subject to garbage collection.

          In former case, auto-tune by reducing gc_thresh2 since this
          will make GC run more quickly.  Algorithm used is to reduce
          gc_thresh2 by 5% of the value between gc_thresh1 (below which
          no GC happens) and gc_thresh2 (after which GC kicks in
          after 5 sec). By doing this, we ensure garbage collection
          happens well before table becomes full.

          In the latter case, with a large number (75% or more) of
          exempt from GC entries, garbage collection won't help
          so we have to increase gc_thresh3. This is done on a per-table
          basis via netlink, so the resource costs are limitied rather
          than setting a system-wide tunable.

          Note that by increasing gc_thresh3 only, garbage collection gets
          gets more time to run from table sized gc_thresh2 until we
          reach gc_thresh3.

        - neighbor table thrashing: too-aggressive GC eviction might lead
          to excessive overhead in re-estabilishing L3->L2 reachability
          information.

        Tunables:

        - gc_interval: how often garbage collection should happen;
          default 30 seconds.
        - gc_stale_time: how often to check for stale entries.
          If neighbor goes stale, it is resolved again
          before sending data; defaults to 60sec
        - base_reachable_time_ms: how long neighbor entry is considered
          reachable for; defaults to 30sec.
        - gc_thresh1: with a table size below this value, no GC
          happens; default 128
        - gc_thresh2: soft max of entries in table; wait 5 secs if
          we exceed this value to do GC; default 512.
        - gc_thresh3: hard max for table size, GC will run if more
          entries than this exist, default 1024.

        Note: to set table size we need to use the equivalent of
        "ip ntable"; i.e.
        "ip ntable change name arp_cache dev eth0 thresh3 1024"
        (this is done directly in bpftune via netlink)

        ...since defaults just give initial values for new device.
        So when adapting table size when approaching full, we
        need to use that approach.

        Contrast this approach with simply choosing a large
        net.ipv4.neigh.gc_thresh3. If thresh2 and thresh3
        are far apart, we may over-garbage collect, whereas
        if they are close we may end up keeping around too
        many entries.  In either case, we're mistuned because
        we've had to choose coarse-grained defaults rather
        than adapting on a per-table basis as the need arises.
