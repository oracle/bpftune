==================
BPFTUNE-NETNS
==================
-------------------------------------------------------------------------------
bpftune plugin for network namespace awareness
-------------------------------------------------------------------------------

:Manual section: 8


DESCRIPTION
===========
        bpftune needs to be namespace-aware; when it receives events, they
        are tied to a specific netns cookie, and if we see an event in that
        netns we want to be able to auto-tune within it and not in the global
        network namespace.

        On startup, the netns tuner iterates over the various sources of
        netns info to collate a list of network namespaces, and supplements
        this by watching for addition and removal of network namespaces
        via BPF observability.  Using this info, we can then maintain tuner
        state on a per-namespace basis.
