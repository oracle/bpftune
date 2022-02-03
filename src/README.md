# Adding new tuners

1. Create a description/<param> dir which describes the tuning carried out.
   It should describe
	1. the relevant tunable(s) in
		- description/<param>/tunable
	2. the set of scenarios that lead to tunable change
		- description/<param>/scenario-<name>
	3. the change made
	4. expected effects with/without tuning
		- description/<param>/untuned-effects-<name>
		- description/<param>/tuned-effects-<name>
2. Add a new param to enumerated enum bpftuners in bpftune.h using
	enum bpftuner {
		BPFTUNER(foo),
		BPFTUNER(bar),
		...
	};

3. Create a BPF object to record events of interest and assess when
   tuning is needed; it should be named <param>tune.bpf.c

4. BPF program should monitor events of interest to tuner, and send a
   perf event when a tuning change is required.

5. This perf event will be caught by bpftune daemon, and
	1. the tuning will be carried out
	2. the description of the tuning will be logged to syslog.

# Example

neigh-table-tune.bpf.c monitors neighbour table updates, and when the
neighbour table is approaching garbage collection limits, those
limits are raised.
 
description/neigh_table/tunable

..describes sysctl.net.ipv[46].gc_thresh[123]

description/neigh_table/scenario_filling_up

..describes the problem; the neigh table is filling up and
garbage collection isn't dumping old entries fast enough

description/neigh_table/untuned_effects_filling_up

..describes the fact that if the neigh table fills up new
entries can't be added and communication with the associated
hosts is impossible.

description/neigh_table/tuned_effects_filling_up

...describes the fact that we have more space and can
accommodate more entries.

bpftune will listen for perf events and it will get change event
requests from BPF programs; each change request contains

- a tuner id (neigh_table)
- a scenario id (filling_up)
- old value(s) (gc_thresh[1-3])
- new value(s) (gc_thresh[1-3])

bpftune will then
 - update the tunable
 - log a message desribing the change made (old->new)
   using the scenario description, untuned/tuned effects
   and rollback instructions.

