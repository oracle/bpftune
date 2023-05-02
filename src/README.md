# Adding new tuners

1. Create 
   - tuner_name_tuner.bpf.c containing BPF programs.  It must
```
#include "bpftune.bpf.h"
```
   - tuner_name_tuner.c containing init, fini and event handler.  It must
```
#include <libbpftune.h>
```

   - tuner_name_tuner.h containing common definitions for bpf/userspace;
     examples of these are enumerated values covering tunable and
     scenario ids (see tcp_buffer_tuner.h for examples).


Ensure that LOG_INFO events are logged when tunable updates are
made; this allows the admin to understand what changes were made
and motivations for doing so.  bpftuner_tunable_sysctl_write() can be
used as a wrapper for sysctl changes which takes care of logging
(additional reasons can be supplied) and bpftuner_tunable_update()
can be used for other cases (see cong_tuner.c for example).

2. Add tuner_name to TUNERS in Makefile so it will be built.

3. Add bpftune-tuner-name.rst to docs and add tuner-name to TUNERS in
   Makefile there also.

# Example

neigh_table_tuner.bpf.c monitors neighbour table updates, and when the
neighbour table is approaching garbage collection limits, those
limits are raised.  It consists of

- src/neigh_table_tuner.bpf.c
- src/neigh_table_tuner.c
- src/neigh_table_tuner.h
- docs/bpftune-neigh.rst

We see that ringbuf messages are sent from the BPF program when the
neighbour table approaches being full, and these are handled in the
event_handler function.
