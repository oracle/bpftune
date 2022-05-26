# bpftune - BPF driven auto-tuning

bpftune aims to provide lightweight, always-on auto-tuning of system
behaviour.  The key benefit it provides are

- by using BPF observability features, we can continuously monitor
  and adjust system behaviour
- because we can observe system behaviour at a fine grain (rather
  than using coarse system-wide stats), we can tune at a finer grain
  too (individual socket policies, individual device policies etc)

# Key design principles

- Minimize overhead.  Use observability features sparingly; do not
  trace very high frequency events.
- Be explicit about policy changes providing both a "what" - what
  change was made - and a "why" - how does it help? syslog logging
  makes policy actions explicit with explanations
- Get out of the way of the administrator.  We can use BPF
  observability to see if the admin sets tunable values that we
  are auto-tuning; if they do, we need to get out of the way and
  disable auto-tuning of the related feature set.
- Don't replace tunables with more tunables! bpftune is designed to
  be zero configuration; there are no options, and we try to avoid
  magic numbers where possible.  Where a threshold value is used,
  reinforcement learning techniques will be applied to it to allow
  it to float to the optimal value (TBD).

# Architecture

- bpftune is a daemon which manages a set of .so plugin tuners;
  each of these is a shared object that is loaded on start-up.
- tuners can be enabled or disabled; a tuner is automatically
  disabled if the admin changes associated tunables manually.
- tuners share a global BPF ring buffer which allows posting of
  events from BPF programs to userspace.  For example, if the
  sysctl tuner sees a systl being set, it posts an event.
- each tuner has an associated id (set when it is loaded),
  and events posted contain the tuner id.
- each tuner has a BPF component (built using a BPF skeleton)
  and a userspace component.  The latter has init(), fini()
  and event_handler() entrypoints.  When an event is
  received, the tuner id is used to identify the appropriate
  event handler and its event_handler() callback function is run.
- init, fini and event_handler functions are loaded from the
  tuner .so object.

# Supported tuners

- congestion tuner: auto-tune choice of congestion control algorithm.
  See bpftune-cong (8).
- sysctl tuner: monitor sysctl setting and if it collides with an
  auto-tuned sysctl value, disable the associated tuner.  See
  bpftune-sysctl (8).
- TCP buffer tuner: auto-tune max and initial buffer sizes. TBD

# Code organization

Both core bpftune.c and individual tuners use the libbpftune library.
It handles logging, tuner init/fini, and BPF init/fini.

Each tuner defines an init(), fini() and event_handler() function.

# Tests

Tests are supplied for each tuner in the tests/ subdirectory.
"make tests" runs all the tests.  Tests us network namespaces
to simulate interactions with remote hosts.

# For more info

See the docs/ subdirectory for manual pages covering bpftune
and assoiated tuners.
