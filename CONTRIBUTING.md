# Contributing to bpftune

We welcome your contributions! There are multiple ways to contribute.

## Opening issues

For bugs or enhancement requests, please file a GitHub issue unless it is security related. When filing a bug remember that the better written the bug is, the more likely it is to be fixed. If you think you have found a security vulnerability, do not raise a GitHub issue and follow the instructions in our security policy documented in SECURITY.md.

## Contributing code

We welcome your code contributions. Before submitting code via a pull request, you will need to have signed the Oracle Contributor Agreement (OCA) at

https://oca.opensource.oracle.com/

...and your commits need to include the following line using the name and e-mail address you used to sign the OCA:

Signed-off-by: Your Name <you@example.org>

This can be automatically added to pull requests by committing with --sign-off or -s, e.g.

git commit --signoff

Only pull requests from committers that can be verified as having signed the OCA can be accepted.

## Pull request process

-   Ensure there is an issue created to track and discuss the fix or enhancement you intend to submit.
-    Fork this repository.
-    Create a branch in your fork to implement the changes. We recommend using the issue number as part of your branch name, e.g. 1234-fixes.
-    Ensure that any documentation is updated with the changes that are required by your change.
-    Ensure that any samples are updated if the base image has been changed.
-    Ensure that all changes comply to project coding conventions as documented here
-    Ensure that there is at least one test that would fail without the fix and passes post fix.
-    Submit the pull request. Do not leave the pull request blank. Explain exactly what your changes are meant to do and provide simple steps on how to validate your changes. Ensure that you reference the issue you created as well.
-    We will assign the pull request for review before it is submitted internally and the PR is closed.

## Code of conduct

Follow the Golden Rule. If you would like more specific guidelines, see the Contributor Covenant Code of Conduct at

https://www.contributor-covenant.org/version/1/4/code-of-conduct/

## Technical guide to contribution

The architecture used is

- a core daemon, src/bpftune.c
- a library, libbpftune which consists of functions used by core daemon
  and tuners, such as logging, BPF setup etc, src/libbpftune.c; and
- a set of plug-in shared object tuners which are loaded when bpftune
  starts; sysctl_tuner.[bpf.]c, neigh_table_tuner.[bpf.]c

## Adding a tuner

Tuners are added as plug-in .so objects built as tuner_name.c, and each tuner
has a BPF program named tuner_name.bpf.c.  To add a new tuner, add these
files and simply add tuner_name to TUNERS in src/Makefile.

Tuners can also be built outside of bpftune; see the sample_tuner/
subdirectory for a simple example and sample Makefile.

## BPF component (tuner_name.bpf.c)

The BPF code must

```
#include <bpftune/bpftune.bpf.h>
```

...since that header includes all relevant definitions and includes
the definition of the BPF ring buffer that tuners use to communicate
with userspace:

```
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 64 * 1024);
} ringbuf_map SEC(".maps");

```

On startup BPF reuses the map fd across all BPF objects; in other
words they all share this ring buffer to communication with bpftune.

It also include a global variable:

```
unsigned int tuner_id;
```

When bpftune loads the tuner, it assigns this tuner id to the
BPF object.  This allows us to send events from the BPF programs
in that object which identify the tuner source.  The tuner id
in the ringbuf event allows us to call the event handler callback
in the appropriate tuner.

## Legacy kernel handling

Here "legacy" implies lack of fentry, fexit, tp_btf and BPF
iter programs.  BPF ringbuf is assumed.  For each tuner, we
build a version with BPFTUNE_LEGACY defined.  This corresponds
to around v5.6 of the kernel, but for Oracle Linux it corresponds
to UEK6U3 (v5.4-based) since it includes backports of ringbuf
support.

To support per-namespace policies, support for netns cookies
is required, and this is orthogonal to legacy/full support.
So legacy support does not necessarily imply no netns cookie
support (currently the aarch64 platform is legacy as it
does not support BPF trampoline).

To test what level of bpftune support (if any) is provided
on your system, run "bpftune -S"; it provides feedback like this:

```
$ bpftune -S
bpftune works fully
bpftune supports per-netns policy (via netns cookie)
```

If you add new BPF features, check the probe program
probe.bpf.c; it may need updating.

If the BPF program just consists of fentry programs, simply use
the BPF_FENTRY() wrapper - it will convert to kprobes
for the legacy version.  For other cases see these examples:

- using raw_tracepoint instead of tp_btf, see sysctl_tuner.bpf.c
- using kprobe+kretprobe instead of fexit access to calling args,
  see neigh_table_tuner.bpf.c
- using kretprobe instead of fexit (where no access to calling
  args is needed), see tcp_buffer_tuner.bpf.c

Also use BPF_CORE_READ() rather than direct dereference where
possible as that will work for both kprobe and fentry for example.

For maps, use the BPF_MAP_DEF() definitions which will invoke
the older libbpf map definition if using an older libbpf.

## Userspace component - tuner_name.c

It should #include <libbpftune.h>, and must consist of the following
functions

```
int init(struct bpftuner *tuner, int ringbuf_map_fd);

void fini(struct bpftuner *tuner);

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   void *ctx);
```

The init function is called on tuner initialization, and is passed
the fd referring to the ring buffer map which is shared across tuners.
The init() function should do any additional BPF attachment not covered
by SEC() names (such as attaching to a cgroup), and initialize any
global variables.  All tuners should call

```
bpftuner_bpf_init(tuner_name, ringbuf_map_fd);
```

...since this loads the associated BPF skeleton.  In addition, if
the tuner auto-tunes any sysctls, an array of "struct bpftunable_desc":

```
struct bpftunable_desc {
        unsigned int id;
        enum bpftunable_type type;
        const char *name;
        __u8 num_values;
};
```

...should be added naming them, and

```
	bpftuner_tunables_init(tuner, num_descs, descs);
```

...should be called.  This informs bpftune so that if the sysctl
tuner sees a modification of a sysctl that should be auto-tuned,
we can disable the associated tuner.  So for example if the
neigh_table_tuner manages sysctl "net.ipv4.neigh.default.gc_thresh3",
so if the sysctl BPF program sees it being modified, we can disable
the associated neigh_table_tuner.

If any data structures are common across userspace and BPF, they
should be added to a tuner_name.h file which both include.

Remember to include both the skel.h and skel.legacy.h files.

## Events

When an event the user-space component needs to know about occurs,
a ringbuf event should be sent.  The event structure is:

```
struct bpftune_event {
        unsigned int tuner_id;
        unsigned int scenario_id;
        union {
                struct bpftunable_update update[BPFTUNE_MAX_TUNABLES];
                char str[BPFTUNE_MAX_NAME];
                __u8 raw_data[BPFTUNE_MAX_DATA];
        };
};
```

The scenario refers to the event type (seen packet loss to remote
system), and the payload can be a string, a raw data structure etc.

## Overhead

When choosing BPF events to instrument, please try to avoid very
high-frequency events.  Try to use fentry instead of kprobe,
tp_btf instead of tracepoint etc as these perform much better.

To test overhead of your tuner, there are iperf3/qperf tests
that compare baseline performance versus performance when
bpftune runs.  For example:

```
$ cd test
$ TUNER=tcp_buffer_tuner.so sh iperf3_test.sh
...
$ TUNER=tcp_buffer_tuner.so sh qperf_test.sh
...
```

Replace TUNER value with the name of the tuner you want to assess.

## Tests

Tests are mandatory for tuners; in the test directory you can see
lots of examples.  The test framework uses network namespaces to
support iperf3 runs within the same system.  Tests should validate
tuning behaviour works, and ideally improves performance.  In
addition, ensure to test both legacy (where legacy mode is forced
via "-L") and non-legacy modes.  See ./TESTING.md for more details
on tests.
