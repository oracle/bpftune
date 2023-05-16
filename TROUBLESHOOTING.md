# Troubleshooting Guide

# Checking bpftune support

The first step is to determine if bpftune is supported on the system; this
can be done via 

```
$ sudo bpftune -S
bpftune: bpftune works in legacy mode
bpftune: bpftune supports per-netns policy (via netns cookie)
```

legacy mode will be used if there is no fentry/fexit, but it requires
at a minimum raw tracepoint support, cgroup/sysctl BPF program support
and BPF ring buffer support.  So if any of these are missing, bpftune
is not supported.  If you see a "not supported" error, it is worth
adding debug flags to dig deeper.  For example, in this case,
the libbpf used cannot read vmlinux BTF and as a result full bpftune
support is not available:

```
$ sudo bpftune -dS

bpftune: set caps (count 1)
bpftune: set caps (count 2)
bpftune: drop caps (count 1)
bpftune: set caps (count 2)
bpftune: libbpf: loading object 'probe_bpf' from buffer
bpftune: libbpf: elf: section(3) fentry/setup_net, size 16, link 0, flags 6, type=1
bpftune: libbpf: sec 'fentry/setup_net': found program 'entry__setup_net' at insn offset 0 (0 bytes), code size 2 insns (16 bytes)
bpftune: libbpf: elf: section(4) tp_btf/neigh_create, size 16, link 0, flags 6, type=1
bpftune: libbpf: sec 'tp_btf/neigh_create': found program 'bpftune_neigh_create' at insn offset 0 (0 bytes), code size 2 insns (16 bytes)
bpftune: libbpf: elf: section(5) cgroup/sysctl, size 16, link 0, flags 6, type=1
bpftune: libbpf: sec 'cgroup/sysctl': found program 'sysctl_write' at insn offset 0 (0 bytes), code size 2 insns (16 bytes)
bpftune: libbpf: elf: section(6) license, size 7, link 0, flags 3, type=1
bpftune: libbpf: license of probe_bpf is GPL v2
bpftune: libbpf: elf: section(7) .bss, size 25, link 0, flags 3, type=8
bpftune: libbpf: elf: section(8) .maps, size 112, link 0, flags 3, type=1
bpftune: libbpf: elf: section(15) .BTF, size 1670, link 0, flags 0, type=1
bpftune: libbpf: elf: section(17) .BTF.ext, size 160, link 0, flags 0, type=1
bpftune: libbpf: elf: section(24) .symtab, size 552, link 1, flags 0, type=2
bpftune: libbpf: looking for externs among 23 symbols...
bpftune: libbpf: collected 0 externs total
bpftune: libbpf: map 'ring_buffer_map': at sec_idx 8, offset 0.
bpftune: libbpf: map 'ring_buffer_map': found type = 27.
bpftune: libbpf: map 'ring_buffer_map': found max_entries = 131072.
bpftune: libbpf: map 'netns_map': at sec_idx 8, offset 16.
bpftune: libbpf: map 'netns_map': found type = 1.
bpftune: libbpf: map 'netns_map': found key [12], sz = 8.
bpftune: libbpf: map 'netns_map': found value [12], sz = 8.
bpftune: libbpf: map 'netns_map': found max_entries = 65536.
bpftune: libbpf: map 'last_event_map': at sec_idx 8, offset 48.
bpftune: libbpf: map 'last_event_map': found type = 1.
bpftune: libbpf: map 'last_event_map': found key [12], sz = 8.
bpftune: libbpf: map 'last_event_map': found value [12], sz = 8.
bpftune: libbpf: map 'last_event_map': found max_entries = 65536.
bpftune: libbpf: map 'probe_hash_map': at sec_idx 8, offset 80.
bpftune: libbpf: map 'probe_hash_map': found type = 1.
bpftune: libbpf: map 'probe_hash_map': found key [12], sz = 8.
bpftune: libbpf: map 'probe_hash_map': found value [12], sz = 8.
bpftune: libbpf: map 'probe_hash_map': found max_entries = 65536.
bpftune: libbpf: map 'probe_bp.bss' (global data): at sec_idx 7, offset 0, flags 400.
bpftune: libbpf: map 4 is "probe_bp.bss"
bpftune: libbpf: Unsupported BTF_KIND:19
bpftune: libbpf: loading kernel BTF '/sys/kernel/btf/vmlinux': -22
bpftune: libbpf: failed to find valid kernel BTF
bpftune: libbpf: Error loading vmlinux BTF: -3
bpftune: libbpf: failed to load object 'probe_bpf'
bpftune: libbpf: failed to load BPF skeleton 'probe_bpf': -3
bpftune: full bpftune support not available: Unknown error -3
...
```

So we see the reason why; if bpftune cannot read kernel BTF,
it cannot use fentry/fexit BPF programs which use BTF.

# Debugging bpftune behaviour

bpftune is run via service mostly, so examining logs in /var/log/messages
can help here.  However by default logging is only informational, so
again debug messaging would have to be enabled by specifying the -d
flag in /lib/systemd/system/bpftune.service and restarting.

The -d flag is passed through to bpf programs also, so 

```
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```
will show any bpftune_debug() messages emitted by BPF programs.

# Checking bpf program attachment

```
$ sudo bpftool prog
```

...will show the bpf programs currently loaded; most bpftune
programs will begin with bpftune_*

```
$ sudo bpftool map
```
...will show associated maps, and these can be dumped via

```
$ sudo bpftool map dump id <id of map>
```

...where the id is the number to the left of the ":"; i.e.

```
$ sudo bpftool map
...
149: array  name net_buff.bss  flags 0x400
	key 4B  value 49B  max_entries 1  memlock 8192B
	btf_id 269
...
$ sudo bpftool map dump id 149
[{
        "value": {
            ".bss": [{
                    "drop_count": 0
                },{
                    "drop_interval_start": 0
                },{
                    "flow_limit_cpu_bitmap": 0
                },{
                    "bpftune_learning_rate": 4
                },{
                    "tuner_id": 6
                },{
                    "bpftune_pid": 129053
                },{
                    "bpftune_init_net": 0
                },{
                    "debug": true
                }
            ]
        }
    }
]
```

# General problem or tuner-specific problem?

bpftune + libbpftune implement the general BPF load/attach and
event handling, so bugs in these areas will likely be found
there.  Tuners consist of the tuner_name.c/tuner_name.bpf.c.

Check the init()/fini() methods for setup/teardown issues,
event_handler() for event handling issues.

See ./CONTRIBUTING.md for more details on bpftune internals.

# Running tests

Tests can be a useful way to isolate tuner-specific issues.

See ./TESTING.md to explore what tests are available.
