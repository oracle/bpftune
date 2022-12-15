# Case studies

Below are a set of real customer bugs (all customer details removed) which
relate to various network tunable issues.

# TCP buffer exhaustion and iSCSI

Orabug 34281824

A number of systems lost connectivity simultaneously; logging revealed

```
 May 26 02:39:23 systemname kernel: TCP: out of memory – consider tuning tcp_mem

```

Turns out the tcp_mem parameters were set to

```
net.ipv4.tcp_mem = 65536  131072  262144
```

...and upping them to 

```
net.ipv4.tcp_mem = 9246282        12328377        18492564
```

...resolves the problem.

## Conclusion

tcp_mem exhaustion leads to very broken behaviour; we should avoid
it at all costs. Adaptively increase tcp_mem[2] when we approach the exhaustion
limit.

However we have to consider the effect; if a large number of connections
are active, we can exhaust system memory.  The problem is that some settings
are global (such as tcp_[wr]mem, and different sockets have different
priorities; we should, for example always support iSCSI buffer space
demands.  To handle this, may be worth clamping lower-priority service
buffer sizes to limit overheads in the case that a service needs a larger
buffer size.

See tcp_buffer_tuner (8) for more details.

# NFS server not responding 

Orabug 33106618

NFS server was not responding; a lot of retransmissions/out of order segments.  Saw

```
kernel: nfs: server 192.168.x.x not responding, still trying
```

Never fully root-caused, but a bunch of the tunables were set to low defaults:

```
TCP Read and Write Buffer
Current Values
/proc/sys/net/ipv4/tcp_rmem
4096 87380 6291456
/proc/sys/net/ipv4/tcp_wmem
4096 16384 4194304
```

Suggestion was to set the following:

```
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 87380 33554432
net.core.netdev_max_backlog = 30000
```

...and problems went away.

## Conclusion

Again we see value of adaptively increasing wmem/rmem rather than sticking
with too-low defaults.

net.core.netdev_max_backlog is by default 1000; this is too low on
faster systems as it represents the maximum length of the receive queue.

# Short listen backlog

TCP listen system call specifies a backlog which represents the maximum length
the queue of completely established connections waiting for accept() calls.
tcp_max_syn_backlog represents the max number of incomplete sockets that can
be queued, but if syncookies are enabled, this is ignored.
 
If the value in listen backlog is > proc.net.core.somaxconn it is silently
truncated to that value.

## Conclusion

If we see listen calls with backlog > proc.net.core.somaxconn, might make
sense to increase proc.net.core.somaxconn to honour app request.

# Too-small proc.net.core.netdev_max_backlog

This value defaults to 1000 and represents the maximum number of packets
to keep in the receive queue; received data is stored in that queue when it
leaves the ring buffer and faster network devices need a larger backlog.

# Conclusion

Multiple bug reports suggest increasing the netdev max backlog to 30000.

#  Large numbers of TIME_WAIT sockets

# Congestion control and high-speed links

Orabug: 31565670

Intermittent high CPU load driven by NFS causing hangs; turns out
settings were not optimal for 10G network.  Similar observations as
above, with additional use of htcp as congestion control algorithm.

# Conclusion

Would be good to auto-select htcp for high-speed links; it is more
aggressive in increasing the congestion window after loss events.
How do we distinguish which connections to use it for? Papers
describe high BDP links as being appropriate.
