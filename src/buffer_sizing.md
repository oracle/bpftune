# How socket buffer sizing works for sockets and TCP

1. When set explicitly via setsockopt( SO_SNDBUF|SO_RCVBUF):

a) for SO_SNDBUF:

value is first filtered by syctl_wmem_max (net.core.wmem_max);
it cannot exceed this value.

value passed also maxes out at INT_MAX/2 (since it is doubled);
value actually set is (2 * val) passed in , with a min
value of SOCK_MIN_SNDBUF, which is (TCP_SKB_MIN_TRUESIZE * 2),
i.e. enough space for two TCP messages. Note that the only
tunable max value that matters here is net.core.wmem_max.

b) for SO_RCVBUF:

same logic as above applies, with SOCK_MIN_RCVBUF being
the minimum allowable size; this is one TCP_MESSAGE size.
sysctl_rmem_max (net.core.rmem_max) is the maximum value
we can set.

The minimum values allow for three-way handshake.

Note that the sysctl tcp max values are ignored when an 
application explicitly sets send/receive buffer sizes, and the
SOCK_[SND|RCV]BUF_LOCK flag is set for sk_userlocks; this flag
prevents automatic buffer expansion, trusting the user.

Observation: if an application sets SO_SNDBUF/SO_RCVBUF, we
cannot use it to analyze effects of adjusting tcp [wr]mem default
or max, since those value is ignored. Only interesting questions are

a) do send/receive buffer values get clamped to net.core.[rw]mem_max,
   i.e. are our tunable max values too low?

   If so, we probably want to trust the app and bump the associated
   core max value, since we're in effect not honouring app intentions.

b) do the defaults apps set via setsockopt() serve it well; do they 
   over/underestimate buffer utilization?

For a), we can investigate by tracing setsockopt()s for
SO_[SND|RCV]BUF and compare values set to net.core.[wr]mem_max;
if the values are clamped, we can provide feedback to adjust 
net.core.[wr]mem_max.

For b), we can see if more send/receive buffer space would
be desirable, but is not added - due to user locks on SND/RCV. 
For the send side, tracing tcp_new_space()/tcp_should_expand_sndbuf()
allows us to check if we are  not under memory pressure (tcp_memory_pressure)
and other conditions would be met for buffer expansion, i.e.

```
static __always_inline bool bpf_tcp_should_expand_sndbuf(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if (tcp_under_memory_pressure(sk))
		return false;
	/* If we are under soft global TCP memory pressure, do not expand.  */
	if (sk_memory_allocated(sk) >= sk_prot_mem_limits(sk, 0))
		return false;

	/* If we filled the congestion window, do not expand.  */
	if (tcp_packets_in_flight(tp) >= tp->snd_cwnd)
		return false;
	return true;
}
```

For overestimation of buffer sizing, we would have to confirm the
buffer utilization never gets close to filling up socket buffers;
maxes out at < 25% of core mem max value say. Would have to drop
max value _very_ conservatively.

2. When set explicitly via sysctl

As we saw above, net.core.[wr]mem_max governs maximum setsockopt()
values for SO_SNDBUF/SO_RCVBUF. However, for TCP sockets where no
setsockopt() setting is done the default tcp_[wr]mem values matter.
And for all tcp sockets, adjustments to [snd|rcv]buf values are
clamped by tcp_wmem max; they cannot exceed that value.

here is how the values are described:

a) tcp_wmem (since Linux 2.4)
	This is a vector of 3 integers: [min, default, max].  These parameters 
	are used by TCP to regulate send buffer sizes.  TCP dynamically adjusts
	the size of the send  buffer from the default values listed below, in
	the range of these values, depending on memory available.
 
	min	Minimum  size  of  the  send  buffer used by each TCP socket.
		The default value is the system page size.  (On Linux 2.4, the 
		default value is 4K bytes.)  This value is used to ensure that
		in memory pressure mode, allocations below this size will still
		succeed.  This is not used to bound the size of  the  send
		buffer declared using SO_SNDBUF on a socket.
 
	default	The   default   size   of   the   send  buffer  for  a  TCP
		socket.   This  value  overwrites  the  initial  default
		buffer  size  from  the  generic  global
		/proc/sys/net/core/wmem_default defined for all protocols.
		The default value is 16K bytes.  If larger send buffer sizes
		are  desired,  this  value  should  be increased (to affect 
		all sockets).  To employ large TCP windows, the
		/proc/sys/net/ipv4/tcp_window_scaling must be set to a nonzero
		value (default).
 
	max	The maximum size of the send buffer used by each TCP socket.
		This value does not override the value in
		/proc/sys/net/core/wmem_max.  This is not used to limit
		the size of the send buffer declared using SO_SNDBUF on a
		socket.  The default value is calculated using the formula
 
                     max(65536, min(4MB, tcp_mem[1]*PAGE_SIZE/128))
 
                     (On Linux 2.4, the default value is 128K bytes, lowered
		      64K depending on low-memory systems.)

b) tcp_rmem (since Linux 2.4)
	This is a vector of 3 integers: [min, default, max].  These parameters
	are used by TCP to regulate receive buffer sizes.  TCP dynamically
	adjusts the size of the receive buffer from the defaults listed below,
	in the range of these values, depending on memory available in the
	system.
 
	min	minimum  size  of  the  receive buffer used by each TCP socket.
		The default value is the system page size.  (On Linux 2.4, the
		default value is 4K, lowered to PAGE_SIZE bytes in low-memory
		systems.)  This value is used to ensure that in memory pressure
		mode, allocations below this size will still  succeed.   This
		is not used to bound the size of the receive buffer declared
		using SO_RCVBUF on a socket.
 
	default	the  default  size of the receive buffer for a TCP socket.
		This value overwrites the initial default buffer size from the
		generic global net.core.rmem_default defined for all protocols.
		The default value is 87380 bytes.  (On Linux 2.4, this will be
		lowered to 43689 in low-memory systems.)  If larger  receive
		buffer sizes  are  desired,  this  value  should  be  increased
		(to affect all sockets).  To employ large TCP windows, the 
		net.ipv4.tcp_window_scaling must be enabled (default).
 
	max	the maximum size of the receive buffer used by each TCP socket.
		This value does not override the global net.core.rmem_max.
		This is not used to limit the size of the receive buffer
		declared using SO_RCVBUF on a socket.  The default value is
		calculated using the formula
 
                     max(87380, min(4MB, tcp_mem[1]*PAGE_SIZE/128))
 
		(On Linux 2.4, the default is 87380*2 bytes, lowered to 87380
		 in low-memory systems).


c) tcp_mem (since Linux 2.4)
	This  is  a  vector of 3 integers: [low, pressure, high].  These
	bounds, measured in units of the system page size, are  used  by
	TCP  to  track its memory usage.  The defaults are calculated at
	boot time from the amount of available memory.   (TCP  can  only
	use  low  memory  for  this,  which  is  limited  to  around 900
	megabytes on 32-bit systems.  64-bit systems do not suffer  this
	limitation.)

	low		TCP  doesn't  regulate  its memory allocation when the
			number of pages it has  allocated  globally  is  below
			this number.

	pressure  	When  the  amount  of  memory allocated by TCP exceeds
			this number of pages, TCP moderates  its  memory  con‐
			sumption.   This  memory pressure state is exited once
			the number of pages  allocated  falls  below  the  low
			mark.

	high		The  maximum  number of pages, globally, that TCP will
			allocate.   This  value  overrides  any  other  limits
			imposed by the kernel.

Defaults for Oracle Linux/upstream (5.15)

net.core.wmem_default = 212992
net.core.wmem_max = 212992
net.ipv4.tcp_wmem = 4096	16384	4194304

net.core.rmem_default = 212992
net.core.rmem_max = 212992
net.ipv4.tcp_rmem = 4096	131072	6291456

net.ipv4.tcp_mem = 188634	251515	377268

3. Default behaviour (tcp_init_sock()):

a) sndbuf:

On initialization, sk_sndbuf is set to ipv4.sysctl.tcp_wmem[1];
which corresponds to the second value of

net.ipv4.tcp_wmem = 4096	16384	4194304

b) rcvbuf:

On initialization, sk_rcvbuf is set to ipv4.systcl.tcp_rmem[1]
which corresponds to the second value of 

net.ipv4.tcp_rmem = 4096	131072	6291456

4. Expansion behaviour

a) sndbuf expansion (tcp_sndbuf_expand())

Send buffer is only expanded in established state.

Note that tcp_expand_sndbuf() is called conditionally
via tcp_new_space(). The latter checks if tcp_should_expand_sndbuf().
The conditions for sndbuf expansion are:

 - the user did not specify a sendbuf (sk_userlocks & SOCK_SNDBUF_LOCK)
 - the system is not under global TCP memory pressure (see below). If the
   system is under memory pressure, and there is unused memory available
   associated with the socket (sk_unused_reserved_mem(sk)), the amount of
   send buffer is adjusted to the unused memory from 
   sk_unused_reserved_mem(sk). The unused memory must be > SOCK_MIN_SNDBUF. 
 - the socket has not exhausted soft memory limits specified in sysctl
   net.ipv4.tcp_mem[0] (see above). This is expressed as the limit in pages
   on unchecked tcp memory expansion; when memory utilization climbs
   to pressure value tcp_mem[1], utilization is moderated until we again fall
   below tcp_mem[0].
 - we have not filled the congestion window

When grown, it is grown to "sndmem", with a maximum size
of ipv4.sysctl_tcp_wmem[2]; the max send buffer.

To calculate sndmem, first calculate worst case scenario
for maximum send size allocation, multiplying by worst
case number of segments. The latter is calculated by
taking the maximum of the initial/current send congestion 
window size and the packet reordering metric. Finally
it is multiplied by the fast recovery expansion factor
from the congestion ops ca_ops->sndbuf_expand(), 2 by
default, BBR specifies 3.

Given all of the above, we can observe that send buffer expansion will
occur

- when the connection is established;
- when the user has not explicitly set a send buffer size via setsockopt();
- when the system is not under memory pressure;
- when congestion window is not full;

b) rcvbuf expansion


5. Shrinkage behaviour


6. Maximum behaviour





# Aim

we want to adjust default/max values associated with tcp mem to improve
performance. Note that sometimes improving buffer space can lead to
latency issues, so ideally we would like to improve on both throughput
and latency metrics.

Latency metric would be rtt values in tcp sock.

A useful throughput metric would be the send buffer size itself
(in the absence of an explicit setsockopt()).

It's a symptom of high throughput that we need to bump up send
buffer size.

Because we are event-driven, we can to an extent sidestep issues where 
lack of activity skews metrics, and send buffer size is tweaked
up but not down so gives a sense of peak utilization.

Example of kind of behaviour we want:

Event: We trace TCP_CHRONO_SNDBUF_LIMITED events

How: kprobe/tcp_chrono_start arg1 == TCP_CHRONO_SNDBUF_LIMITED

Meaning: these indicate that we were send buffer size constrained

Adjustments:

- increase the net.ipv4.tcp_wmem max value
- do we need to adjust net.ipv4.tcp_mem pressure/max also?
	- adjust based on current tcp mem utilization via /proc/net/sockstat
- do we adjust the net.ipv4.tcp_wmem default value?
	- could adjust towards the mem max value, based on scaling factor
	  observations, e.g.
		wmem_default += (wmem_max - wmem_default) * scaling_factor;

- need ceiling memory utilization here; x% of memory? but how do we assess?
we could use current tcp mem utilization as a guide. Let's assume at the
point we notice wmem_max is insufficient, let's assume 50% of total tcp mem
is wmem. advice is

"for tcp_mem, set it to twice the maximum value for tcp_[rw]mem multiplied by 
the maximum number of running network applications divided by 4096 bytes per page."


Event: We trace (via tcp_rcv_space_adjust tracepoint) receive buffer size 
constraints

Monitor effects:

- Was RTT negatively effected?
- Was memory utilization 

possible signals


interdependencies


param			effect

net.core.[wr]mem	max limits setsockopt() SO_[SND|RCV]BUF settings

net.ipv4.[wr]mem	tcp-specific settings; for 10GB NICs to maximize
			throughput suggested values are
			net.ipv4.tcp_[wr]mem = 10000000 10000000 10000000

net.ipv4.tcp_mem	vector of 3 INTEGERs: min, pressure, max
			min: below this number of pages TCP is not bothered about its
			memory appetite.

			pressure: when amount of memory allocated by TCP exceeds this number
			of pages, TCP moderates its memory consumption and enters memory
			pressure mode, which is exited when memory consumption falls
			under "min".

			max: number of pages allowed for queueing by all TCP sockets.
net.ip[46].tcp_[wr]mem	

net.ipv4.tcp_timestamps	turn off for 10Gb NICs to reduce CPU utilization
			Documentation/networking/device_drivers/ethernet/intel/ixgb.rst



## Auto-tuning - what exists?

tracepoints
tcp_rcv_space_adjust
tcp_enter_memory_pressure
tcp_leave_memory_pressure

kprobe tcp_chrono_start	
kprobe tcp_chrono_stop		

	TCP_CHRONO_SNDBUF_LIMITED
	TCP_CHRONO_RWND_LIMITED


net.ipv4.tcp.moderate_rcvbuf


tcp_moderate_rcvbuf - BOOLEAN
	If set, TCP performs receive buffer auto-tuning, attempting to
	automatically size the buffer (no greater than tcp_rmem[2]) to
	match the size required by the path for full throughput.  Enabled by
	default.

Note it is still governed by rmem_max.

If enabled, the receive window size is adjusted based on how much data was
copied to the user in the last RTT, taking into account slow start growth.

we can trace at tcp_rcv_space_adjust() and get num bytes copied since last
rtt:

	copied = tp->copied_seq - tp->rcvq_space.seq;

	rtt = tp->rcv_rtt_est.rtt_us;

Note that if the sender is in slow start, this may underestimate.


## Auto-tuning - when do I increase values?

1. net.core.[wr]mem_max

- setsockopt SO_SNDBUF/SO_RCVBUF settings are explicit settings for apps
  which max out at net.core/[wr]mem_max

```
1056  	case SO_SNDBUF:
1062		val = min_t(u32, val, sysctl_wmem_max);
1063 set_sndbuf:
1064  		/* Ensure val * 2 fits into an int, to prevent max_t()
1065  		 * from treating it as a negative value.
1066  		 */
1067  		val = min_t(int, val, INT_MAX / 2);
1068  		sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
1069  		WRITE_ONCE(sk->sk_sndbuf,
1070  			   max_t(int, val * 2, SOCK_MIN_SNDBUF));
```


- if we see setsockopt calls with > current [wr]mem_max, they will fall back
  to wmem_max; consider adjusting [wr]mem_max in such cases. Should we always
  trust such app settings? No; use memory heuristic to estimate worst-case
  scenario.

2. net.ipv4.[wr]mem_max

When are these values preventing transmission? If 

tcp_chrono_start(tp, TCP_CHRONO_SNDBUF_LIMITED);

...is called, we know we are send buffer limited for the tcp socket.
If current send buffer for the socket is 


3. net.ipv4.tcp_mem

	if we are entering memory pressure mode too frequently, may need to
	tune pressure/max. Apply heuristic to 
