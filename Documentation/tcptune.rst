================
KSNOOP
================
-------------------------------------------------------------------------------
tool for tracing kernel function entry/return showing arguments/return values
-------------------------------------------------------------------------------

:Manual section: 8

SYNOPSIS
========

	**ksnoop** [*OPTIONS*] { *COMMAND*  *FUNC* | **help** }

	*OPTIONS* := { { **-V** | **--version** } | { **-h** | **--help** }
	| { [**-P** | **--pages**] nr_pages} | { [**-p** | **--pid**] pid} |
        [{ **-s** | **--stack** }] | [{ **-d** | **--debug** }] }

	*COMMAND* := { **trace** | **info** }

        *FUNC* := { **name** | **name**\(**arg**\[,**arg\]) }

DESCRIPTION
===========
	*ksnoop* allows for inspection of arguments and return values
        associated with function entry/return.

        **ksnoop info** *FUNC*
                Show function description, arguments and return value types.
        **ksnoop trace** *FUNC* [*FUNC*]
                Trace function entry and return, showing arguments and
                return values.  A function name can simply be specified,
                or a function name along with named arguments, return values.
                **return** is used to specify the return value.

        *ksnoop* requires the kernel to provide BTF for itself, and if
        tracing of module data is required, module BTF must be present also.
        Check /sys/kernel/btf to see if BTF is present.

        **ksnoop** requires *CAP_BPF* and *CAP_TRACING* capabilities.

OPTIONS
=======
        -h, --help
                  Show help information
        -V, --version
                  Show version.
        -d, --debug
                  Show debug output.
        -p, --pid
                  Filter events by pid.
        -P, --pages
                  Specify number of pages used per-CPU for perf event
                  collection.  Default is 8.
        -s, --stack
                  Specified set of functions are traced if and only
                  if they are encountered in the order specified.

EXAMPLES
========
**# ksnoop info ip_send_skb** ::

  int  ip_send_skb(struct net  * net, struct sk_buff  * skb);

Show function description.

**# ksnoop trace ip_send_skb** ::

            TIME  CPU      PID FUNCTION/ARGS
  78101668506811    1     2813 ip_send_skb(
                                   net = *(0xffffffffb5959840)
                                    (struct net){
                                     .passive = (refcount_t){
                                      .refs = (atomic_t){
                                       .counter = (int)0x2,
                                      },
                                     },
                                     .dev_base_seq = (unsigned int)0x18,
                                     .ifindex = (int)0xf,
                                     .list = (struct list_head){
                                      .next = (struct list_head *)0xffff9895440dc120,
                                      .prev = (struct list_head *)0xffffffffb595a8d0,
                                     },
                                   ...

  79561322965250    1     2813 ip_send_skb(
                                   return =
                                    (int)0x0
                               );

Show entry/return for ip_send_skb() with arguments, return values.

**# ksnoop trace "ip_send_skb(skb)"** ::


           TIME  CPU      PID FUNCTION/ARGS
  78142420834537    1     2813 ip_send_skb(
                                   skb = *(0xffff989750797c00)
                                    (struct sk_buff){
                                     (union){
                                      .sk = (struct sock *)0xffff98966ce19200,
                                      .ip_defrag_offset = (int)0x6ce19200,
                                     },
                                     (union){
                                      (struct){
                                       ._skb_refdst = (long unsigned int)0xffff98981dde2d80,
                                       .destructor = (void (*)(struct sk_buff *))0xffffffffb3e1beb0,
                                      },
                                  ...

Show entry argument **skb**.

**# ksnoop trace "ip_send_skb(return)"** ::

           TIME  CPU      PID FUNCTION/ARGS
  78178228354796    1     2813 ip_send_skb(
                                   return =
                                    (int)0x0
                               );

Show return value from ip_send_skb().

**# ksnoop trace "ip_send_skb(skb->sk)"** ::

            TIME  CPU      PID FUNCTION/ARGS
  78207649138829    2     2813 ip_send_skb(
                                   skb->sk = *(0xffff98966ce19200)
                                    (struct sock){
                                     .__sk_common = (struct sock_common){
                                      (union){
                                       .skc_addrpair = (__addrpair)0x1701a8c017d38f8d,
                                       (struct){
                                        .skc_daddr = (__be32)0x17d38f8d,
                                        .skc_rcv_saddr = (__be32)0x1701a8c0,
                                       },
                                      },
                                    ...

Trace meber information associated with argument.  Only one level of
membership is supported.

**# ksnoop -p 2813 "ip_rcv(dev)"** ::

            TIME  CPU      PID FUNCTION/ARGS
  78254803164920    1     2813 ip_rcv(
                                   dev = *(0xffff9895414cb000)
                                    (struct net_device){
                                     .name = (char[16])[
                                      'l',
                                      'o',
                                     ],
                                     .name_node = (struct netdev_name_node *)0xffff989541515ec0,
                                     .state = (long unsigned int)0x3,
                                   ...

Trace **dev** argument of **ip_rcv()**.  Specify process id 2813 for events
for that process only.

**# ksnoop -s tcp_sendmsg __tcp_transmit_skb  ip_output** ::

           TIME  CPU      PID FUNCTION/ARGS
  71827770952903    1     4777 __tcp_transmit_skb(
                                   sk = *(0xffff9852460a2300)
                                    (struct sock){
                                     .__sk_common = (struct sock_common){
                                      (union){
                                       .skc_addrpair = (__addrpair)0x61b2af0a35cbfe0a,

Trace entry/return of tcp_sendmsg, __tcp_transmit_skb and ip_output when
tcp_sendmsg leads to a call to __tcp_transmit_skb and that in turn
leads to a call to ip_output; i.e. with a call graph matching the order
specified.  The order does not have to be direct calls, i.e. function A
can call another function that calls function B.

**# ksnoop "ip_send_skb(skb->len > 100, skb)"** ::

            TIME  CPU      PID FUNCTION/ARGS
  39267395709745    1     2955 ip_send_skb(
                                   skb->len = 
                                    (unsigned int)0x89,
                                   skb = *(0xffff89c8be81e500)
                                    (struct sk_buff){
                                     (union){
                                      .sk = (struct sock *)0xffff89c6c59e5580,
                                      .ip_defrag_offset = (int)0xc59e5580,
                                     },

Trace ip_send_skb() skbs which have len > 100.
