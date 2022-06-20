#include <bpftune.h>

#ifndef SK_MEM_QUANTUM
#define SK_MEM_QUANTUM          4096
#endif

enum tcp_buffer_tunables {
	TCP_BUFFER_TCP_WMEM,
	TCP_BUFFER_TCP_RMEM,
	TCP_BUFFER_TCP_MEM,
	TCP_BUFFER_NUM_TUNABLES,
};

enum tcp_buffer_scenarios {
	TCP_BUFFER_INCREASE,
	TCP_BUFFER_DECREASE,
	TCP_MEM_PRESSURE,
	TCP_MEM_EXHAUSTION,
};
