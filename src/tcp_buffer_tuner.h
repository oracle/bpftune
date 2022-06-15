#include <bpftune.h>

enum tcp_buffer_tunables {
	TCP_BUFFER_TCP_WMEM,
	TCP_BUFFER_TCP_RMEM,
	TCP_BUFFER_NUM_TUNABLES,
};

enum tcp_buffer_scenarios {
	TCP_BUFFER_INCREASE,
	TCP_BUFFER_DECREASE,
};
