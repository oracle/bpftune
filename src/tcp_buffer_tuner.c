#include <libbpftune.h>
#include "tcp_buffer_tuner.h"
#include "tcp_buffer_tuner.skel.h"

struct tcp_buffer_tuner_bpf *skel;

struct bpftunable_desc descs[] = {
{ TCP_BUFFER_TCP_WMEM,			BPFTUNABLE_SYSCTL,
  		"net.ipv4.tcp_wmem",	3 },
};

int init(struct bpftuner *tuner, int ringbuf_map_fd)
{
	bpftuner_bpf_init(tcp_buffer, tuner, ringbuf_map_fd);
	return bpftuner_tunables_init(tuner, TCP_BUFFER_NUM_TUNABLES, descs);
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	long newvals[3];

	bpftune_log(LOG_DEBUG, "got scenario %d for tuner %s\n",
		    event->scenario_id, tuner->name);

	newvals[0] = event->update[0].new[0];
	newvals[1] = event->update[0].new[1];
	newvals[2] = event->update[0].new[2];

	bpftune_sysctl_write("net.ipv4.tcp_wmem", 3, newvals);
}
