#include <libbpftune.h>
#include "tcp_buffer_tuner.h"
#include "tcp_buffer_tuner.skel.h"

#include <unistd.h>

struct tcp_buffer_tuner_bpf *skel;

static struct bpftunable_desc descs[] = {
{ TCP_BUFFER_TCP_WMEM,	BPFTUNABLE_SYSCTL, "net.ipv4.tcp_wmem", true, 3 },
{ TCP_BUFFER_TCP_RMEM,	BPFTUNABLE_SYSCTL, "net.ipv4.tcp_rmem", true, 3 },
};

int init(struct bpftuner *tuner, int ringbuf_map_fd)
{
	struct tcp_buffer_tuner_bpf *skel;
	int pagesize;

	bpftuner_bpf_open(tcp_buffer, tuner, ringbuf_map_fd);
	bpftuner_bpf_load(tcp_buffer, tuner, ringbuf_map_fd);

	skel = tuner->skel;

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize < 0)
		pagesize = 4096;
	skel->bss->kernel_page_size = pagesize;
	skel->bss->kernel_page_shift = ilog2(pagesize);
	skel->bss->sk_mem_quantum = SK_MEM_QUANTUM;
	skel->bss->sk_mem_quantum_shift = ilog2(SK_MEM_QUANTUM);
	bpftune_log(LOG_DEBUG,
		    "set pagesize/shift to %d/%d; sk_mem_quantum/shift %d/%d\n",
		    pagesize, skel->bss->kernel_page_shift, SK_MEM_QUANTUM,
		    skel->bss->sk_mem_quantum_shift);
	bpftuner_bpf_attach(tcp_buffer, tuner, ringbuf_map_fd);
	return bpftuner_tunables_init(tuner, TCP_BUFFER_NUM_TUNABLES, descs);
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

void event_handler(__attribute__((unused))struct bpftuner *tuner,
		   struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	int netns_fd = 0;
	long newvals[3];

	newvals[0] = event->update[0].new[0];
	newvals[1] = event->update[0].new[1];
	newvals[2] = event->update[0].new[2];

	if (event->netns_cookie) {
		netns_fd = bpftune_netns_fd_from_cookie(event->netns_cookie);
		if (netns_fd < 0) {
			bpftune_log(LOG_DEBUG, "could not get netns fd for cookie %ld\n",
				    event->netns_cookie); 
			return;
		}
	}
	switch (event->update[0].id) {
	case TCP_BUFFER_TCP_WMEM:
		bpftune_sysctl_write(netns_fd, "net.ipv4.tcp_wmem", 3, newvals);
		break;
	case TCP_BUFFER_TCP_RMEM:
		bpftune_sysctl_write(netns_fd, "net.ipv4.tcp_rmem", 3, newvals);
		break;
	}

	if (netns_fd)
		close(netns_fd);
}
