#include <libbpftune.h>
#include "cong_tuner.skel.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct cong_tuner_bpf *skel;

int init(struct bpftuner *tuner, int ringbuf_map_fd)
{
	int prog_fd, cgroup_fd, err;
	const char *cgroup_dir;

	bpftuner_bpf_init(cong, tuner, ringbuf_map_fd);

	skel = tuner->skel;
	/* attach to root cgroup */
	cgroup_dir = bpftune_cgroup_name();

	if (!cgroup_dir) {
		bpftune_log(LOG_ERR, "cannot get cgroup_dir\n");
		return 1;
	}
	cgroup_fd = bpftune_cgroup_fd();

	prog_fd = bpf_program__fd(skel->progs.cong_sockops);

	if (bpf_prog_attach(prog_fd, cgroup_fd,
			    BPF_CGROUP_SOCK_OPS, BPF_F_ALLOW_MULTI)) {
		err = -errno;
		bpftune_log(LOG_ERR, "cannot attach to cgroup '%s': %s\n",
			    cgroup_dir, strerror(-err));
		return 1;
	}

	return 0;
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	if (skel->progs.cong_sockops) {
		int prog_fd = bpf_program__fd(skel->progs.cong_sockops);
		int cgroup_fd = bpftune_cgroup_fd();

		bpf_prog_detach2(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS);
	}
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&event->raw_data;
	char buf[INET6_ADDRSTRLEN];

	inet_ntop(sin6->sin6_family, &sin6->sin6_addr, buf, sizeof(buf));
	bpftune_log(LOG_INFO,
		    "due to loss events for %s, specified 'bbr' congestion control algorithm: (scenario %d) for tuner %s\n",
		    buf, event->scenario_id, tuner->name);
}
