#include <libbpftune.h>
#include "cong_tuner.h"
#include "cong_tuner.skel.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct cong_tuner_bpf *skel;

int tcp_iter_fd;

int init(struct bpftuner *tuner, int ringbuf_map_fd)
{
	struct bpf_link *link;
	int err;

	/* make sure cong modules are loaded; might be builtin so do not
 	 * shout about errors.
 	 */
	if (bpftune_module_load("net/ipv4/tcp_bbr.ko"))
		bpftune_log(LOG_DEBUG, "could not load BBR module\n");
	if (bpftune_module_load("net/ipv4/tcp_htcp.ko"))
		bpftune_log(LOG_DEBUG, "could not load htcp module\n");

	bpftuner_bpf_init(cong, tuner, ringbuf_map_fd);

	skel = tuner->skel;
	link = bpf_program__attach_iter(skel->progs.bpftune_cong_iter, NULL);
	if (!link) {
		err = -errno;
		bpftune_log(LOG_ERR, "cannot attach iter : %s\n",
			    strerror(-err));
		return 1;
	}
	tcp_iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (tcp_iter_fd < 0) {
		err = -errno;
		bpftune_log(LOG_ERR, "cannot create iter fd: %s\n",
			    strerror(-err));
		return 1;
	}

	return 0;
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	if (tcp_iter_fd)
		close(tcp_iter_fd);
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&event->raw_data;
	int id = event->scenario_id;
	char buf[INET6_ADDRSTRLEN];
	char iterbuf;

	inet_ntop(sin6->sin6_family, &sin6->sin6_addr, buf, sizeof(buf));
	bpftune_log(LOG_INFO,
		    "due to loss events for %s, we will specify '%s' congestion control algorithm: (scenario %d) for tuner %s\n",
		    buf, id == TCP_CONG_BBR ? "bbr" : "htcp", id, tuner->name);

	/* kick existing connections by running iterator over them... */
	while (read(tcp_iter_fd, &iterbuf, sizeof(iterbuf)) == -1 && errno == EAGAIN)
		;

}
