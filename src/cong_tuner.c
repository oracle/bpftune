/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/libbpftune.h>
#include "cong_tuner.h"
#include "cong_tuner.skel.h"
#include "cong_tuner.skel.legacy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static struct bpftunable_desc descs[] = {
{ 
 TCP_CONG, BPFTUNABLE_OTHER, "TCP congestion control", false, 0 },
};

static struct bpftunable_scenario scenarios[] = {
{ TCP_CONG_BBR,		"specify bbr congestion control",
  "Because loss rate has exceeded 1 percent for a connection, use bbr congestion control algorithm instead of default" },
};

struct cong_tuner_bpf *skel;

int tcp_iter_fd;

int init(struct bpftuner *tuner)
{
	int err;

	/* make sure cong modules are loaded; might be builtin so do not
 	 * shout about errors.
 	 */
	err = bpftune_module_load("net/ipv4/tcp_bbr.ko");
	if (err != -EEXIST)
		bpftune_log(LOG_DEBUG, "could not load tcp_bbr module\n");

	bpftuner_bpf_init(cong, tuner, NULL);

	if (tuner->bpf_legacy) {

		/* attach to root cgroup */
		if (bpftuner_cgroup_attach(tuner, "cong_tuner_sockops", BPF_CGROUP_SOCK_OPS))
			return 1;
	} else {
		struct bpf_link *link;

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
	}

	return bpftuner_tunables_init(tuner, ARRAY_SIZE(descs), descs,
				      ARRAY_SIZE(scenarios), scenarios);
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	if (tuner->bpf_legacy)
		bpftuner_cgroup_detach(tuner, "cong_tuner_sockops", BPF_CGROUP_SOCK_OPS);
	if (tcp_iter_fd)
		close(tcp_iter_fd);
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&event->raw_data;
	unsigned int id = event->scenario_id;
	char buf[INET6_ADDRSTRLEN];
	char iterbuf;

	inet_ntop(sin6->sin6_family, &sin6->sin6_addr, buf, sizeof(buf));
	bpftuner_tunable_update(tuner, TCP_CONG, id, 0,
"due to loss events for %s, specify '%s' congestion control algorithm\n",
				buf, "bbr");

	if (!tuner->bpf_legacy) {
		/* kick existing connections by running iterator over them... */
		while (read(tcp_iter_fd, &iterbuf, sizeof(iterbuf)) == -1 && errno == EAGAIN)
		;
	}
}
