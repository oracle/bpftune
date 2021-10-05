#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "tcptune.skel.h"
#include "tcptune.h"

static bool done;
static bool debug;
static int sockops_fd, setsockopt_fd, cgroup_fd;
static char *cgroupdir;
struct tcptune_bpf *tcptune_skel;

static void cleanup(int sig)
{
	if (sockops_fd > 0)
		bpf_prog_detach2(sockops_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS);
	if (setsockopt_fd > 0)
		bpf_prog_detach2(setsockopt_fd, cgroup_fd,
				 BPF_CGROUP_SETSOCKOPT);
	tcptune_bpf__destroy(tcptune_skel);
	done = true;
}

static int print_all_levels(enum libbpf_print_level level,
                 const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
	int opt, err = 0;

	while ((opt = getopt(argc, argv, "c:d")) != -1) {	
		switch (opt) {
		case 'c':
			cgroupdir = optarg;
			break;
		case 'd':
			debug = true;
			break;
		default:
			fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
			return 1;
		}
	}

	if (debug)
		libbpf_set_print(print_all_levels);

	tcptune_skel = tcptune_bpf__open_and_load();
	if (!tcptune_skel) {
		fprintf(stderr, "could not open tcptune\n");
		return 1;
	}
	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);

	err = tcptune_bpf__attach(tcptune_skel);
	if (err) {
		fprintf(stderr, "could not attach tcptune: %s\n",
			strerror(err));
		goto out;
	}
	if (cgroupdir) {
		struct bpf_object *obj = tcptune_skel->obj;
		struct bpf_program *prog;

		cgroup_fd = open(cgroupdir, O_DIRECTORY, O_RDONLY);
		if (cgroup_fd < 0) {
			err = -errno;
			fprintf(stderr, "could not open cgroup path: %s\n",
				strerror(-err));
			goto out;
		}
		bpf_object__for_each_program(prog, obj) {
			const char *sec_name = bpf_program__section_name(prog);
			int prog_fd = bpf_program__fd(prog);
			enum bpf_attach_type attach_type;

			if (strcmp(sec_name, "sockops") == 0) {
				attach_type = BPF_CGROUP_SOCK_OPS;
				sockops_fd = prog_fd;
			} else if (strcmp(sec_name, "cgroup/setsockopt") == 0) {
				attach_type = BPF_CGROUP_SETSOCKOPT;
				setsockopt_fd = prog_fd;
			} else
				continue;

			fprintf(stderr, "attaching %s to cgroup %s\n",
				sec_name, cgroupdir);
			if (!bpf_prog_attach(prog_fd, cgroup_fd,
					     attach_type,
					     BPF_F_ALLOW_MULTI))
				continue;

			err = -errno;
			fprintf(stderr,
				"could not attach cgroup to prog: %s\n",
				strerror(errno));
			goto out;
		}
	}
	while (!done)
		sleep(TCP_TUNE_MIN_INTERVAL);
	return 0;
out:
	cleanup(0);
	return err;
}
