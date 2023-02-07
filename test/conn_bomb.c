/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/types.h>
#include <linux/rds.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <unistd.h>

static int usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -l localIP -p localPort -r remoteIP -P remotePort\n"
		"	   -m msg -c count [-o]\n",
		prog);
	return 1;
}

int main(int argc, char **argv)
{
	int sock, addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_storage laddr, raddr;
	char msgbuf[1024];
	int buflen = 1024;
	char *buf, *recvbuf;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	int family = AF_INET;
	int i = 0, count = 0, conn_count = 1;
	int waitstatus = 0;
	struct iovec iov;
	int isserver = 0;
	int conn_num = 0;
	int c, ret = 0;
	int orphan = 0;
	int gotmsg = 0;
	int child = 0;
	int quiet = 0;
	void *a;

	memset(&laddr, 0, sizeof(laddr));
	memset(&raddr, 0, sizeof(raddr));

	while ((c = getopt(argc, argv, "C:c:l:m:o:r:p:P:qs:")) != -1) {
		switch (c) {
		case 'C':
			conn_count = atoi(optarg);
			break;
		case 'c':
			count = atoi(optarg);
			break;
		case 'm':
			strncpy(msgbuf, optarg, sizeof(msgbuf));
			buflen = sizeof(buf);
			break;
		case 'l':
			a = &((struct sockaddr_in *)&laddr)->sin_addr;
			if (strchr(optarg, ':')) {
				family = AF_INET6;
				addrlen = sizeof(struct sockaddr_in6);
				a = &((struct sockaddr_in6 *)&laddr)->sin6_addr;
			}
			if (inet_pton(family, optarg, a) != 1) {
				fprintf(stderr, "invalid laddr %s\n", optarg);
				return usage(argv[0]);
			}
			laddr.ss_family = family;
			isserver = 1;
			break;
		case 'o':
			orphan = atoi(optarg);
			break;
		case 'r':
			sin = (struct sockaddr_in *)&raddr;
			a = &sin->sin_addr;
			if (strchr(optarg, ':')) {
				family = AF_INET6;
				addrlen = sizeof(struct sockaddr_in6);
				sin6 = (struct sockaddr_in6 *)&raddr;
				a = &sin6->sin6_addr;

			}
			if (inet_pton(family, optarg, a) != 1) {
				fprintf(stderr, "invalid raddr %s\n", optarg);
				return usage(argv[0]);
			}
			raddr.ss_family = family;
			break;
		case 'p':
			sin = (struct sockaddr_in *)&laddr;
			sin->sin_port = htons(atoi(optarg));
			break;
		case 'P':
			sin = (struct sockaddr_in *)&raddr;
			sin->sin_port = htons(atoi(optarg));
			break;
		case 'q':
			quiet = 1;
			break;
		case 's':
			buflen = atoi(optarg);
			break;
		default:
			return usage(argv[0]);
		}
	}

	buf = calloc(1, buflen);
	strncpy(buf, msgbuf, sizeof(msgbuf));

	recvbuf = calloc(1, buflen);

	if (laddr.ss_family == 0 && raddr.ss_family == 0) {
		fprintf(stderr,
			"local (-l) or remote (-r) addrs must be specified\n");
		return usage(argv[0]);
	}
	if (((struct sockaddr_in *)&laddr)->sin_port == 0 &&
	    ((struct sockaddr_in *)&raddr)->sin_port == 0) {
		fprintf(stderr,
			"local (-p) or remote (-r) ports must be specified\n");
		return usage(argv[0]);
	}

	if (isserver) {
		int enable = 1;

		sock = socket(family, SOCK_STREAM, 0);
                if (sock < 0) {
                        fprintf(stderr, "socket(%d): %s\n", family, strerror(errno));
			ret = 1;
			goto out;
                }
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable,
			       sizeof(enable)) < 0) {
			perror("setsockopt(SO_REUSEADDR) failed");
			ret = 1;
			goto out;
		}
                if (bind(sock, (struct sockaddr *)&laddr, addrlen) < 0) {
                        perror("bind");
                        ret = 1;
			goto out;
		}
	}

	if (isserver) {
		if (!quiet)
                        printf("listening...\n");
                if (listen(sock, conn_count) < 0) {
                        perror("listen");
                        ret = 1;
                        goto out;
		}
	}

	for (i = 0; i < conn_count; i++) {
		int newsock, pid;

		++conn_num;

		if (isserver) {
			newsock = accept(sock, (struct sockaddr *)&raddr, &addrlen);
			if (newsock < 0) {
				perror("accept");
				continue;
			}
			pid = fork();
			if (pid != 0) {
				if (pid < 0)
					perror("fork");
				if (!orphan)
					close(newsock);
				continue;
			}
			child = 1;
		} else {
			pid = fork();
			if (pid != 0) {
				if (pid < 0)
					perror("fork");
				continue;
			}

			sock = socket(family, SOCK_STREAM, 0);
	                if (sock < 0) {
        	                perror("socket");
				exit(1);	
			}
			if (connect(sock, (struct sockaddr *)&raddr, addrlen) < 0) {
				perror("connect");
				exit(1);
			}
		}
		/* In child process context now... */
		for (i = 1; i <= count; i++) {
			int recvbuflen = buflen;

			if (isserver) {
				buflen = sizeof(buf);
				if (recv(newsock, recvbuf, recvbuflen, 0) < 0) {
					perror("recv");
					exit(1);
				}
				if (!quiet)
				printf("conn# %d: %s\n", conn_num, recvbuf);
				if (send(newsock, recvbuf, recvbuflen, 0) < 0) {
					perror("send");
					exit(1);
				}
			} else {
				if (send(sock, buf, buflen, 0) < 0) {
					perror("send");
					exit(1);
				}
				if (recv(sock, recvbuf, recvbuflen, 0) < 0) {
					perror("recv");
					exit(1);
				}
				if (!quiet)
				printf("conn# %d: %s\n", conn_num, recvbuf);
			}
		}
		if (!isserver && orphan)
			sleep(orphan);
		exit(0);
	}

out:
	while (wait(&waitstatus) > 0) {};
	close(sock);

	return ret;
}
