/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

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
#include <pthread.h>

static int usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -l localIP -p localPort -r remoteIP -P remotePort\n"
		"	   -m msg -c count [-o]\n",
		prog);
	return 1;
}

char msgbuf[1024];
int buflen = 1024;
int family = AF_INET;
struct sockaddr_storage laddr, raddr;
int conn_count = 1;
int listen_backlog = 0;
int count = 0;
volatile int active_conn = 0;
int isserver = 0;
int addrlen = sizeof(struct sockaddr_in);
int quiet = 0;
int sock;
int timeout = 30;

static void *perthread(void *arg);

int main(int argc, char **argv)
{
	pthread_t *pthreads;
	int *socks;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	int i = 0, j = 0;
	pthread_attr_t attr = {};
	int c, ret = 0;
	int orphan = 0;
	int iters = 0;
	void *a;

	memset(&laddr, 0, sizeof(laddr));
	memset(&raddr, 0, sizeof(raddr));

	while ((c = getopt(argc, argv, "b:C:c:l:m:o:r:p:P:qs:t:")) != -1) {
		switch (c) {
		case 'b':
			listen_backlog = atoi(optarg);
			break;
		case 'C':
			conn_count = atoi(optarg);
			pthreads = calloc(conn_count, sizeof(*pthreads));
			socks = calloc(conn_count, sizeof(int));
			break;
		case 'c':
			count = atoi(optarg);
			break;
		case 'm':
			strncpy(msgbuf, optarg, sizeof(msgbuf));
			buflen = strlen(optarg) + 1;
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
		case 't':
			timeout = atoi(optarg);
			break;
		default:
			return usage(argv[0]);
		}
	}

	pthread_attr_init(&attr);

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
		if (!quiet)
                        printf("listening...\n");
                if (listen(sock, listen_backlog ? listen_backlog : conn_count) < 0) {
                        perror("listen");
                        ret = 1;
                        goto out;
		}
	}

	for (i = 0; i < conn_count; i++) {
		int newsock = 0;

		if (isserver) {
			newsock = accept(sock, (struct sockaddr *)&raddr, &addrlen);
			if (newsock < 0) {
				perror("accept");
				continue;
			}
			socks[i] = newsock;
                }
		if (pthread_create(&pthreads[i], &attr, perthread, &socks[i])
		    != 0) {
			perror("pthread_create");
			continue;
		}
		active_conn++;
	}
	while (active_conn > 0 && ++iters < timeout) {
		sleep(1);
	}

	printf("%s handled %d/%d connections, exiting %s\n",
               isserver ? "server" : "client", i, conn_count,
	       iters >= timeout ? "due to timeout" : "normally");
out:
        close(sock);

        return ret;
}

static void *perthread(void *arg)
{
	char *buf, *recvbuf;
	int retval = 0;
	int newsock = -1;
	int j;

	buf = calloc(1, buflen);
        strncpy(buf, msgbuf, buflen);
        recvbuf = calloc(1, buflen);

	if (isserver) {
		newsock = *(int *)arg;
	} else {
		newsock = socket(family, SOCK_STREAM, 0);
		if (sock < 0) {
			perror("socket");
			goto out;
		}
		if (connect(newsock, (struct sockaddr *)&raddr, addrlen) < 0) {
			perror("connect");
			goto out;
		}
	}
	for (j = 0; j < count; j++) {
		int recvbuflen = buflen;

		if (isserver) {
			buflen = sizeof(buf);
			if (recv(newsock, recvbuf, recvbuflen, 0) < 0) {
				perror("recv");
				goto out;
			}
			if (!quiet)
				printf("%s\n", recvbuf);
			if (send(newsock, recvbuf, recvbuflen, 0) < 0) {
				perror("send");
				goto out;
			}
		} else {
			if (send(newsock, buf, buflen, 0) < 0) {
				perror("send");
				goto out;
			}
			if (recv(newsock, recvbuf, recvbuflen, 0) < 0) {
				perror("recv");
				goto out;
			}
			if (!quiet)
				printf("%s\n", recvbuf);
		}
	}
out:
	if (newsock >= 0)
		close(newsock);
	active_conn--;
	return NULL;
}
