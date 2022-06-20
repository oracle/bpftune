/*
** Copyright (c) 2022, Oracle and/or its affiliates.
**
** The Universal Permissive License (UPL), Version 1.0
**
** Subject to the condition set forth below, permission is hereby granted to any
** person obtaining a copy of this software, associated documentation and/or data
** (collectively the "Software"), free of charge and under any and all copyright
** rights in the Software, and any and all patent rights owned or freely
** licensable by each licensor hereunder covering either (i) the unmodified
** Software as contributed to or provided by such licensor, or (ii) the Larger
** Works (as defined below), to deal in both
** 
** (a) the Software, and
** (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
** one is included with the Software (each a "Larger Work" to which the Software
** is contributed by such licensors),
** 
** without restriction, including without limitation the rights to copy, create
** derivative works of, display, perform, and distribute the Software and make,
** use, sell, offer for sale, import, export, have made, and have sold the
** Software and the Larger Work(s), and to sublicense the foregoing rights on
** either these or other terms.
** 
** This license is subject to the following condition:
** The above copyright notice and either this complete permission notice or at
** a minimum a reference to the UPL must be included in all copies or
** substantial portions of the Software.
** 
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
** SOFTWARE.
*/

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/types.h>
#include <linux/rds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

static int usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -l localIP -p localPort -r remoteIP -P remotePort\n"
		"	   -m msg -c count\n",
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
	int gotmsg = 0;
	int child = 0;
	int quiet = 0;
	void *a;

	memset(&laddr, 0, sizeof(laddr));
	memset(&raddr, 0, sizeof(raddr));

	while ((c = getopt(argc, argv, "C:c:l:m:r:p:P:qs:")) != -1) {
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

	for (i = 0; i < conn_count; i++) {
		int newsock, pid;

		++conn_num;

		if (isserver) {
			if (!quiet)
			printf("listening...\n");
			if (listen(sock, conn_count) < 0) {
	                        perror("listen");
				ret = 1;
				goto out;
                	}
			newsock = accept(sock, (struct sockaddr *)&raddr, &addrlen);
			if (newsock < 0) {
				perror("accept");
				continue;
			}
			pid = fork();
			if (pid != 0) {
				close(newsock);
				continue;
			}
			child = 1;
		} else {
			pid = fork();
			if (pid != 0)
				continue;

			sock = socket(family, SOCK_STREAM, 0);
	                if (sock < 0) {
        	                perror("socket");
				exit(1);	
			}
			if (connect(sock, (struct sockaddr *)&raddr, addrlen) < 0)
				exit(1);
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
		exit(0);
	}

out:
	while (wait(&waitstatus) > 0) {};
	close(sock);

	return ret;
}
