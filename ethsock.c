#include <sys/socket.h>
#include <sys/types.h>
#include <net/if_dl.h>
#include <stdbool.h>
#include <ifaddrs.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include "ethsock.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

struct ethsock
{
	pcap_t *pcap;
	struct timeval timeout;
	int fd;
	uint8_t hwaddr[6];
};

static bool ethsock_fill_hwaddr(struct ethsock *sock, const char *interface)
{
	struct ifaddrs *ifas, *ifa;
	void *src;
	bool found;

	if (getifaddrs(&ifas) != 0) {
		perror("getifaddrs");
		return false;
	}

	found = false;

	for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
		if (!strcmp(ifa->ifa_name, interface)) {
#ifdef __linux__
			if (ifa->ifa_addr->sa_family != AF_PACKET) {
				continue;
			}
			src = ((struct sockaddr_ll*)ifa->ifa_addr)->sll_addr;
#else
			if (ifa->ifa_addr->sa_family != AF_LINK) {
				continue;
			}
			src = LLADDR((struct sockaddr_dl*)ifa->ifa_addr);
#endif
			memcpy(sock->hwaddr, src, 6);
			found = true;
			break;
		}
	}

	if (!found) {
		fprintf(stderr, "Failed to get MAC address of interface %s.\n", interface);
	}

	freeifaddrs(ifas);
	return found;
}

inline uint8_t *ethsock_get_hwaddr(struct ethsock *sock)
{
	return sock->hwaddr;
}

struct ethsock *ethsock_create(const char *interface, uint16_t protocol)
{
	char buf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	struct ethsock *sock;
	int err;

	sock = malloc(sizeof(struct ethsock));
	if (!sock) {
		perror("malloc");
		return NULL;
	}

	if (!ethsock_fill_hwaddr(sock, interface)) {
		goto cleanup_malloc;
	}

	buf[0] = '\0';

	sock->pcap = pcap_open_live(interface, BUFSIZ, 1, 1, buf);
	if (!sock->pcap) {
		fprintf(stderr, "%s\n", buf);
		goto cleanup_malloc;
	}

	if (*buf) {
		fprintf(stderr, "Warning: %s.\n", buf);
	}

	if (pcap_datalink(sock->pcap) != DLT_EN10MB) {
		fprintf(stderr, "Interface %s not supported.\n", interface);
		goto cleanup_pcap;
	}

	sock->fd = pcap_get_selectable_fd(sock->pcap);
	if (sock->fd == -1) {
		fprintf(stderr, "No selectable file descriptor available.\n");
		goto cleanup_pcap;
	}

	snprintf(buf, sizeof(buf), "ether proto %04x", protocol);
	err = pcap_compile(sock->pcap, &fp, buf, 0, PCAP_NETMASK_UNKNOWN);
	if (err) {
		pcap_perror(sock->pcap, "pcap_compile");
		goto cleanup_pcap;
	}

	if ((err = pcap_setfilter(sock->pcap, &fp))) {
		pcap_perror(sock->pcap, "pcap_setfilter");
		goto cleanup_pcap;
	}

	return sock;

cleanup_pcap:
	pcap_close(sock->pcap);
cleanup_malloc:
	free(sock);
	return NULL;
}

ssize_t ethsock_recv(struct ethsock *sock, void *buf, size_t len)
{
	struct pcap_pkthdr* hdr;
	const u_char *capbuf;
	int status;
	fd_set fds;

	if (sock->timeout.tv_sec || sock->timeout.tv_usec) {
		FD_ZERO(&fds);
		FD_SET(sock->fd, &fds);

		status = select(sock->fd + 1, &fds, NULL, NULL, &sock->timeout);
		if (status == -1) {
			perror("select");
			return -1;
		} else if (status == 0) {
			return 1;
		}
	}

	status = pcap_next_ex(sock->pcap, &hdr, &capbuf);
	switch (status) {
		case 1:
			memcpy(buf, capbuf, MIN(len, hdr->caplen));
			return hdr->caplen;
		case 0:
			return 0;
		case -1:
			pcap_perror(sock->pcap, "pcap_next_ex");
			return -1;
		default:
			fprintf(stderr, "pcap_next_ex: returned %d.\n", status);
			return -1;
	}
}

int ethsock_send(struct ethsock *sock, void *buf, size_t len)
{
#if defined(_WIN32) || defined(_WIN64)
	if (pcap_sendpacket(sock->pcap, buf, len) == 0) {
		return 0;
	} else {
		pcap_perror(sock->pcap, "pcap_sendpacket");
		return -1;
	}
#else
	if (pcap_inject(sock->pcap, buf, len) == len) {
		return 0;
	} else {
		pcap_perror(sock->pcap, "pcap_inject");
		return -1;
	}
#endif
}

int ethsock_close(struct ethsock *sock)
{
	pcap_close(sock->pcap);
	free(sock);
	return 0;
}

int ethsock_set_timeout(struct ethsock *sock, unsigned msec)
{
	sock->timeout.tv_sec = msec / 1000;
	sock->timeout.tv_usec = (msec % 1000) * 1000;
	return 0;
}
