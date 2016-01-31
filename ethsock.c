#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include "ethsock.h"

#if defined(_WIN32) || defined(_WIN64)
#define NMRPFLASH_WINDOWS
#elif defined(__linux__)
#define NMRPFLASH_LINUX
#elif defined(__APPLE__) && defined(__MACH__)
#define NMRPFLASH_OSX
#elif defined(__unix__)
#define NMRPFLASH_UNIX
#warning "nmrp-flash is not fully supported on your operating system"
#endif

#if defined(NMRPFLASH_WINDOWS)
#include <winsock2.h>
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#if defined(NMRPFLASH_LINUX)
#include <linux/if_packet.h>
#elif defined (NMRPFLASH_OSX)
#include <net/if_dl.h>
#endif
#endif

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

#ifndef NMRPFLASH_WINDOWS
static bool get_hwaddr(uint8_t *hwaddr, const char *interface)
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
#ifdef NMRPFLASH_LINUX
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
			memcpy(hwaddr, src, 6);
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
#else
static bool get_hwaddr(uint8_t *hwaddr, const char *interface)
{
	PIP_ADAPTER_INFO adapters, adapter;
	DWORD ret;
	ULONG i, bufLen = 0;
	bool found = false;

	if ((ret = GetAdaptersInfo(NULL, &bufLen)) != ERROR_BUFFER_OVERFLOW) {
		fprintf(stderr, "GetAdaptersInfo: error %d.\n", ret);
		return false;
	}

	adapters = malloc(bufLen);
	if (!adapters) {
		perror("malloc");
		return false;
	}

	if ((ret = GetAdaptersInfo(adapters, bufLen) == NO_ERROR)) {
		for (adapter = adapters; adapter; adapter = adapter->Next) {
			if (adapter->Type != MIB_IF_TYPE_ETHERNET) {
				continue;
			}

			if (!strcmp(adapter->AdapterName, interface)) {
				for (i = 0; i != MIN(adapter->AddressLength, 6); ++i) {
					hwaddr[i] = adapter->Address[i];
				}

				found = true;
				break;
			}
		}
	} else {
		fprintf(stderr, "GetAdaptersInfo: error %d.\n", ret);
	}

	free(adapters);
	return found;
}
#endif


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

	if (!get_hwaddr(sock->hwaddr, interface)) {
		goto cleanup_malloc;
	}

	buf[0] = '\0';

	sock->pcap = pcap_open_live(interface, BUFSIZ, 1, 1, buf);
	if (!sock->pcap) {
		fprintf(stderr, "%s.\n", buf);
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
			return 0;
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
#ifdef NMRPFLASH_WINDOWS
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

int ethsock_list_all(void)
{
	pcap_if_t *devs, *dev;
	uint8_t hwaddr[8];
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&devs, errbuf) != 0) {
		fprintf(stderr, "%s.\n", errbuf);
		return -1;
	}

	for (dev = devs; dev; dev = dev->next) {
		get_hwaddr(hwaddr, dev->name);
		printf("%02x:%02x:%02x:%02x:%02x:%02x %s",
				hwaddr[0], hwaddr[1], hwaddr[2],
				hwaddr[3], hwaddr[4], hwaddr[5],
				dev->name);

		if (dev->description) {
			printf(" (%s)\n", dev->description);
		} else {
			printf("\n");
		}
	}

	return 0;
}
