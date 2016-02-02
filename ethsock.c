#include <sys/types.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include "ethsock.h"
#include "nmrpd.h"

#if !defined(NMRPFLASH_WINDOWS)
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
#ifndef NMRPFLASH_WINDOWS
	struct timeval timeout;
	int fd;
#else
	DWORD timeout;
	HANDLE handle;
#endif
	uint8_t hwaddr[6];
};

#ifndef NMRPFLASH_WINDOWS
static bool get_hwaddr(uint8_t *hwaddr, const char *intf)
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
		if (!strcmp(ifa->ifa_name, intf)) {
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

	freeifaddrs(ifas);
	return found;
}
#else
static bool get_hwaddr(uint8_t *hwaddr, const char *intf)
{
	PIP_ADAPTER_INFO adapters, adapter;
	DWORD ret;
	ULONG i, bufLen = 0;
	bool found = false;

	if ((ret = GetAdaptersInfo(NULL, &bufLen)) != ERROR_BUFFER_OVERFLOW) {
		fprintf(stderr, "GetAdaptersInfo: error %d.\n", (int)ret);
		return false;
	}

	adapters = malloc(bufLen);
	if (!adapters) {
		perror("malloc");
		return false;
	}

	if ((ret = GetAdaptersInfo(adapters, &bufLen) == NO_ERROR)) {
		for (adapter = adapters; adapter; adapter = adapter->Next) {
			if (adapter->Type != MIB_IF_TYPE_ETHERNET) {
				continue;
			}

			if (!strcmp(adapter->AdapterName, intf)) {
				if (adapter->AddressLength == 6) {
					for (i = 0; i != 6; ++i) {
						hwaddr[i] = adapter->Address[i];
					}

					found = true;
					break;
				}
			}
		}
	} else {
		fprintf(stderr, "GetAdaptersInfo: error %d.\n", (int)ret);
	}

	free(adapters);
	return found;
}
#endif


inline uint8_t *ethsock_get_hwaddr(struct ethsock *sock)
{
	return sock->hwaddr;
}

struct ethsock *ethsock_create(const char *intf, uint16_t protocol)
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

	buf[0] = '\0';

	sock->pcap = pcap_open_live(intf, BUFSIZ, 1, 1, buf);
	if (!sock->pcap) {
		fprintf(stderr, "%s.\n", buf);
		goto cleanup_malloc;
	}

	if (*buf) {
		fprintf(stderr, "Warning: %s.\n", buf);
	}

	if (pcap_datalink(sock->pcap) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an ethernet interface.\n",
				intf);
		goto cleanup_pcap;
	}

	if (!get_hwaddr(sock->hwaddr, intf)) {
		fprintf(stderr, "Failed to get MAC address of interface.\n");
		goto cleanup_malloc;
	}

#ifndef NMRPFLASH_WINDOWS
	sock->fd = pcap_get_selectable_fd(sock->pcap);
	if (sock->fd == -1) {
		fprintf(stderr, "No selectable file descriptor available.\n");
		goto cleanup_pcap;
	}
#else
	sock->handle = pcap_getevent(sock->pcap);
	if (!sock->handle) {
		fprintf(stderr, "No event handle available.\n");
		goto cleanup_pcap;
	}
#endif

	snprintf(buf, sizeof(buf), "ether proto %04x", protocol);
	err = pcap_compile(sock->pcap, &fp, buf, 0, 0);
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
#ifndef NMRPFLASH_WINDOWS
	fd_set fds;
#else
	DWORD ret;
#endif

#ifndef NMRPFLASH_WINDOWS
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
#else
	if (sock->timeout) {
		ret = WaitForSingleObject(sock->handle, sock->timeout);
		if (ret == WAIT_TIMEOUT) {
			return 0;
		} else if (ret != WAIT_OBJECT_0) {
			fprintf(stderr, "WaitForSingleObject: returned %d\n", (int)ret);
			return -1;
		}		
	}
#endif

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
#ifndef NMRPFLASH_WINDOWS
	sock->timeout.tv_sec = msec / 1000;
	sock->timeout.tv_usec = (msec % 1000) * 1000;
#else
	sock->timeout = msec;
#endif
	return 0;
}

static bool is_ethernet(const char *intf)
{
	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	bool ret = false;

	if ((pcap = pcap_create(intf, errbuf))) {
		if (pcap_activate(pcap) == 0) {
			ret = (pcap_datalink(pcap) == DLT_EN10MB);
		}
		pcap_close(pcap);
	}

	return ret;
}

int ethsock_list_all(void)
{
	pcap_if_t *devs, *dev;
	uint8_t hwaddr[6];
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&devs, errbuf) != 0) {
		fprintf(stderr, "%s.\n", errbuf);
		return -1;
	}

	memset(hwaddr, 0, 6);

	for (dev = devs; dev; dev = dev->next) {
		if (dev->flags & PCAP_IF_LOOPBACK) {
			continue;
		}

		if (!is_ethernet(dev->name)) {
			continue;
		}

		if (!get_hwaddr(hwaddr, dev->name)) {
			continue;
		}

		printf("%s  %02x:%02x:%02x:%02x:%02x:%02x", dev->name, hwaddr[0],
				hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

		if (dev->description) {
			printf("    (%s)\n", dev->description);
		} else {
			printf("\n");
		}
	}

	return 0;
}
