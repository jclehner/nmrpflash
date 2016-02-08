#include <sys/types.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "nmrpd.h"

#if defined(NMRPFLASH_WINDOWS)
#define NMRPFLASH_NETALIAS_PREFIX "net"
#define WPCAP
#include <pcap.h>
#else
#include <pcap.h>
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
	int fd;
#else
	HANDLE handle;
#endif
	unsigned timeout;
	uint8_t hwaddr[6];
};

const char *mac_to_str(uint8_t *mac)
{
	static char buf[18];
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return buf;
}

static int x_pcap_findalldevs(pcap_if_t **devs)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(devs, errbuf) != 0) {
		fprintf(stderr, "%s.\n", errbuf);
		return -1;
	}

	return 0;
}

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

void win_perror2(const char *msg, DWORD err)
{
	char *buf = NULL;
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&buf, 0, NULL);

	if (buf) {
		/* FormatMessageA terminates buf with CRLF! */
		fprintf(stderr, "%s: %s", msg, buf);
		LocalFree(buf);
	} else {
		fprintf(stderr, "%s: error %d\n", msg, (int)err);
	}
}

static bool get_hwaddr(uint8_t *hwaddr, const char *intf)
{
	PIP_ADAPTER_INFO adapters, adapter;
	DWORD ret;
	ULONG i, bufLen = 0;
	bool found = false;

	if ((ret = GetAdaptersInfo(NULL, &bufLen)) != ERROR_BUFFER_OVERFLOW) {
		win_perror2("GetAdaptersInfo", ret);
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

#ifndef NMRPFLASH_WINDOWS
			if (!strcmp(intf, adapter->AdapterName))
#else
			/* Interface names from WinPcap are "\Device\NPF_{GUID}", while
			 * AdapterName from GetAdaptersInfo is just "{GUID}".*/
			if (strstr(intf, adapter->AdapterName))
#endif
			{
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
		win_perror2("GetAdaptersInfo", ret);
	}

	free(adapters);
	return found;
}

static const char *intf_alias_to_wpcap(const char *intf)
{
	static char buf[128];
	pcap_if_t *devs, *dev;
	unsigned i = 0, dev_num = 0;

	if (intf[0] == '\\') {
		return intf;
	} else if (sscanf(intf, NMRPFLASH_NETALIAS_PREFIX "%u", &dev_num) != 1) {
		fprintf(stderr, "Invalid interface alias.\n");
		return NULL;
	}

	if (x_pcap_findalldevs(&devs) != 0) {
		return NULL;
	}

	for (dev = devs; dev; dev = dev->next, ++i) {
		if (i == dev_num) {
			if (verbosity) {
				printf("%s%u: %s\n", NMRPFLASH_NETALIAS_PREFIX, i, dev->name);
			}
			strncpy(buf, dev->name, sizeof(buf) - 1);
			buf[sizeof(buf) - 1] = '\0';
			break;
		}
	}

	pcap_freealldevs(devs);

	if (!dev) {
		fprintf(stderr, "Interface alias not found.\n");
		return NULL;
	}

	return buf;
}

static const char *intf_get_pretty_name(const char *intf)
{
	static char buf[512];
	char *guid;
	HKEY hkey;
	LONG err;
	DWORD len;

	guid = strstr(intf, "NPF_{");
	if (!guid) {
		return NULL;
	}

	guid += 4;

	snprintf(buf, sizeof(buf),
			"System\\CurrentControlSet\\Control\\Network\\"
			"{4D36E972-E325-11CE-BFC1-08002BE10318}\\"
			"%s\\Connection", guid);
	err = RegOpenKeyExA(HKEY_LOCAL_MACHINE, buf, 0, KEY_READ, &hkey);
	if (err != ERROR_SUCCESS) {
		if (verbosity > 1) {
			win_perror2("RegOpenKeyExA", err);
		}
		return NULL;
	}

	len = sizeof(buf);
	err = RegQueryValueExA(hkey, "Name", NULL, NULL, (LPBYTE)buf, &len);
	if (err == ERROR_SUCCESS) {
		intf = buf;
	} else {
		if (verbosity > 1) {
			win_perror2("RegQueryValueExA", err);
		}
		intf = NULL;
	}

	RegCloseKey(hkey);
	return intf;
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

#ifdef NMRPFLASH_WINDOWS
	intf = intf_alias_to_wpcap(intf);
	if (!intf) {
		return NULL;
	}
#endif

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

	err = pcap_setmintocopy(sock->pcap, 1);
	if (err) {
		pcap_perror(sock->pcap, "pcap_setmintocopy");
		goto cleanup_pcap;
	}
#endif

	snprintf(buf, sizeof(buf), "ether proto 0x%04x and not ether src %s",
			protocol, mac_to_str(sock->hwaddr));

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

int select_fd(int fd, unsigned timeout)
{
	struct timeval tv;
	int status;
	fd_set fds;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	tv.tv_sec = timeout / 1000;
	tv.tv_usec = 1000 * (timeout % 1000);

	status = select(fd + 1, &fds, NULL, NULL, &tv);
	if (status < 0) {
		sock_perror("select");
	}

	return status;
}

ssize_t ethsock_recv(struct ethsock *sock, void *buf, size_t len)
{
	struct pcap_pkthdr* hdr;
	const u_char *capbuf;
	int status;
#ifdef NMRPFLASH_WINDOWS
	DWORD ret;

	if (sock->timeout) {
		ret = WaitForSingleObject(sock->handle, sock->timeout);
		if (ret == WAIT_TIMEOUT) {
			return 0;
		} else if (ret != WAIT_OBJECT_0) {
			win_perror2("WaitForSingleObject", ret);
			return -1;
		}
	}
#else
	if (sock->timeout) {
		status = select_fd(sock->fd, sock->timeout);
		if (status < 0) {
			return -1;
		} else if (status == 0) {
			return 0;
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

inline int ethsock_set_timeout(struct ethsock *sock, unsigned msec)
{
	sock->timeout = msec;
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
	pcap_addr_t *addr;
	uint8_t hwaddr[6];
	unsigned dev_num = 0, dev_ok = 0;
#ifdef NMRPFLASH_WINDOWS
	const char *pretty;
#endif

	if (x_pcap_findalldevs(&devs) != 0) {
		return -1;
	}

	memset(hwaddr, 0, 6);

	for (dev = devs; dev; dev = dev->next, ++dev_num) {
		if (dev->flags & PCAP_IF_LOOPBACK) {
			if (verbosity) {
				printf("%-15s  (loopback device)\n", dev->name);
			}
			continue;
		}

		if (!is_ethernet(dev->name)) {
			if (verbosity) {
				printf("%-15s  (not an ethernet device)\n",
						dev->name);
			}
			continue;
		}

		if (!get_hwaddr(hwaddr, dev->name)) {
			if (verbosity) {
				printf("%-15s  (failed to get hardware address)\n",
						dev->name);
			}
			continue;
		}

#ifndef NMRPFLASH_WINDOWS
		printf("%-15s", dev->name);
#else
		/* Call this here so *_perror() calls don't happen within a line */
		pretty = intf_get_pretty_name(dev->name);

		if (!verbosity) {
			printf("%s%u", NMRPFLASH_NETALIAS_PREFIX, dev_num);
		} else {
			printf("%s", dev->name);
		}
#endif

		for (addr = dev->addresses; addr; addr = addr->next) {
			if (addr->addr->sa_family == AF_INET) {
				printf("  %-15s",
						inet_ntoa(((struct sockaddr_in*)addr->addr)->sin_addr));
				break;
			}
		}

		if (!addr) {
			printf("  %-15s", "0.0.0.0");
		}

		printf("  %s", mac_to_str(hwaddr));

#ifdef NMRPFLASH_WINDOWS
		if (pretty) {
			printf("  (%s)", pretty);
		} else if (dev->description) {
			printf("  (%s)", dev->description);
		}

#endif
		printf("\n");
		++dev_ok;
	}

	if (!dev_ok) {
		printf("No suitable network interfaces found.\n");
	}

	return 0;
}
