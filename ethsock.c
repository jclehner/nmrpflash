/**
 * nmrpflash - Netgear Unbrick Utility
 * Copyright (C) 2016 Joseph Lehner <joseph.c.lehner@gmail.com>
 *
 * nmrpflash is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nmrpflash is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with nmrpflash.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <sys/types.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include "nmrpd.h"

#if defined(NMRPFLASH_WINDOWS)
#define NMRPFLASH_NETALIAS_PREFIX "net"
#define WPCAP
#include <pcap.h>
#else
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <net/if.h>
#include <pcap.h>
#if defined(NMRPFLASH_LINUX)
#define NMRPFLASH_AF_PACKET AF_PACKET
#include <linux/if_packet.h>
#else
#define NMRPFLASH_AF_PACKET AF_LINK
#include <net/if_types.h>
#endif
#endif

struct ethsock
{
	const char *intf;
	pcap_t *pcap;
#ifndef NMRPFLASH_WINDOWS
	int fd;
#ifdef NMRPFLASH_LINUX
	bool stp;
#endif
#else
	HANDLE handle;
	DWORD index;
#endif
	unsigned timeout;
	uint8_t hwaddr[6];
};

struct ethsock_arp_undo
{
	uint32_t ipaddr;
	uint8_t hwaddr[6];
};

struct ethsock_ip_undo
{
#ifndef NMRPFLASH_WINDOWS
	uint32_t ip[2];
#else
	ULONG context;
#endif
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
static inline bool sockaddr_get_hwaddr(struct sockaddr *sa, uint8_t *hwaddr)
{
	void *src;

	if (sa->sa_family != NMRPFLASH_AF_PACKET) {
		return false;
	}

#ifndef NMRPFLASH_LINUX
	if (((struct sockaddr_dl*)sa)->sdl_type != IFT_ETHER) {
		return false;
	}
	src = LLADDR((struct sockaddr_dl*)sa);
#else
	src = ((struct sockaddr_ll*)sa)->sll_addr;
#endif

	memcpy(hwaddr, src, 6);
	return true;
}

#ifdef NMRPFLASH_LINUX
static int open_stp_state(const char *intf)
{
	char name[256];
	snprintf(name, sizeof(name), "/sys/class/net/%s/bridge/stp_state", intf);
	return open(name, O_RDWR, 0644);
}

static bool is_stp_enabled(const char *intf)
{
	char c;
	int fd = open_stp_state(intf);
	if (fd == -1) {
		return false;
	}

	if (read(fd, &c, 1) != 1) {
		c = '0';
	}

	close(fd);
	return c == '1';
}

static bool set_stp_enabled(const char *intf, bool enabled)
{
	bool ret;
	const char *s = enabled ? "1\n" : "0\n";
	int fd = open_stp_state(intf);
	if (fd == -1) {
		return false;
	}

	ret = (write(fd, s, 2) == 2);
	close(fd);

	return ret;
}
#endif

static bool get_intf_info(const char *intf, uint8_t *hwaddr, void *dummy)
{
	struct ifaddrs *ifas, *ifa;
	bool found;

	if (getifaddrs(&ifas) != 0) {
		xperror("getifaddrs");
		return false;
	}

	found = false;

	for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
		if (!strcmp(ifa->ifa_name, intf)) {
			if (sockaddr_get_hwaddr(ifa->ifa_addr, hwaddr)) {
				found = true;
				break;
			}
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

static bool get_intf_info(const char *intf, uint8_t *hwaddr, DWORD *index)
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
		xperror("malloc");
		return false;
	}

	if ((ret = GetAdaptersInfo(adapters, &bufLen) == NO_ERROR)) {
		for (adapter = adapters; adapter; adapter = adapter->Next) {
			if (adapter->Type != MIB_IF_TYPE_ETHERNET && adapter->Type != IF_TYPE_IEEE80211) {
				continue;
			}

			/* Interface names from WinPcap are "\Device\NPF_{GUID}", while
			 * AdapterName from GetAdaptersInfo is just "{GUID}".*/
			if (strstr(intf, adapter->AdapterName)) {
				if (adapter->AddressLength == 6) {
					memcpy(hwaddr, adapter->Address, 6);
					if (index) {
						*index = adapter->Index;
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

#ifdef NMRPFLASH_WINDOWS
	intf = intf_alias_to_wpcap(intf);
	if (!intf) {
		return NULL;
	}
#endif

	sock = malloc(sizeof(struct ethsock));
	if (!sock) {
		xperror("malloc");
		return NULL;
	}

	buf[0] = '\0';

	sock->intf = intf;
	sock->pcap = pcap_open_live(sock->intf, BUFSIZ, 1, 1, buf);
	if (!sock->pcap) {
		fprintf(stderr, "%s.\n", buf);
		goto cleanup;
	}

	if (*buf) {
		fprintf(stderr, "Warning: %s.\n", buf);
	}

	if (pcap_datalink(sock->pcap) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an ethernet interface.\n",
				intf);
		goto cleanup;
	}

#ifndef NMRPFLASH_WINDOWS
	err = !get_intf_info(intf, sock->hwaddr, NULL);
#else
	err = !get_intf_info(intf, sock->hwaddr, &sock->index);
#endif
	if (err) {
		fprintf(stderr, "Failed to get interface info.\n");
		goto cleanup;
	}

#ifndef NMRPFLASH_WINDOWS
	sock->fd = pcap_get_selectable_fd(sock->pcap);
	if (sock->fd == -1) {
		pcap_perror(sock->pcap, "pcap_get_selectable_fd");
		goto cleanup;
	}
#else
	sock->handle = pcap_getevent(sock->pcap);
	if (!sock->handle) {
		pcap_perror(sock->pcap, "pcap_getevent");
		goto cleanup;
	}

	err = pcap_setmintocopy(sock->pcap, 1);
	if (err) {
		pcap_perror(sock->pcap, "pcap_setmintocopy");
		goto cleanup;
	}
#endif

	snprintf(buf, sizeof(buf), "ether proto 0x%04x and not ether src %s",
			protocol, mac_to_str(sock->hwaddr));

	err = pcap_compile(sock->pcap, &fp, buf, 0, 0);
	if (err) {
		pcap_perror(sock->pcap, "pcap_compile");
		goto cleanup;
	}

	err = pcap_setfilter(sock->pcap, &fp);
	pcap_freecode(&fp);

	if (err) {
		pcap_perror(sock->pcap, "pcap_setfilter");
		goto cleanup;
	}

#ifdef NMRPFLASH_LINUX
	// nmrpflash does not work on bridge interfaces with STP enabled
	if ((sock->stp = is_stp_enabled(intf))) {
		if (!set_stp_enabled(intf, false)) {
			fprintf(stderr, "Warning: failed to disable STP on %s.\n", intf);
		}
	}
#endif

	return sock;

cleanup:
	ethsock_close(sock);
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
	if (!sock) {
		return 0;
	}

#ifdef NMRPFLASH_LINUX
	if (sock->stp) {
		set_stp_enabled(sock->intf, true);
	}
#endif
	if (sock->pcap) {
		pcap_close(sock->pcap);
	}

	free(sock);
	return 0;
}

inline int ethsock_set_timeout(struct ethsock *sock, unsigned msec)
{
	sock->timeout = msec;
	return 0;
}

#ifndef NMRPFLASH_WINDOWS
int ethsock_arp_add(struct ethsock *sock, uint8_t *hwaddr, uint32_t ipaddr, struct ethsock_arp_undo **undo)
{
	return 0;
}

int ethsock_arp_del(struct ethsock *sock, struct ethsock_arp_undo **undo)
{
	return 0;
}
#else
static int ethsock_arp(struct ethsock *sock, uint8_t *hwaddr, uint32_t ipaddr, struct ethsock_arp_undo **undo)
{
	DWORD ret;
	MIB_IPNETROW arp = {
		.dwIndex = sock->index,
		.dwPhysAddrLen = 6,
		.dwAddr = ipaddr,
		.dwType = MIB_IPNET_TYPE_STATIC
	};

	memcpy(arp.bPhysAddr, hwaddr, 6);

	if (undo) {
		ret = CreateIpNetEntry(&arp);
		if (ret != NO_ERROR) {
			win_perror2("CreateIpNetEntry", ret);
			return -1;
		}

		*undo = malloc(sizeof(struct ethsock_arp_undo));
		if (!*undo) {
			xperror("malloc");
			return -1;
		}

		(*undo)->ipaddr = ipaddr;
		memcpy((*undo)->hwaddr, hwaddr, 6);
	} else {
		DeleteIpNetEntry(&arp);
	}

	return 0;
}

int ethsock_arp_add(struct ethsock *sock, uint8_t *hwaddr, uint32_t ipaddr, struct ethsock_arp_undo **undo)
{
	ethsock_arp(sock, hwaddr, ipaddr, NULL);
	return undo ? ethsock_arp(sock, hwaddr, ipaddr, undo) : -1;
}

int ethsock_arp_del(struct ethsock *sock, struct ethsock_arp_undo **undo)
{
	if (!*undo) {
		return 0;
	}

	int ret = ethsock_arp(sock, (*undo)->hwaddr, (*undo)->ipaddr, NULL);
	free(*undo);
	*undo = NULL;
	return ret;
}
#endif

static bool get_hwaddr_from_pcap(const pcap_if_t *dev, uint8_t *hwaddr)
{
#ifndef NMRPFLASH_WINDOWS
	pcap_addr_t *addr;
	int i;

	for (addr = dev->addresses; addr; addr = addr->next) {
		if (verbosity > 1) {
			printf("%s: sa_family=%d, sa_data={ ", dev->name,
					addr->addr->sa_family);
			for (i = 0; i != sizeof(addr->addr->sa_data); ++i) {
				printf("%02x ", addr->addr->sa_data[i] & 0xff);
			}
			printf("}\n");
		}

		if (sockaddr_get_hwaddr(addr->addr, hwaddr)) {
			return true;
		}
	}
#endif

	return get_intf_info(dev->name, hwaddr, NULL);
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

		if (!get_hwaddr_from_pcap(dev, hwaddr)) {
			if (verbosity) {
				printf("%-15s  (not an ethernet device)\n",
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

int ethsock_for_each_ip(struct ethsock *sock, ethsock_ip_callback_t callback,
		void *arg)
{
	struct ethsock_ip_callback_args args;
	pcap_if_t *devs, *dev;
	pcap_addr_t *addr;
	int status = 0;

	if (x_pcap_findalldevs(&devs) != 0) {
		return -1;
	}

	args.arg = arg;

	for (dev = devs; dev; dev = dev->next) {
		if (strcmp(sock->intf, dev->name)) {
			continue;
		}

		for (addr = dev->addresses; addr; addr = addr->next) {
			if (addr->addr->sa_family == AF_INET) {
				args.ipaddr = &((struct sockaddr_in*)addr->addr)->sin_addr;
				args.ipmask = &((struct sockaddr_in*)addr->netmask)->sin_addr;

				status = callback(&args);
				if (status <= 0) {
					break;
				}
			}
		}

		break;
	}

	pcap_freealldevs(devs);

	return status <= 0 ? status : 0;
}

static inline void set_addr(void *p, uint32_t addr)
{
	struct sockaddr_in* sin = p;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr;
#ifdef NMRPFLASH_BSD
	((struct sockaddr*)p)->sa_len = sizeof(struct sockaddr_in);
#endif
}

#ifndef NMRPFLASH_WINDOWS
static bool set_interface_up(int fd, const char *intf, bool up)
{
	struct ifreq ifr;
	strncpy(ifr.ifr_name, intf, IFNAMSIZ);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
		if (up) {
			xperror("ioctl(SIOCGIFFLAGS)");
		}
		return false;
	}

	if (!up) {
		ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
	} else {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	}

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
		if (up) {
			xperror("ioctl(SIOCSIFFLAGS)");
		}
		return false;
	}

	return true;
}

#endif

int ethsock_ip_add(struct ethsock *sock, uint32_t ipaddr, uint32_t ipmask, struct ethsock_ip_undo **undo)
{
	if (undo && !(*undo = malloc(sizeof(struct ethsock_ip_undo)))) {
		xperror("malloc");
		return -1;
	}

	int ret = -1;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!fd) {
		sock_perror("socket");
		goto out;
	}

#ifndef NMRPFLASH_WINDOWS
	// XXX: undo is non-zero only if we're adding an IP
	bool add = undo;
#ifdef NMRPFLASH_LINUX
	struct ifreq ifr;
	strncpy(ifr.ifr_name, sock->intf, IFNAMSIZ);
	// FIXME: automatically determine the next free alias
	strcat(ifr.ifr_name, ":42");

	if (add) {
		set_addr(&ifr.ifr_addr, ipaddr);
		if (ioctl(fd, SIOCSIFADDR, &ifr) != 0) {
			xperror("ioctl(SIOSIFADDR)");
			goto out;
		}

		set_addr(&ifr.ifr_netmask, ipmask);
		if (ioctl(fd, SIOCSIFNETMASK, &ifr) != 0) {
			xperror("ioctl(SIOCSIFNETMASK)");
			goto out;
		}

		(*undo)->ip[0] = ipaddr;
		(*undo)->ip[1] = ipmask;
	}

	if (!set_interface_up(fd, ifr.ifr_name, add)) {
		goto out;
	}
#else // NMRPFLASH_OSX (or any other BSD)
	struct ifaliasreq ifra;
	memset(&ifra, 0, sizeof(ifra));
	strncpy(ifra.ifra_name, sock->intf, IFNAMSIZ);

	set_addr(&ifra.ifra_addr, ipaddr);
	set_addr(&ifra.ifra_mask, ipmask);
	//set_addr(&ifra.ifra_broadaddr, (ipaddr & ipmask) | ~ipmask);

	if (ioctl(fd, add ? SIOCAIFADDR : SIOCDIFADDR, &ifra) != 0) {
		if (add) {
			xperror("ioctl(SIOCAIFADDR");
		}
		goto out;
	}

	if (add) {
		(*undo)->ip[0] = ipaddr;
		(*undo)->ip[1] = ipmask;
		set_interface_up(fd, ifra.ifra_name, true);
	}

#endif
#else // NMRPFLASH_WINDOWS
	struct sockaddr_in sin;
	ULONG instance;

	(*undo)->context = 0;

	DWORD err = AddIPAddress(ipaddr, ipmask, sock->index, &(*undo)->context, &instance);
	if (err != NO_ERROR && err != ERROR_DUP_DOMAINNAME && err != ERROR_OBJECT_ALREADY_EXISTS) {
		win_perror2("AddIPAddress", err);
		goto out;
	}

	set_addr(&sin, ipaddr);
	time_t beg = time_monotonic();

	/* Wait until the new IP has actually been added */

	while (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) != 0) {
		if ((time_monotonic() - beg) >= 5) {
			fprintf(stderr, "Failed to bind after 5 seconds: ");
			sock_perror("bind");
			DeleteIPAddress((*undo)->context);
			goto out;
		}
	}
#endif
	ret = 0;

out:
#ifndef NMRPFLASH_WINDOWS
	close(fd);
#else
	closesocket(fd);
#endif
	if (ret != 0 && undo) {
		free(*undo);
		*undo = NULL;
	}

	return ret;
}

int ethsock_ip_del(struct ethsock *sock, struct ethsock_ip_undo **undo)
{
	if (!*undo) {
		return 0;
	}

	int ret;

#ifndef NMRPFLASH_WINDOWS
	if ((*undo)->ip[0] != INADDR_NONE) {
		ret = ethsock_ip_add(sock, (*undo)->ip[0], (*undo)->ip[1], NULL);
	} else {
		ret = 0;
	}
#else
	DeleteIPAddress((*undo)->context);
	ret = 0;
#endif

	free(*undo);
	*undo = NULL;
	return ret;
}
