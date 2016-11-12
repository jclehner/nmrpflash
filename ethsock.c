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
#else
	HANDLE handle;
	DWORD index;
#endif
	unsigned timeout;
	uint8_t hwaddr[6];
};

struct ethsock_ip_undo
{
#ifndef NRMPFLASH_WINDOWS
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

static bool get_intf_info(const char *intf, uint8_t *hwaddr, void *dummy)
{
	struct ifaddrs *ifas, *ifa;
	bool found;

	if (getifaddrs(&ifas) != 0) {
		perror("getifaddrs");
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
		perror("malloc");
		return false;
	}

	if ((ret = GetAdaptersInfo(adapters, &bufLen) == NO_ERROR)) {
		for (adapter = adapters; adapter; adapter = adapter->Next) {
			if (adapter->Type != MIB_IF_TYPE_ETHERNET) {
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

	sock->intf = intf;
	sock->pcap = pcap_open_live(sock->intf, BUFSIZ, 1, 1, buf);
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

#ifndef NMRPFLASH_WINDOWS
	err = !get_intf_info(intf, sock->hwaddr, NULL);
#else
	err = !get_intf_info(intf, sock->hwaddr, &sock->index);
#endif
	if (err) {
		fprintf(stderr, "Failed to get interface info.\n");
		goto cleanup_malloc;
	}

#ifndef NMRPFLASH_WINDOWS
	sock->fd = pcap_get_selectable_fd(sock->pcap);
	if (sock->fd == -1) {
		pcap_perror(sock->pcap, "pcap_get_selectable_fd");
		goto cleanup_pcap;
	}
#else
	sock->handle = pcap_getevent(sock->pcap);
	if (!sock->handle) {
		pcap_perror(sock->pcap, "pcap_getevent");
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

	err = pcap_setfilter(sock->pcap, &fp);
	pcap_freecode(&fp);

	if (err) {
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

#ifndef NMRPFLASH_WINDOWS
int ethsock_arp_add(struct ethsock *sock, uint8_t *hwaddr, struct in_addr *ipaddr)
{
	return 0;
}

int ethsock_arp_del(struct ethsock *sock, uint8_t *hwaddr, struct in_addr *ipaddr)
{
	return 0;
}
#else
static int ethsock_arp(struct ethsock *sock, uint8_t *hwaddr, struct in_addr *ipaddr, int add)
{
	DWORD ret;
	MIB_IPNETROW arp = {
		.dwIndex = sock->index,
		.dwPhysAddrLen = 6,
		.dwAddr = ipaddr->s_addr,
		.dwType = MIB_IPNET_TYPE_STATIC
	};
	
	memcpy(arp.bPhysAddr, hwaddr, 6);
	
	if (add) {
		ret = CreateIpNetEntry(&arp);
		if (ret != NO_ERROR) {
			win_perror2("CreateIpNetEntry", ret);
			return -1;
		}
	} else {
		DeleteIpNetEntry(&arp);
	}
	
	return 0;
}

int ethsock_arp_add(struct ethsock *sock, uint8_t *hwaddr, struct in_addr *ipaddr)
{
	ethsock_arp_del(sock, hwaddr, ipaddr);
	return ethsock_arp(sock, hwaddr, ipaddr, 1);
}

int ethsock_arp_del(struct ethsock *sock, uint8_t *hwaddr, struct in_addr *ipaddr)
{
	return ethsock_arp(sock, hwaddr, ipaddr, 0);
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

#ifndef NMRPFLASH_WINDOWS
static inline void set_addr(void *p, uint32_t addr)
{
	struct sockaddr_in* sin = p;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr;
}

static bool set_interface_up(int fd, const char *intf, bool up)
{
	struct ifreq ifr;
	strncpy(ifr.ifr_name, intf, IFNAMSIZ);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
		perror("ioctl(SIOCGIFFLAGS)");
		return false;
	}

	if (!up) {
		ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
	} else {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	}

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
		perror("ioctl(SIOCSIFFLAGS)");
		return false;
	}

	return true;
}

#endif

int ethsock_ip_add(struct ethsock *sock, uint32_t ipaddr, uint32_t ipmask, struct ethsock_ip_undo **undo)
{
	if (undo && !(*undo = malloc(sizeof(struct ethsock_ip_undo)))) {
		perror("malloc");
		return -1;
	}

#ifndef NMRPFLASH_WINDOWS
	int ret = -1;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!fd) {
		perror("socket");
		return -1;
	}

#ifdef NMRPFLASH_LINUX
	struct ifreq ifr;
	strncpy(ifr.ifr_name, sock->intf, IFNAMSIZ);
	// FIXME: automatically determine the next free alias
	strcat(ifr.ifr_name, ":42");

	// XXX: undo is non-zero only if we're actually adding an ip
	if (undo) {
		set_addr(&ifr.ifr_addr, ipaddr);
		if (ioctl(fd, SIOCSIFADDR, &ifr) != 0) {
			perror("ioctl(SIOSIFADDR)");
			goto out;
		}

		set_addr(&ifr.ifr_netmask, ipmask);
		if (ioctl(fd, SIOCSIFNETMASK, &ifr) != 0) {
			perror("ioctl(SIOCSIFNETMASK)");
			goto out;
		}

		(*undo)->ip[0] = ipaddr;
		(*undo)->ip[1] = ipmask;
	}

	if (!set_interface_up(fd, ifr.ifr_name, undo ? true : false)) {
		goto out;
	}
#else // NMRPFLASH_OSX (or any other BSD)
	struct ifaliasreq ifra;
	strncpy(ifra.ifra_name, sock->intf, IFNAMSIZ);

	set_addr(&ifra.ifra_addr, ipaddr);
	set_addr(&ifra.ifra_mask, ipmask);
	//set_addr(&ifra.ifra_broadaddr, (ipaddr & ipmask) | ~ipmask);
	memset(&ifra.ifra_broadaddr, 0, sizeof(ifra.ifra_broadaddr));

	// XXX: undo is non-zero only if we're actually adding an ip

	if (ioctl(fd, undo ? SIOCAIFADDR : SIOCDIFADDR, &ifra) != 0) {
		perror("ioctl(SIOCAIFADDR)");
		goto out;
	}

	if (undo) {
		(*undo)->ip[0] = ipaddr;
		(*undo)->ip[1] = ipmask;
		set_interface_up(fd, ifra.ifra_name, true);
	}

#endif
	ret = 0;

out:
	close(fd);
	return ret;
#else // NMRPFLASH_WINDOWS
	ULONG instance;

	DWORD ret = AddIPAddress(ipaddr, ipmask, sock->index, &undo->context, &instance);
	if (ret != NO_ERROR) {
		win_perror2("AddIPAddress", ret);
		return -1;
	}

	return 0;
#endif
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
	DWORD err = DeleteIPAddress((*undo)->context);
	if (err != NO_ERROR) {
		win_perror2("DeleteIPAddress", ret);
		ret = -1;
	} else {
		ret = 0;
	}
#endif

	free(*undo);
	*undo = NULL;
	return ret;
}
