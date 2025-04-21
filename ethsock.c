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
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include "nmrpd.h"

#if defined(NMRPFLASH_WINDOWS)
#  include <iphlpapi.h>
#  ifndef ERROR_NDIS_MEDIA_DISCONNECTED
#    define ERROR_NDIS_MEDIA_DISCONNECTED 0x8034001f
#  endif
#  define WPCAP
#  include <pcap.h>
#else
#  include <sys/ioctl.h>
#  include <ifaddrs.h>
#  include <unistd.h>
#  include <net/if.h>
#  include <pcap.h>
#  if defined(NMRPFLASH_LINUX)
#    define NMRPFLASH_AF_PACKET AF_PACKET
#    include <linux/if_packet.h>
#    include <netlink/route/addr.h>
#    include <netlink/route/neighbour.h>
#  else
#    define NMRPFLASH_AF_PACKET AF_LINK
#    include <net/if_types.h>
#    include <net/if_media.h>
#  endif
#endif

#ifdef NMRPFLASH_MACOS
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#endif

struct ethsock
{
	const char *intf;
	pcap_t *pcap;
#ifndef NMRPFLASH_WINDOWS
	int fd;
#ifdef NMRPFLASH_LINUX
	bool stp;
	// managed by NetworkManager
	bool nm_managed;
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
	uint32_t ip[2];
};

static int x_pcap_findalldevs(pcap_if_t **devs)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(devs, errbuf) != 0) {
		fprintf(stderr, "%s.\n", errbuf);
		return -1;
	}

	return 0;
}

static bool intf_get_pcap_flags(const char *intf, bpf_u_int32 *flags)
{
	pcap_if_t *devs, *dev;

	if (x_pcap_findalldevs(&devs) == 0) {
		for (dev = devs; dev; dev = dev->next) {
			if (!strcmp(intf, dev->name)) {
				*flags = dev->flags;
				break;
			}
		}

		pcap_freealldevs(devs);
		return dev != NULL;
	}

	return false;
}

int systemf(const char *fmt, ...)
{
	char cmd[1024];
	int ret;
	va_list va;
	va_start(va, fmt);

	ret = vsnprintf(cmd, sizeof(cmd) - 1, fmt, va);
	if (ret >= sizeof(cmd) - 1) {
		return -1;
	}

	ret = system(cmd);
	va_end(va);

	return ret;
}

#ifndef NMRPFLASH_WINDOWS
static inline bool sockaddr_get_hwaddr(struct sockaddr *sa, uint8_t *hwaddr)
{
	void *src;

	if (!sa || sa->sa_family != NMRPFLASH_AF_PACKET) {
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
static int intf_sys_open(const char* intf, const char* file)
{
	char name[256];
	snprintf(name, sizeof(name), "/sys/class/net/%s/%s", intf, file);
	return open(name, O_RDWR, 0644);
}

static bool intf_sys_read(const char* intf, const char* file, bool def)
{
	char c;
	int fd;

	fd = intf_sys_open(intf, file);
	if (fd == -1) {
		return def;
	}

	c = 0;
	read(fd, &c, 1);
	close(fd);

	return c ? (c == '1') : def;
}

static bool intf_stp_enable(const char *intf, bool enabled)
{
	int fd;
	ssize_t n;

	fd = intf_sys_open(intf, "bridge/stp_state");
	if (fd == -1) {
		return false;
	}

	n = write(fd, enabled ? "1\n" : "0\n", 2);
	close(fd);

	return n == 2;
}

static struct nl_addr *build_ip(uint32_t ip)
{
	struct nl_addr *na = nl_addr_build(AF_INET, &ip, 4);
	if (!na) {
		xperror("nl_addr_build");
	}

	return na;
}

static struct nl_sock *xnl_socket_route()
{
	int err;
	struct nl_sock *sk = nl_socket_alloc();
	if (sk) {
		if (!(err = nl_connect(sk, NETLINK_ROUTE))) {
			return sk;
		}
		nl_socket_free(sk);
		nl_perror(err, "nl_connect");
	} else {
		xperror("nl_socket_alloc");
	}

	return NULL;
}

static bool intf_add_del_ip(const char *intf, uint32_t ipaddr, uint32_t ipmask, bool add)
{
	struct rtnl_addr *ra = NULL;
	struct nl_sock *sk = NULL;
	struct nl_addr *laddr = NULL;
	struct nl_addr *bcast = NULL;
	int err = 1;

	if (!(sk = xnl_socket_route())) {
		return false;
	}

	if (!(laddr = build_ip(ipaddr))) {
		goto out;
	}

	nl_addr_set_prefixlen(laddr, bitcount(ipmask));

	if (!(bcast = build_ip((ipaddr & ipmask) | ~ipmask))) {
		goto out;
	}

	if (!(ra = rtnl_addr_alloc())) {
		xperror("rtnl_addr_alloc");
		goto out;
	}

	rtnl_addr_set_ifindex(ra, if_nametoindex(intf));
	rtnl_addr_set_local(ra, laddr);
	rtnl_addr_set_broadcast(ra, bcast);

	if ((err = (add ? rtnl_addr_add(sk, ra, 0) : rtnl_addr_delete(sk, ra, 0))) < 0) {
		if (add && err == -NLE_EXIST) {
			err = 0;
		} else if (add || verbosity > 1) {
			nl_perror(err, add ? "rtnl_addr_add" : "rtnl_addr_delete");
		}
	}

out:
	rtnl_addr_put(ra);
	nl_addr_put(laddr);
	nl_addr_put(bcast);
	nl_socket_free(sk);

	return !err;
}

static bool intf_add_del_arp(const char *intf, uint32_t ipaddr, uint8_t *hwaddr, bool add)
{
#if 0
	struct arpreq arp;
	memset(&arp, 0, sizeof(arp));
	arp.arp_ha.sa_family = ARPHRD_ETHER;
	memcpy(&arp.arp_ha.sa_data, hwaddr, 6);
	arp.arp_flags = ATF_PERM | ATF_COM;

	struct sockaddr_in *in = (struct sockaddr_in*)&req.arp_pa;
	in->sin_addr.s_addr = htonl(ipaddr);
	in->sin_family = AF_INET;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return false;
	}

	bool ret = true;

	if (ioctl(fd, add ? SIOCSARP : SIOCDARP, &req) < 0) {
		perror(add ? "ioctl(SIOCSARP)" : "ioctl(SIOCDARP");
		ret = false;
	}

	close(fd);
	return ret;
#else
	struct nl_sock *sk;
	struct rtnl_neigh *neigh;
	struct nl_addr *mac, *ip;
	int err = 1;

	sk = NULL;
	neigh = NULL;
	mac = ip = NULL;

	if (!(sk = xnl_socket_route())) {
		goto out;
	}

	if (!(neigh = rtnl_neigh_alloc())) {
		xperror("rtnl_neigh_alloc");
		goto out;
	}

	if (!(mac = nl_addr_build(AF_PACKET, hwaddr, 6))) {
		xperror("nl_addr_build");
		goto out;
	}

	if (!(ip = nl_addr_build(AF_INET, &ipaddr, 4))) {
		xperror("nl_addr_build");
		goto out;
	}

	rtnl_neigh_set_ifindex(neigh, if_nametoindex(intf));
	rtnl_neigh_set_dst(neigh, ip);

	err = rtnl_neigh_delete(sk, neigh, 0);

	if (add) {
		rtnl_neigh_set_lladdr(neigh, mac);
		rtnl_neigh_set_state(neigh, NUD_PERMANENT);
		err = rtnl_neigh_add(sk, neigh, NLM_F_CREATE);
	}

	if (err && add) {
		nl_perror(err, "rtnl_neigh_add");
	}

out:
	nl_addr_put(ip);
	nl_addr_put(mac);
	rtnl_neigh_put(neigh);
	nl_socket_free(sk);

	return !err;
#endif
}

#endif

static bool intf_get_hwaddr_and_bridge(const char *intf, uint8_t *hwaddr, bool *bridge)
{
	struct ifaddrs *ifas, *ifa;
	bool found;

	if (getifaddrs(&ifas) != 0) {
		xperror("getifaddrs");
		return false;
	}

	found = false;

	if (bridge) {
		*bridge = false;
	}

	for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
		if (!strcmp(ifa->ifa_name, intf)) {
			if (sockaddr_get_hwaddr(ifa->ifa_addr, hwaddr)) {
#ifdef NMRPFLASH_BSD
				if (bridge) {
					*bridge = ((struct if_data*) ifa->ifa_data)->ifi_type == IFT_BRIDGE;
				}
#endif
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
			(LPSTR)&buf, 0, NULL);

	if (buf) {
		/* FormatMessageA terminates buf with CRLF! */
		fprintf(stderr, "%s: %s", msg, buf);
		LocalFree(buf);
	} else {
		fprintf(stderr, "%s: error %d\n", msg, (int)err);
	}
}

static bool intf_get_if_row(NET_IFINDEX index, MIB_IF_ROW2* row)
{
	DWORD err;

	memset(row, 0, sizeof(*row));
	row->InterfaceIndex = index;

	err = GetIfEntry2(row);
	if (err != NO_ERROR) {
	    if (verbosity > 1) {
			win_perror2("GetIfEntry2", err);
	    }
		return false;
	}

	return true;
}

static bool intf_get_hwaddr_and_index(const char *intf, uint8_t *hwaddr, DWORD *index)
{
	PIP_ADAPTER_ADDRESSES adapters, adapter;
	ULONG ret, flags, bufLen;
	bool found = false;

	flags = GAA_FLAG_INCLUDE_ALL_INTERFACES;
	bufLen = 0;
	ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &bufLen);
	if (ret != ERROR_BUFFER_OVERFLOW) {
		win_perror2("GetAdaptersAddresses", ret);
		return false;
	}

	bufLen *= 2;

	adapters = malloc(bufLen);
	if (!adapters) {
		xperror("malloc");
		return false;
	}

	ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, adapters, &bufLen);
	if (ret == NO_ERROR) {
		for (adapter = adapters; adapter; adapter = adapter->Next) {
			if (verbosity > 2) {
				printf("  %s: Type=%lu, Name=%ls\n", adapter->AdapterName, adapter->IfType, adapter->FriendlyName);
			}
			if (adapter->IfType != IF_TYPE_ETHERNET_CSMACD && adapter->IfType != IF_TYPE_IEEE80211) {
				continue;
			}

			/* Interface names from WinPcap are "\Device\NPF_{GUID}", while
			 * AdapterName from GetAdaptersAddresses is just "{GUID}".*/
			if (strstr(intf, adapter->AdapterName)) {
				if (adapter->PhysicalAddressLength == 6) {
					memcpy(hwaddr, adapter->PhysicalAddress, 6);
					if (index) {
						*index = adapter->IfIndex;
					}
					found = true;
					break;
				}
			}
		}
	} else {
		win_perror2("GetAdaptersAddresses", ret);
	}

	free(adapters);
	return found;
}

static const char *intf_name_to_wpcap(const char *intf)
{
	static char buf[128];

	if (intf[0] == '\\') {
		return intf;
	}

	do {
		NET_IFINDEX index;
		DWORD err;
		NET_LUID luid;
		GUID guid;

		// Allow net%lu as well, for backwards compatiblity with <= 0.9.25

		if (sscanf(intf, "eth%lu", &index) != 1 && sscanf(intf, "net%lu", &index) != 1) {
			index = if_nametoindex(intf);
			if (!index) {
				break;
			}
		}

		err = ConvertInterfaceIndexToLuid(index, &luid);
		if (err != NO_ERROR) {
			if (verbosity) {
				win_perror2("ConvertInterfaceIndexToLuid", err);
			}
			break;
		}

		err = ConvertInterfaceLuidToGuid(&luid, &guid);
		if (err != NO_ERROR) {
			if (verbosity) {
				win_perror2("ConvertInterfaceLuidToGuid", err);
			}
			break;
		}

		snprintf(buf, sizeof(buf),
			"\\Device\\NPF_{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
			guid.Data1, guid.Data2, guid.Data3,
			guid.Data4[0], guid.Data4[1], guid.Data4[2],
			guid.Data4[3], guid.Data4[4], guid.Data4[5],
			guid.Data4[6], guid.Data4[7]);

		return buf;

	} while (false);

	fprintf(stderr, "Invalid interface name.\n");
	return NULL;
}

NET_IFINDEX intf_get_index(const char* intf)
{
	const char* p;
	GUID guid;
	NET_LUID luid;
	DWORD err;
	NET_IFINDEX ret;
	int n;

	p = strstr(intf, "NPF_{");
	if (!p) {
		return 0;
	}

	sscanf(p + 5,
			"%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%n",
			&guid.Data1, &guid.Data2, &guid.Data3,
			&guid.Data4[0], &guid.Data4[1], &guid.Data4[2],
			&guid.Data4[3], &guid.Data4[4], &guid.Data4[5],
			&guid.Data4[6], &guid.Data4[7], &n);

	if (n != 36) {
		return 0;
	}

	err = ConvertInterfaceGuidToLuid(&guid, &luid);
	if (err) {
		win_perror2("ConvertInterfaceGuidToLuid", err);
		return 0;
	}

	err = ConvertInterfaceLuidToIndex(&luid, &ret);
	if (err) {
		win_perror2("ConvertInterfaceLuidToIndex", err);
		return 0;
	}

	return ret;
}

static char* wcs_to_utf8(const wchar_t* src)
{
	char* buf = NULL;
	int len;

	len = WideCharToMultiByte(CP_UTF8, 0, src, -1, 0, 0, NULL, NULL);
	if (len) {
		buf = malloc(len);
		if (buf) {
			if (WideCharToMultiByte(CP_UTF8, 0, src, -1, buf, len, NULL, NULL) == len) {
				return buf;
			}
			free(buf);
		}
	}

	return NULL;
}
#endif

#ifdef NMRPFLASH_MACOS
void cf_perror(const char* function)
{
	if (verbosity > 1) {
		fprintf(stderr, "Warning: %s failed\n", function);
	}
}

void cf_release(CFTypeRef cf)
{
	if (cf) {
		CFRelease(cf);
	}
}

char* get_pretty_name(const char* interface)
{
	CFStringRef target_dev = NULL;
	CFArrayRef interfaces = NULL;
	char* pretty = NULL;

	target_dev = CFStringCreateWithCString(NULL, interface, kCFStringEncodingUTF8);
	if (!target_dev) {
		cf_perror("CFStringCreateWithCString");
		return NULL;
	}

	interfaces = SCNetworkInterfaceCopyAll();
	if (!interfaces) {
		goto out;
	}

	CFIndex size = CFArrayGetCount(interfaces);
	for (CFIndex i = 0; i < size; ++i) {
		SCNetworkInterfaceRef intf = (SCNetworkInterfaceRef)CFArrayGetValueAtIndex(interfaces, i);
		if (!intf) {
			continue;
		}

		CFStringRef dev = SCNetworkInterfaceGetBSDName(intf);
		if (!dev) {
			continue;
		}

		if (CFStringCompare(dev, target_dev, 0) == kCFCompareEqualTo) {
			CFStringRef	s = SCNetworkInterfaceGetLocalizedDisplayName(intf);
			if (!s) {
				continue;
			}

			CFIndex len = CFStringGetLength(s) + 1;
			pretty = (char*)malloc(len);
			if (!pretty) {
				if (verbosity > 1) {
					perror("malloc");
				}
			} else if (!CFStringGetCString(s, pretty, len, kCFStringEncodingUTF8)) {
				cf_perror("CFStringGetCString");
				free(pretty);
				pretty = NULL;
			}

			break;
		}
	}

out:
	cf_release(target_dev);
	cf_release(interfaces);
	return pretty;
}
#endif

inline uint8_t *ethsock_get_hwaddr(struct ethsock *sock)
{
	return sock->hwaddr;
}

bool ethsock_is_wifi(struct ethsock *sock)
{
#ifdef PCAP_IF_WIRELESS
	bpf_u_int32 flags;

	if (!intf_get_pcap_flags(sock->intf, &flags)) {
		return false;
	}

	return flags & PCAP_IF_WIRELESS;
#else
#warning "libpcap version is < 1.9.0"
	return false;
#endif
}

bool ethsock_is_unplugged(struct ethsock *sock)
{
#ifdef PCAP_IF_CONNECTION_STATUS
	bpf_u_int32 flags;

	if (!intf_get_pcap_flags(sock->intf, &flags)) {
		return false;
	}

	return (flags & PCAP_IF_CONNECTION_STATUS)
		== PCAP_IF_CONNECTION_STATUS_DISCONNECTED;
#else
#warning "libpcap version is < 1.9.0"
	return false;
#endif
}

struct ethsock *ethsock_create(const char *intf, uint16_t protocol)
{
	char buf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	struct ethsock *sock;
	bool is_bridge = false;
	int err;

#ifdef NMRPFLASH_WINDOWS
	intf = intf_name_to_wpcap(intf);
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
	sock->pcap = pcap_create(sock->intf, buf);
	if (!sock->pcap) {
		fprintf(stderr, "pcap_create: %s\n", buf);
	}

	if (*buf) {
		fprintf(stderr, "Warning: %s.\n", buf);
	}

	err = pcap_set_snaplen(sock->pcap, BUFSIZ);
	if (err) {
		pcap_perror(sock->pcap, "pcap_set_snaplen");
		goto cleanup;
	}

	err = pcap_set_promisc(sock->pcap, 1);
	if (err) {
		pcap_perror(sock->pcap, "pcap_set_promisc");
		goto cleanup;
	}

	err = pcap_set_timeout(sock->pcap, 200);
	if (err) {
		pcap_perror(sock->pcap, "pcap_set_timeout");
		goto cleanup;
	}

	err = pcap_set_immediate_mode(sock->pcap, 1);
	if (err) {
		pcap_perror(sock->pcap, "pcap_set_immediate_mode");
		goto cleanup;
	}

	err = pcap_activate(sock->pcap);
	if (err < 0) {
		pcap_perror(sock->pcap, "pcap_activate");
		goto cleanup;
	} else if (err > 0) {
		fprintf(stderr, "Warning: %s.\n", pcap_geterr(sock->pcap));
	}

	if (pcap_datalink(sock->pcap) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an ethernet interface.\n",
				intf);
		goto cleanup;
	}

#ifndef NMRPFLASH_WINDOWS
	err = !intf_get_hwaddr_and_bridge(intf, sock->hwaddr, &is_bridge);
#else
	err = !intf_get_hwaddr_and_index(intf, sock->hwaddr, &sock->index);
#endif
	if (err) {
		fprintf(stderr, "Failed to get interface info.\n");
		goto cleanup;
	}

#ifdef NMRPFLASH_WINDOWS
	err = pcap_setmintocopy(sock->pcap, 0);
	if (err) {
		pcap_perror(sock->pcap, "pcap_setmintocopy");
		goto cleanup;
	}

	sock->handle = pcap_getevent(sock->pcap);
	if (!sock->handle) {
		pcap_perror(sock->pcap, "pcap_getevent");
		goto cleanup;
	}
#else
	sock->fd = pcap_get_selectable_fd(sock->pcap);
	if (sock->fd == -1) {
		pcap_perror(sock->pcap, "pcap_get_selectable_fd");
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
	if ((sock->stp = intf_sys_read(intf, "bridge/stp_state", false))) {
		if (!intf_stp_enable(intf, false)) {
			fprintf(stderr, "Warning: failed to disable STP on %s.\n", intf);
		}
	}

	err = system("nmcli -v > /dev/null");
	if (!err) {
		err = systemf("nmcli -f GENERAL.STATE device show %s | grep -q unmanaged", sock->intf);
		if (!err) {
			sock->nm_managed = false;
		} else {
			sock->nm_managed = true;
			err = systemf("nmcli device set ifname %s managed no", sock->intf);
			if (err) {
				printf("Warning: failed to temporarily disable NetworkManager\n");
			} else if (verbosity > 1) {
				printf("Temporarily disabling NetworkManager on interface.\n");
			}
		}
	} else {
		sock->nm_managed = false;
	}
#else
	if (is_bridge) {
		fprintf(stderr, "Warning: bridge interfaces are not fully "
				"supported on this platform.\n");
	}
#endif

	return sock;

cleanup:
	ethsock_close(sock);
	return NULL;
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
	if (pcap_inject(sock->pcap, buf, len) != len) {
#ifdef NMRPFLASH_WINDOWS
		// Npcap's pcap_inject fails in many cases where neither
		// Linux or macOS report an error. For now, we simply
		// ignore errors if unplugged (and let all other through
		// as well, just printing a debug line).

		if (!ethsock_is_unplugged(sock) && verbosity > 1) {
			pcap_perror(sock->pcap, "pcap_inject");
		}

		return 0;
#endif
		pcap_perror(sock->pcap, "pcap_inject");
		return -1;
	}

	return 0;
}

int ethsock_close(struct ethsock *sock)
{
	if (!sock) {
		return 0;
	}

#ifdef NMRPFLASH_LINUX
	if (sock->stp) {
		intf_stp_enable(sock->intf, true);
	}

	if (sock->nm_managed) {
		systemf("nmcli device set ifname %s managed yes", sock->intf);
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

unsigned ethsock_get_timeout(struct ethsock *sock)
{
	return sock->timeout;
}

static int ethsock_arp(struct ethsock *sock, uint8_t *hwaddr, uint32_t ipaddr, struct ethsock_arp_undo **undo)
{
#if defined(NMRPFLASH_UNIX) && !defined(NMRPFLASH_LINUX)
	struct in_addr addr = { .s_addr = ipaddr };
#elif defined(NMRPFLASH_WINDOWS)
	DWORD err;
	MIB_IPNETROW arp = {
		.dwIndex = sock->index,
		.dwPhysAddrLen = 6,
		.dwAddr = ipaddr,
		.dwType = MIB_IPNET_TYPE_STATIC
	};

	memcpy(arp.bPhysAddr, hwaddr, 6);
#endif

	if (undo) {
#if defined(NMRPFLASH_LINUX)
		if (!intf_add_del_arp(sock->intf, ipaddr, hwaddr, true)) {
			return -1;
		}
#elif defined(NMRPFLASH_WINDOWS)
		err = CreateIpNetEntry(&arp);
		if (err != NO_ERROR) {
			win_perror2("CreateIpNetEntry", err);
			return -1;
		}
#else
		if (systemf("arp -s %s %s", inet_ntoa(addr), mac_to_str(hwaddr)) != 0) {
			return -1;
		}
#endif

		*undo = malloc(sizeof(struct ethsock_arp_undo));
		if (!*undo) {
			xperror("malloc");
			return -1;
		}

		(*undo)->ipaddr = ipaddr;
		memcpy((*undo)->hwaddr, hwaddr, 6);
	} else {
#if defined(NMRPFLASH_LINUX)
		if (!intf_add_del_arp(sock->intf, ipaddr, hwaddr, false)) {
			return -1;
		}
#elif defined(NMRPFLASH_WINDOWS)
		return DeleteIpNetEntry(&arp) ? 0 : -1;
#else
		return systemf("arp -d %s &> /dev/null", inet_ntoa(addr));
#endif
	}

	return 0;
}

int ethsock_arp_add(struct ethsock *sock, uint8_t *hwaddr, uint32_t ipaddr, struct ethsock_arp_undo **undo)
{
	// remove any previous ARP entry
	ethsock_arp(sock, hwaddr, ipaddr, NULL);
	// add the new ARP entry
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

	return intf_get_hwaddr_and_bridge(dev->name, hwaddr, NULL);
#else
	return intf_get_hwaddr_and_index(dev->name, hwaddr, NULL);
#endif
}

int ethsock_list_all(void)
{
	pcap_if_t *devs, *dev;
	pcap_addr_t *addr;
	uint8_t hwaddr[6];
	unsigned dev_num = 0, dev_ok = 0;
#if defined(NMRPFLASH_WINDOWS)
	char* pretty;
	NET_IFINDEX index;
	MIB_IF_ROW2 row;
#elif defined(NMRPFLASH_MACOS)
	char *pretty;
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
#  ifdef NMRPFLASH_MACOS
		pretty = get_pretty_name(dev->name);
#  endif
#else
		index = intf_get_index(dev->name);

		if (intf_get_if_row(index, &row)) {
			if (!row.InterfaceAndOperStatusFlags.HardwareInterface) {
				if (verbosity) {
					printf("%-15s  (virtual interface)\n", dev->name);
				}
				continue;
			}

			if (row.Alias[0]) {
				pretty = wcs_to_utf8(row.Alias);
			} else {
				pretty = NULL;
			}
		}

		if (index) {
			printf("eth%-2lu", index);
		} else {
			printf("%-15s", dev->name);
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

#if defined(NMRPFLASH_WINDOWS) || defined(NMRPFLASH_MACOS)
		if (pretty) {
			printf("  (%s)", pretty);
			free(pretty);
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

#if !defined(NMRPFLASH_WINDOWS) && !defined(NMRPFLASH_LINUX)
static bool intf_up(int fd, const char *intf, bool up)
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

static int ethsock_ip_add_del(struct ethsock *sock, uint32_t ipaddr, uint32_t ipmask, struct ethsock_ip_undo **undo, bool add)
{
	int ret, fd;

	if (add && undo) {
		if (!(*undo = malloc(sizeof(struct ethsock_ip_undo)))) {
			xperror("malloc");
			return -1;
		}

		(*undo)->ip[0] = ipaddr;
		(*undo)->ip[1] = ipmask;
	} else if (!add && (!undo || !*undo)) {
		return 0;
	}

	ret = -1;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		sock_perror("socket");
		goto out;
	}

#ifndef NMRPFLASH_WINDOWS
#ifdef NMRPFLASH_LINUX
	if (!intf_add_del_ip(sock->intf, (*undo)->ip[0], (*undo)->ip[1], add)) {
		goto out;
	}
#else // NMRPFLASH_MACOS (or any other BSD)
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
		intf_up(fd, ifra.ifra_name, true);
	}

#endif
#else // NMRPFLASH_WINDOWS
	MIB_UNICASTIPADDRESS_ROW row;
	DWORD err;
	int i;

	memset(&row, 0, sizeof(row));

	row.InterfaceIndex = sock->index;
	set_addr(&row.Address.Ipv4, ipaddr);
	row.Address.si_family = AF_INET;

	if (add) {
		row.PrefixOrigin = IpPrefixOriginManual;
		row.SuffixOrigin = IpSuffixOriginManual;
		row.OnLinkPrefixLength = bitcount(ipmask);
		row.SkipAsSource = false;
		row.PreferredLifetime = 0xffffffff;
		row.ValidLifetime = 0xffffffff;
	}

	if (add) {
		err = CreateUnicastIpAddressEntry(&row);
		if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
			win_perror2("CreateUnicastIpAddressEntry", err);
			goto out;
		}

		if (err != ERROR_OBJECT_ALREADY_EXISTS) {
			/* Wait until the new IP has actually been added */
			for (i = 0; i < 20; ++i) {
				err = GetUnicastIpAddressEntry(&row);
				if (err != NO_ERROR) {
					win_perror2("GetUnicastIpAddressEntry", err);
					goto out;
				}

				if (row.DadState == IpDadStateTentative) {
					Sleep(500);
				} else {
					break;
				}
			}

			if (row.DadState == IpDadStateDeprecated) {
				fprintf(stderr, "Warning: IP address marked as deprecated.\n");
			} else if (row.DadState == IpDadStateTentative) {
				fprintf(stderr, "Warning: IP address marked as tentative.\n");
			} else if (row.DadState != IpDadStatePreferred) {
				fprintf(stderr, "Failed to add IP address (state=%d).\n", row.DadState);
				goto out;
			}
		}
	} else {
		err = DeleteUnicastIpAddressEntry(&row);
		if (err != NO_ERROR) {
			win_perror2("DeleteUnicastIpAddressEntry", err);
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

int ethsock_ip_add(struct ethsock *sock, uint32_t ipaddr, uint32_t ipmask, struct ethsock_ip_undo **undo)
{
	return ethsock_ip_add_del(sock, ipaddr, ipmask, undo, true);
}

int ethsock_ip_del(struct ethsock *sock, struct ethsock_ip_undo **undo)
{
	if (!undo || !*undo) {
		return 0;
	}

	int ret;

	if ((*undo)->ip[0] != INADDR_NONE) {
		ret = ethsock_ip_add_del(sock, (*undo)->ip[0], (*undo)->ip[1], undo, false);
	} else {
		ret = 0;
	}

	free(*undo);
	*undo = NULL;
	return ret;
}
