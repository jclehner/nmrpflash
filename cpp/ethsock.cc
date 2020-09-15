/**
 * nmrpflash - Netgear Unbrick Utility
 * Copyright (C) 2016-2020 Joseph Lehner <joseph.c.lehner@gmail.com>
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
#if 0
#include <netlink/route/addr.h>
#endif
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fstream>
#include <cstdarg>
#include "ethsock.h"

#if BOOST_OS_LINUX
#include <linux/if_packet.h>
#endif
using namespace std;

namespace nmrpflash {
namespace {

struct eth_header
{
	uint8_t dest[6];
	uint8_t src[6];
	uint16_t proto;
} __attribute__((packed));

class pcap_devices
{
	pcap_if_t* m_devs = nullptr;

	public:
	pcap_devices()
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		if (pcap_findalldevs(&m_devs, errbuf) != 0) {
			throw runtime_error(errbuf);
		}
	}

	~pcap_devices()
	{
		pcap_freealldevs(m_devs);
	}

	list<const pcap_if_t*> get() const
	{
		list<const pcap_if_t*> ret;
		for (pcap_if_t* dev = m_devs; dev; dev = dev->next) {
			ret.push_back(dev);
		}

		return ret;
	}

	const pcap_if_t* get(const string& intf)
	{
		for (pcap_if_t* dev = m_devs; dev; dev = dev->next) {
			if (dev->name == intf) {
				return dev;
			}
		}

		throw invalid_argument("No such interface: " + intf);
	}
};

void check_mac_addr(const mac_addr& mac)
{
	if (mac == mac_addr::none || mac == mac_addr::broadcast) {
		throw invalid_argument("Invalid MAC address: " + stringify(mac));
	}
}

void check_ip_addr(const ip_addr& ip)
{
	if (!ip || ip == ip_addr(255, 255, 255, 255)) {
		throw invalid_argument("Invalid IP address: " + stringify(ip));
	}
}

#if BOOST_OS_WINDOWS
GUID guid_from_str(const string& str)
{
	GUID guid;
	int n;

	sscanf(str.c_str(),
			"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X%n",
			&guid.Data1, &guid.Data2, &guid.Data3,
			&guid.Data4[0], &guid.Data4[1], &guid.Data4[2],
			&guid.Data4[3], &guid.Data4[4], &guid.Data4[5],
			&guid.Data4[6], &guid.Data4[7], &n);

	if (n != 36) {
		throw invalid_argument("Not a valid GUID: " + str);
	}

	return ret;

}

string guid_to_str(const GUID& guid)
{
	string ret('\0', 37);
	snprintf(&ret[0], ret.size(),
			"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
			guid.Data1, guid.Data2, guid.Data3,
			guid.Data4[0], guid.Data4[1], guid.Data4[2],
			guid.Data4[3], guid.Data4[4], guid.Data4[5],
			guid.Data4[6], guid.Data4[7]);

	return ret;
}

void get_if_entry(MIB_IF_ROW2* row, NET_IFINDEX index)
{
	memset(row, 0, sizeof(*row));
	row->InterfaceIndex = index;

	DWORD err = GetIfEntry2(row);
	if (err) {
		throw winapi_error("GetIfEntry2", err);
	}
}
#elif BOOST_OS_LINUX
bool linux_sys_read_b(const string& intf, const string& file, bool defval)
{
	ifstream in((boost::format("/sys/class/net/%s/%s") % intf % file).str().c_str());
	return in ? (in.get() == '1') : defval;
}
#endif

#if 0
#if defined(NMRPFLASH_LINUX) && false
auto create_nl_route_socket()
{
	auto sock = wrap_unique(nl_socket_alloc(), &nl_socket_free);
	if (sock) {
		if (nl_connect(sock.get(), NETLINK_ROUTE) != 0) {
			throw libnl_error("nl_connect");
		}

		return sock;
	} else {
		throw libnl_error("nl_socket_alloc");
	}
}

auto build_nl_ip(const ip_addr& ip)
{
	uint32_t raw = ip.to_uint();
	auto ret = wrap_unique(nl_addr_build(AF_INET, &raw, 4), &nl_addr_put);
	if (!ret) {
		throw libnl_error("nl_addr_build");
	}

	if (ip.pfxlen()) {
		nl_addr_set_prefixlen(ret.get(), ip.pfxlen());
	}

	return ret;
}
#endif
static int systemf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static int systemf(const char* fmt, ...)
{
	va_list va;
	va_start(va, fmt);

	char cmd[1024];
	int n = vsnprintf(cmd, sizeof(cmd), fmt, va);
	if (n >= sizeof(cmd)) {
		return -1;
	}

	int ret = system(cmd);
	va_end(va);

	return ret;
}
#endif

#if !BOOST_OS_WINDOWS && !BOOST_OS_LINUX
static void bsd_set_intf_up(const string& intf, bool up, int fd = -1)
{
	scoped_fd sfd;

	if (fd == -1) {
		sfd.reset(xsocket(AF_INET, SOCK_DGRAM, 0));
		fd = *sfd;
	}

	struct ifreq ifr;
	strncpy(ifr.ifr_name, intf.c_str(), IFNAMSIZ);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
		throw errno_error("ioctl(SIOCGIFFLAGS)");
	}

	if (!up) {
		ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
	} else {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	}

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
		throw errno_error("ioctl(SIOCSIFFLAGS)");
	}
}
#endif
}

eth_interface::eth_interface(const string& intf)
{
	init_from_name(intf);

	pcap_devices devs;
	init_from_pcap(devs.get(m_name));
}

eth_interface::eth_interface(const pcap_if_t* dev)
{
	init_from_name(dev->name);
	init_from_pcap(dev);
}

eth_interface::~eth_interface()
{
	try {
		for (auto ip : m_undo_ip) {
			del_ip(ip);
		}

		for (auto arp : m_undo_arp) {
			del_arp(arp.first);
		}
	} catch (const exception& e) {
		// yum!
	}
}

void eth_interface::init_index(const string& intf)
{
	m_index = if_nametoindex(intf.c_str());
	if (!m_index) {
		throw invalid_argument("Interface does not exist: " + intf);
	}
}

void eth_interface::init_from_name(const string& intf)
{
	// On Windows, `intf` might be either the pcap name, which is
	// `\Device\NPF_{GUID}`, or the ANSI interface name!

#if !BOOST_OS_WINDOWS
	m_name = intf;
	init_index(intf);
#else
	if (intf.find("\\Device\\NPF_{") == string::npos) {
		if (intf.find("net") == 0 && intf.find('_') == string::npos) {
			m_index = stoi(intf.substr(3));
		} else {
			init_index(intf);
		}

		DWORD err = ConvertInterfaceIndexToLuid(m_index, &m_luid);
		if (err) {
			throw winapi_error("ConvertInterfaceIndexToLuid", err);
		}

		err = ConvertInterfaceLuidToGuid(index, &m_guid);
		if (err) {
			throw winapi_error("ConvertInterfaceLuidToGuid", err);
		}

		m_name = "\\Device\\NPF_{" + guid_to_str(m_guid) + "}";
	} else {
		m_name = intf;
		m_guid = guid_from_str(intf.substr(13, 36));

		DWORD err = ConvertInterfaceGuidToLuid(&guid, &m_luid);
		if (err) {
			throw winapi_error("ConvertInterfaceGuidToLuid", err);
		}

		err = ConvertInterfaceLuidToIndex(&m_luid, &m_index);
		if (err) {
			throw winapi_error("ConvertInterfaceGuidToLuid", err);
		}
	}
#endif
}

void eth_interface::init_from_pcap(const pcap_if_t* dev)
{
#if !BOOST_OS_WINDOWS
	for (pcap_addr_t* addr = dev->addresses; addr; addr = addr->next) {
		if (addr->addr->sa_family == AF_PACKET) {
			void* src;
#if BOOST_OS_LINUX
			src = reinterpret_cast<sockaddr_ll*>(addr->addr)->sll_addr;
#else
			src = LLADDR(reinterpret_cast<sockaddr_dl*>(addr->addr));
#endif
			m_mac = mac_addr(src);
			return;
		}
	}

	throw runtime_error("Failed to get hwaddr of interface");
#else
	MIB_IF_ROW2 row;
	get_if_entry(&row, m_index);
	memcpy(m_mac, row.PhysicalAddress, sizeof(m_mac));

	char ansi[IF_NAMESIZE];
	m_ansi = if_indextoname(m_index, ansi);
	m_alias = row.Alias;
#endif
}

bool eth_interface::is_unplugged() const
{
#if BOOST_OS_WINDOWS
	MIB_IF_ROW2 row;
	get_if_entry(&row, m_index);
	return row.InterfaceAndOperStatusFlags.NotMediaConnected;
#elif BOOST_OS_LINUX
	return !linux_sys_read_b(m_name, "carrier", true);
#else
	return false;
#endif
}

void eth_interface::add_del_ip(const ip_addr& ip, bool add)
{
	check_ip_addr(ip);

	boost::format cmd;

#if BOOST_OS_WINDOWS
	if (add) {
		cmd = boost::format("netsh interface add address %s addr=%s mask=%s gateway=0.0.0.0")
				% quote(m_alias) % stringify(ip.address()) % stringify(ip.netmask());
	} else {
		cmd = boost::format("netsh interface delete address %s addr=%s")
				% quote(m_alias) % stringify(ip.address());
	}
#elif BOOST_OS_LINUX
	cmd = boost::format("ip address %s %s dev %s") % (add ? "add" : "del")
			% stringify(ip) % quote(m_name);
#else
	cmd = boost::format("ifconfig %s inet %s netmask %s %s") % quote(m_name)
			% stringify(ip.address()) % stringify(ip.netmask()) % (add ? "add" : "delete");
#endif

	run(cmd.str(), add);

#if 0
#if defined(NMRPFLASH_WINDOWS)
	MIB_UNICASTIPADDRESS_ROW row;
	memset(&row, 0, sizeof(row));

	row.InterfaceIndex = m_index;
	row.PrefixOrigin = IpPrefixOriginManual;
	row.SuffixOrigin = IpPrefixOriginManual;
	row.OnLinkPrefixLength = pfix;
	row.SkipAsSource = false;
	row.PreferredLifetime = 0xffffffff;
	row.ValidLifetime = 0xffffffff;
	ip.apply_to(row.Address.Ipv4);

	if (add) {
		DWORD err = CreateUnicastIpAddressEntry(&row);
		if (err && err != ERROR_OBJECT_ALREADY_EXISTS) {
			throw winapi_error("CreateUnicastIpAddressEntry", err);
		}
	} else {
		DWORD err = DeleteUnicastIpAddressEntry(&row);
		if (err) {
			log::d("DeleteUnicastIpAddressEntry: %d", err);
		}
	}
#elif defined(NMRPFLASH_LINUX)
	auto ra = wrap_unique(rtnl_addr_alloc(), rtnl_addr_put);
	if (!ra) {
		throw libnl_error("rtnl_addr_alloc");
	}

	rtnl_addr_set_ifindex(ra.get(), m_index);
	rtnl_addr_set_local(ra.get(), build_nl_ip(ip).get());
	rtnl_addr_set_broadcast(ra.get(), build_nl_ip(ip.broadcast()).get());

	auto sk = create_nl_route_socket();

	int err = add ? rtnl_addr_add(*sk, *ra, 0) : rtnl_addr_delete(*sk, *ra, 0);
	if (add) {
		if (err && err != -NLE_EXIST) {
			throw libnl_error("rtnl_addr_add");
		}
	} else if (err) {
		log::d("rtnl_addr_delete: %d", err);
	}
#else // NMRPFLASH_OSX (or any other BSD)
	struct ifaliasreq ifra;
	memset(&ifra, 0, sizeof(ifra));
	strncpy(ifra.ifra_name, m_name.c_str(), IFNAMSIZ);
	ip.apply_to(ifra.ifra_addr);
	ip.netmask().apply_to(ifra.ifra_mask);

	scoped_fd fd(xsocket(AF_INET, SOCK_DGRAM, 0);

	if (ioctl(*fd, add ? SIOCAIFADDR : SIOCDIFADDR, &ifra) != 0) {
		if (add) {
			throw errno_error("ioctl(SIOCAIFADDR");
		} else {
			log::d("ioctl(SIOCDIFADDR): %d", errno);
		}
	}

	bsd_set_intf_up(m_name, true, *fd);
#endif
#endif

	if (add) {
		m_undo_ip.insert(ip);
	} else {
		m_undo_ip.erase(ip);
	}
}

void eth_interface::add_del_arp(const mac_addr& mac, const ip_addr& ip, bool add)
{
#if 0
#if defined(NMRPFLASH_WINDOWS)
	MIB_IPNETROW arp = {
		.dwIndex = m_index,
		.dwPhysAddrLen = sizeof(mac),
		.dwAddr = ip,
		.dwType = MIB_IPNET_TYPE_STATIC,
	};

	mac.apply_to(&arp.bPhysAddr);

	DWORD err = add ? CreateIpNetEntry(&arp) : DeleteIpNetEntry(&arp);
	if (err)
		throw winapi_error(add ? "CreateIpNetEntry" : "DelteIpNetEntry", err);
	}
#elif defined(NMRPFLASH_LINUX)
	arpreq arp;
	memset(&arp, 0, sizeof(arp));
	arp.arp_ha.sa_family = ARPHRD_ETHER;
	arp.arp_flags = ATF_PERM | ATF_COM;
	mac.apply_to(&arp.arp_ha.sa_data);
	ip.apply_to(&arp.arp_pa);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		throw errno_error("socket");
	}

	bool err = (ioctl(fd, add ? SIOCSARP : SIOCDARP, &req) < 0);
	close(fd);

	if (err) {
		throw errno_error(add ? "ioctl(SIOCSARP)" : "ioctl(SIOCDARP)");
	}
#else
#endif
#endif

	boost::format cmd;

	if (add) {
#if BOOST_OS_WINDOWS
		cmd = boost::format("netsh add neighbors interface=%s address=%s neighbor=%s store=active"
				% quote(m_alias) % stringify(ip.address()) % mac.to_string('-');
#else
		cmd = boost::format("arp -s %s %s") % stringify(ip.address()) % stringify(mac);
#endif
	} else {
#if BOOST_OS_WINDOWS
		cmd = boost::format("netsh delete neighbors interface=%s address=%s")
				% quote(m_alias) % stringify(ip.address()));
#else
		cmd = boost::format("arp -d %s") % stringify(ip.address());
#endif
	}

	run(cmd.str(), add);

	if (add) {
		m_undo_arp[ip] = mac;
	} else {
		m_undo_arp.erase(ip);
	}
}

list<eth_interface> eth_interface::all()
{
	list<eth_interface> ret;
	pcap_devices devs;

	for (auto dev : devs.get()) {
		ret.emplace_back(dev);
	}

	return ret;
}


eth_sock::eth_sock(eth_interface& iface, uint16_t proto)
: m_iface(iface), m_proto(proto), m_timeout(0), m_stp_enabled(iface.is_stp_enabled())
{
	char errbuf[PCAP_ERRBUF_SIZE];
	m_pcap = pcap_open_live(iface.name().c_str(), BUFSIZ, 1, 1, errbuf);
	if (!m_pcap) {
		throw runtime_error(errbuf);
	} else if (*errbuf) {
		log::w(errbuf);
	}

	try {
		init();
	} catch (const exception& e) {
		shutdown();
		throw e;
	}
}

void eth_sock::send(const string& buf, const mac_addr& dest)
{
	send(buf.data(), buf.size(), dest);
}

void eth_sock::send(const void* data, size_t size, const mac_addr& dest)
{
	size += sizeof(eth_header);
	auto pkt = make_unique<char[]>(size);
	auto hdr = reinterpret_cast<eth_header*>(pkt.get());
	m_iface.hwaddr().apply_to(hdr->src);
	hdr->proto = htons(m_proto);

	if (m_peer == mac_addr::none) {
		dest.apply_to(hdr->dest);
	} else {
		m_peer.apply_to(hdr->dest);
	}

#if BOOST_OS_WINDOWS
	if (pcap_sendpacket(m_pcap, pkt.get(), size) != 0) {
		throw pcap_error("pcap_sendpacket", m_pcap);
	}
#else
	if (pcap_inject(m_pcap, pkt.get(), size) != size) {
		throw pcap_error("pcap_inject", m_pcap);
	}
#endif
}

std::string eth_sock::recv(unsigned timeout, mac_addr* src)
{
	if (!timeout) {
		timeout = m_timeout;
	}

	if (timeout) {
#if BOOST_OS_WINDOWS
		DWORD ret = WaitForSingleObject(m_handle, timeout);
		if (ret == WAIT_TIMEOUT) {
			return pkt::empty();
		} else if (ret != WAIT_OBJECT_0) {
			throw winapi_error("WaitForSingleObject", ret);
		}
#else
		if (!select_readfd(m_fd, timeout)) {
			return {};
		}
#endif
	}

	pcap_pkthdr* hdr;
	const u_char* buf;

	int status = pcap_next_ex(m_pcap, &hdr, &buf);
	if (!status) {
		return {};
	} else if (status == PCAP_ERROR) {
		throw pcap_error("pcap_next_ex", m_pcap);
	} else if (status != 1) {
		throw runtime_error("pcap_next_ex: error " + to_string(status));
	} else if (hdr->caplen < sizeof(eth_header)) {
		throw runtime_error("Received short packet: " + to_string(hdr->caplen) + "b");
	}

	if (src) {
		*src = mac_addr(&buf[6]);
	}

	return string(reinterpret_cast<const char*>(buf + 14), hdr->caplen - 14);
}

void eth_sock::init()
{
	if (pcap_datalink(m_pcap) != DLT_EN10MB) {
		throw invalid_argument("Not an Ethernet interface: " + m_iface.name());
	}

#if BOOST_OS_WINDOWS
	m_handle = pcap_getevent(m_pcap);
	if (!m_handle) {
		throw pcap_error("pcap_getevent", m_pcap);
	}

	if (pcap_setmintocopy(m_pcap, 1) != 0) {
		throw pcap_error("pcap_setmintocopy", m_pcap);
	}

#else
	m_fd = pcap_get_selectable_fd(m_pcap);
	if (m_fd == -1) {
		throw pcap_error("pcap_get_selectable_fd", m_pcap);
	}
#endif

	bpf_program bpf;

	string filter = (boost::format("ether proto 0x%04x and not ether src %s")
			% m_proto % stringify(m_iface.hwaddr())).str();

	if (pcap_compile(m_pcap, &bpf, filter.c_str(), 0, 0) != 0) {
		throw pcap_error("pcap_compile", m_pcap);
	}

	int err = pcap_setfilter(m_pcap, &bpf);
	pcap_freecode(&bpf);

	if (err) {
		throw pcap_error("pcap_setfilter", m_pcap);
	}

	m_iface.enable_stp(false);
}

void eth_sock::shutdown()
{
	if (m_pcap) {
		pcap_close(m_pcap);
		m_pcap = nullptr;

		m_iface.enable_stp(m_stp_enabled);
	}
}
}
