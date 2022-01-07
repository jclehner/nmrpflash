#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <net/if.h>
#if !BOOST_OS_WINDOWS
#include <sys/types.h>
#include <ifaddrs.h>
#endif
#include "eth_interface.h"

using namespace std;

namespace nmrpflash {
namespace {
eth_interface::index_type name_to_index(string name, string& pcap_name)
{
	auto index = if_nametoindex(name.c_str());
#if BOOST_OS_WINDOWS
	if (!index) {
		// it's not an ANSI interface name, but it could still
		// be a GUID, or pcap device name.
		
		const std::string pcap_prefix = "\\Device\\NPF_";
		if (boost::starts_with(name, pcap_prefix)) {
			name = name.substr(pcap_prefix.size());
		}

		GUID guid;
		if (CLSIDFromString(name.c_str(), &guid) != NOERROR) {
			return 0;
		}

		NET_LUID luid;
		auto err = ConvertInterfaceGuidToLuid(&guid, &luid);
		if (err) {
			return 0;
		}

		pcap_name = pcap_prefix + name;

		err = ConvertInterfaceLuidToIndex(&luid, &index);
		if (err) {
			return 0;
		}
	}
#else
	pcap_name = name;
#endif
	return index;
}

struct pcap_devlist
{
	pcap_if_t* raw;

	pcap_devlist()
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		if (pcap_findalldevs(&raw, errbuf) != 0) {
			throw runtime_error("pcap_findalldevs: "s + errbuf);
		}
	}

	~pcap_devlist() { pcap_freealldevs(raw); }
};

#if !BOOST_OS_WINDOWS
struct if_addrs
{
	ifaddrs* raw;

	if_addrs()
	{
		if (getifaddrs(&raw) != 0) {
			throw runtime_error("getifaddrs: "s + strerror(errno));
		}
	}

	static uint8_t* get_mac_addr(ifaddrs* ifa)
	{
		if (!ifa || !ifa->ifa_addr) {
			return nullptr;
		}

#if BOOST_OS_LINUX
		sockaddr_ll* sll = reinterpret_cast<sockaddr_ll*>(ifa->ifa_addr);
		if (sll->sll_family == AF_PACKET) {
			return sll->sll_addr;
		}
#else
		sockaddr_dl* sdl = reinterpret_cast<sockaddr_dl*>(ifa->ifa_addr);
		if (sdl->sdl_family == AF_LINK && sdl->sdl_type == IFT_ETHER) {
			return LLADDR(sdl);
		}
#endif

		return nullptr;
	}

	~if_addrs()
	{
		freeifaddrs(raw);
	}
};
#else
struct adapters_addrs
{
	unique_ptr<IP_ADAPTER_ADDRESSES, void(*)(IP_ADAPTER_ADDRESSES*)> raw;

	if_info(DWORD index)
	{
		ULONG size = 0;
		ULONG flags = GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | 
			GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_INCLUDE_GATEWAYS;

		auto err = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, &size);
		if (err != ERROR_BUFFER_OVERFLOW) {
			throw winapi_error("GetAdaptersAddresses");
		}

		// just to be on the safe side, in case things change in between the two calls.
		size += 1024;

		raw = { reinterpret_cast<IP_ADAPTER_ADDRESSES*>(malloc(size)), [](IP_ADAPTER_ADDRESSES* p) {
			free(p);
		}};

		err = GetAdaptersAddresses(AF_UNSPEC, flags, raw.get(), &size);
		if (err) {
			throw winapi_error("GetAdaptersAddresses");
		}

	}

	void visit(DWORD index, std::function<void(IP_ADAPTER_ADDRESSES*>)> f)
	{
		for (auto addrs = raw.get(); addrs; addrs = addrs->Next) {
			if (addrs->Index == index) {
				f(addrs);
				return;
			}
		}

		throw invalid_argument("invalid adapter index " + to_string(index));
	}
};
#endif
}

eth_interface::eth_interface(const string& name)
{
	m_index = name_to_index(name.c_str(), m_pcap_name);

	if (!m_index) {
		throw invalid_argument("no such interface: " + name);
	}

#if !BOOST_OS_WINDOWS
	if_addrs addrs;

	for (auto ifa = addrs.raw; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_name == name) {
			auto* raw = if_addrs::get_mac_addr(ifa);
			if (raw) {
				m_mac_addr = mac_addr::from_raw(raw);
#if BOOST_OS_LINUX
				m_is_bridge = (access(("/sys/class/net/" + name + "/bridge").c_str(), F_OK) == 0);
#else
				m_is_bridge = (reinterpret_cast<if_data*>(a->ifa_data)->ifi_type == IFT_BRIDGE);
#endif
				return;
			}
		}
	}

	throw invalid_argument("not an Ethernet interface: " + name);
#else
	adapters_addrs addrs;
	addrs.visit(m_index, [&](IP_ADAPTER_ADDRESSES* a) {
		if (a->IfType != IF_TYPE_ETHERNET_CSMACD && a->IfType != IF_TYPE_IEEE80211) {
			throw invalid_argument("not an Ethernet interface: " + name);
		} else if (a->PhysicalAdressLength != mac_addr::length) {
			throw runtime_error("unexpected address size: " + to_string(a->PhysicalAdressLength));
		}

		m_mac_addr = mac_addr::from_raw(a->PhysicalAddress);
		m_pretty_name = a->FriendlyName;
		// TODO how to detect a bridge interface on Windows?
	});
#endif
}

eth_interface::~eth_interface()
{

}

vector<ip_net> eth_interface::list_networks() const
{
	vector<ip_net> ret;

	with_pcap_if([&ret] (const pcap_if_t& dev) {
		for (auto addr = dev.addresses; addr; addr = addr->next) {
			try {
				ret.push_back({ ip_from_sockaddr(addr->addr), ip_from_sockaddr(addr->netmask) });
			} catch (const invalid_argument&) {
				// ignore
			}
		}
	});

	return ret;
}

vector<eth_interface> eth_interface::list()
{
	vector<eth_interface> ret;
	pcap_devlist devs;

	for (auto dev = devs.raw; dev; dev = dev->next) {
		try {
			ret.push_back({ dev->name });
		} catch (const exception& e) {
			// yummy!
		}
	}

	return ret;
}

void eth_interface::with_pcap_if(const function<void(const pcap_if_t&)> f) const
{
	pcap_devlist devs;

	for (auto dev = devs.raw; dev; dev = dev->next) {
		if (dev->name == get_pcap_name()) {
			f(*dev);
			return;
		}
	}

	throw runtime_error("no such pcap device: " + get_pcap_name());
}
}
