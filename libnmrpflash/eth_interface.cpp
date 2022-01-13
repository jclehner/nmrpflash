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

	static void visit(const eth_interface& intf, function<void(const pcap_if_t&)> f)
	{
		pcap_devlist list;

		for (auto dev = list.raw; dev; dev = dev->next) {
			if (dev->name == intf.get_pcap_name()) {
				f(*dev);
				return;
			}
		}

		throw runtime_error("no such pcap device: " + intf.get_pcap_name());
	}

	~pcap_devlist() { pcap_freealldevs(raw); }
};

#if !BOOST_OS_WINDOWS
struct if_addrs
{
#if BOOST_OS_LINUX
	typedef uint8_t mac_byte_type;
#else
	typedef char mac_byte_type;
#endif

	ifaddrs* raw;

	if_addrs()
	{
		if (getifaddrs(&raw) != 0) {
			throw runtime_error("getifaddrs: "s + strerror(errno));
		}
	}

	static mac_byte_type* get_mac_addr(ifaddrs* ifa)
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
struct adapter_info
{
	unique_ptr<IP_ADAPTER_ADDRESSES, void(*)(IP_ADAPTER_ADDRESSES*)> addrs;
	MIB_IF_ROW2 row;

	if_info(DWORD index)
	{
		memset(&row, 0, sizeof(row));
		row.InterfaceIndex = index;

		if (!GetIfEntry2(&row)) {
			throw winapi_error("GetIfEntry2");
		}

		ULONG size = 0;
		ULONG flags = GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | 
			GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_INCLUDE_GATEWAYS;

		auto err = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, &size);
		if (err != ERROR_BUFFER_OVERFLOW) {
			throw winapi_error("GetAdaptersAddresses");
		}

		// just to be on the safe side, in case things change in between the two calls.
		size += 1024;

		addrs = { reinterpret_cast<IP_ADAPTER_ADDRESSES*>(malloc(size)), [](IP_ADAPTER_ADDRESSES* p) {
			free(p);
		}};

		err = GetAdaptersAddresses(AF_UNSPEC, flags, addrs.get(), &size);
		if (err) {
			throw winapi_error("GetAdaptersAddresses");
		}

	}

	void visit(DWORD index, std::function<void(IP_ADAPTER_ADDRESSES*>)> f)
	{
		for (auto addrs = addrs.get(); addrs; addrs = addrs->Next) {
			if (addrs->Index == index) {
				f(addrs);
				return;
			}
		}

		throw invalid_argument("invalid adapter index " + to_string(index));
	}
};
#endif

#if BOOST_OS_MACOS
typedef cf_ref<CFDictionaryRef> cf_dict_ref;

cf_dict_ref plist_open_as_dict(const string& filename)
{
	auto url = make_cf_ref(CFURLCreateFromFileSystemRepresentation(
				kCFAllocatorDefault, reinterpret_cast<const UInt8*>(filename.c_str()),
				filename.size(), false));
	if (!url) {
		throw runtime_error("CFURLCreateFromFileSystemRepresentation: " + filename);
	}

	auto stream = make_cf_ref(CFReadStreamCreateWithFile(kCFAllocatorDefault, url.get()));
	if (!stream) {
		throw runtime_error("CFReadStreamCreateWithFile: " + filename);
	}

	if (!CFReadStreamOpen(stream.get())) {
		throw runtime_error("CFReadStreamOpen: " + filename);
	}

	auto plist = make_cf_ref(CFPropertyListCreateWithStream(kCFAllocatorDefault, stream.get(), 0,
			kCFPropertyListImmutable, NULL, NULL));
	CFReadStreamClose(stream.get());
	if (!plist) {
		throw runtime_error("CFPropertyListCreateWithStream: " + filename);
	}

	return plist.as<CFDictionaryRef>();
}

void cf_dict_for_each(const cf_ref<CFDictionaryRef>& dict, function<void(const string&, const cf_ref<CFTypeRef>&)> f)
{
	typedef decltype(&f) F;
	CFDictionaryApplyFunction(dict.get(), [](const void* key, const void* value, void* applier) {
		reinterpret_cast<F>(applier)->operator()(
				from_cf_string(cf_cast<CFStringRef>(key)),
				make_cf_view(reinterpret_cast<CFTypeRef>(value)));
	}, &f);
}

template<typename T> cf_ref<T> cf_dict_get(const cf_ref<CFDictionaryRef>& dict, const string& key)
{
	const void* value;

	if (!CFDictionaryGetValueIfPresent(dict.get(), to_cf_string(key).get(), &value) || !value) {
		throw out_of_range("no such key: " + key);
	}

	return make_cf_view(cf_cast<T>(value));
}

string get_macos_pretty_name(const string& device)
{
	try {
		string pretty;
		auto prefs = plist_open_as_dict("/Library/Preferences/SystemConfiguration/preferences.plist");
		auto services = cf_dict_get<CFDictionaryRef>(prefs, "NetworkServices");

		// loop through each NetworkService. The key is a UUID here, but we're only interested in the
		// sub-dictionary "Interface" here, which contains the "DeviceName" and "UserDefinedName" keys.
		cf_dict_for_each(services, [&device, &pretty](const string& key, const cf_ref<CFTypeRef>& value) {
			if (!pretty.empty()) {
				return;
			}

			auto interface = cf_dict_get<CFDictionaryRef>(value.as<CFDictionaryRef>(), "Interface");
			auto cf_device = from_cf_string(cf_dict_get<CFStringRef>(interface, "DeviceName"));
			if (device == cf_device) {
				pretty = from_cf_string(cf_dict_get<CFStringRef>(interface, "UserDefinedName"));
			}
		});

		return pretty;
	} catch (const exception& e) {
		return "";
	}
}
#endif
}

eth_interface::eth_interface(const string& name)
{
	m_index = name_to_index(name.c_str(), m_pcap_name);

	if (!m_index) {
		throw invalid_argument("no such interface: " + name);
	}

	pcap_devlist::visit(*this, [&] (const pcap_if_t& dev) {
		if (dev.flags & PCAP_IF_LOOPBACK) {
			throw invalid_argument("loopback device: " + name);
		}
	});

#if !BOOST_OS_WINDOWS
	if_addrs addrs;

	for (auto ifa = addrs.raw; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_name == name) {
			auto* raw = if_addrs::get_mac_addr(ifa);
			if (raw) {
				m_mac_addr = mac_addr::from_raw(raw);
#if BOOST_OS_LINUX
				m_is_bridge = (access(("/sys/class/net/" + name + "/bridge").c_str(), F_OK) == 0);
				m_pretty_name = nm_get_connection(name);
#else
				m_is_bridge = (reinterpret_cast<if_data*>(ifa->ifa_data)->ifi_type == IFT_BRIDGE);
#if BOOST_OS_MACOS
				m_pretty_name = get_macos_pretty_name(name);
#endif
#endif
				return;
			}
		}
	}

	throw invalid_argument("not an Ethernet interface: " + name);
#else
	adapter_info info;
	if (!info.row.InterfaceAndOperStatusFlags.HardwareInterface) {
		throw invalid_argument("not a hardware interface: " + name);
	}

	info.visit(m_index, [&](IP_ADAPTER_ADDRESSES* a) {
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

string eth_interface::get_name() const
{
#if !BOOST_OS_WINDOWS
	return m_pcap_name;
#else
	char buf[IF_NAMESIZE];
	return if_indextoname(m_index, buf);
#endif
}

vector<ip_net> eth_interface::list_networks(bool ipv4_only) const
{
	vector<ip_net> ret;

	pcap_devlist::visit(*this, [&] (const pcap_if_t& dev) {
		for (auto addr = dev.addresses; addr; addr = addr->next) {
			if (ipv4_only && addr->addr->sa_family != AF_INET) {
				continue;
			}
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
}
