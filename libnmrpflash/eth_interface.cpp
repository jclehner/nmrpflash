#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <net/if.h>
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
	pcap_if_t* list;

	pcap_devlist()
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		if (pcap_findalldevs(&list, errbuf) != 0) {
			throw runtime_error("pcap_findalldevs: "s + errbuf);
		}
	}

	~pcap_devlist()
	{
		pcap_freealldevs(list);
	}
};
}

eth_interface::eth_interface(const string& name)
{
	m_index = name_to_index(name.c_str(), m_pcap_name);

	if (!m_index) {
		throw invalid_argument("no such interface: " + name);
	}
}

eth_interface::~eth_interface()
{

}


vector<ip4_addr> eth_interface::list_ip_addrs() const
{
	vector<ip4_addr> ret;

	with_pcap_if([&ret] (const pcap_if_t& dev) {
		for (auto addr = dev.addresses; addr; addr = addr->next) {
			if (addr->addr->sa_family == AF_INET) {
				ret.push_back(reinterpret_cast<sockaddr_in*>(addr->addr));
			}
		}
	});

	return ret;
}

vector<eth_interface> eth_interface::list()
{
	vector<eth_interface> ret;
	pcap_devlist devs;

	for (auto dev = devs.list; dev; dev = dev->next) {
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

	for (auto dev = devs.list; dev; dev = dev->next) {
		if (dev->name == get_pcap_name()) {
			f(*dev);
			return;
		}
	}

	throw runtime_error("no such pcap device: " + get_pcap_name());
}
}
