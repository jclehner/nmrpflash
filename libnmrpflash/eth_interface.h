#ifndef NMRPFLASH_ETH_INTERFACE
#define NMRPFLASH_ETH_INTERFACE
#include <boost/predef.h>
#include <string>
#include <pcap.h>
#include <vector>
#include <map>
#include <set>
#include "address.h"

namespace nmrpflash {

///! An Ethernet interface.
//
//
//
//

class eth_interface
{
	public:
#if !BOOST_OS_WINDOWS
	typedef unsigned index_type;
	typedef std::string pretty_type;
#else
	typedef DWORD index_type;
	typedef std::wstring pretty_type;
#endif

	/**
	 * Constructs an interface from a given name.
	 *
	 * On POSIX systems, this is a device name
	 * such as `en0`, or `eth2`, etc.
	 *
	 * On Windows, this can be any of the following:
	 *  * ANSI interface name
	 *  * Interface GUID
	 *  * Npcap/WinPCAP name (`\Device\NPF_<GUID>`)
	 */
	eth_interface(const std::string& name);
	eth_interface(const pcap_if_t* intf);

	~eth_interface();

	/// Returns this interface's MAC address.
	const mac_addr& get_mac_addr() const { return m_mac_addr; }
	/// Returns this interface's interface index.
	index_type get_index() const { return m_index; }
	/// Returns a name that can be passed to `pcap_open_live`.
	const std::string& get_pcap_name() const { return m_pcap_name; }

	/**
	 * Returns a short, human readable name.
	 *
	 * On POSIX, this is the device name, while
	 * on Windows it's the ANSI device name.
	 */
	std::string get_name() const;

	/**
	 * Returns a less technical name.
	 *
	 * On Linux, returns NetworkManager's `GENERAL.CONNECTION` attribute,
	 * if this device is being managed by NetworkManager. Otherwise
	 * an empty string.
	 *
	 * On Windows, returns the name used in the Control Panel/Settings,
	 * and by the `ipconfig` utility.
	 *
	 * On macOS, returns the interface name used by System Preferences.
	 */
	const std::string& get_pretty_name() const { return m_pretty_name; }

	/// Returns a list of this interface's IP addresses.
	std::vector<ip_net> list_networks(bool ipv4_only = false) const;

	/**
	 * Adds an IPv4 address to this interface.
	 *
	 * If `permanent` is `false`, the address is removed when the
	 * `eth_interface` object is destroyed.
	 */
	void add_ip_addr(const ip4_addr& addr, bool permanent = false);
	void del_ip_addr(const ip4_addr& addr);

	/**
	 * Adds an entry to the device's ARP table.
	 *
	 * If `permanent` is `false`, the mapping is removed, when the
	 * `eth_interface` object is destroyed.
	 */
	void add_arp_entry(const mac_addr& mac, const ip4_addr& ip, bool permanent = false);

	void del_arp_entry(const mac_addr& mac);

	static std::vector<eth_interface> list();

	private:
	void with_pcap_if(std::function<void(const pcap_if_t&)> f) const;

	index_type m_index;
	mac_addr m_mac_addr;
	bool m_is_bridge = false;

	std::string m_pcap_name;
	pretty_type m_pretty_name;

	std::set<ip4_addr> m_ip_undo;
	std::map<mac_addr, ip4_addr> m_arp_undo;
};
}
#endif

