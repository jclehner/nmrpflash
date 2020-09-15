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
#ifndef NMRPFLASH_ETHSOCK_H
#define NMRPFLASH_ETHSOCK_H
#include <list>
#include <map>
#include <set>
#include <pcap.h>
#include "util.h"

namespace nmrpflash {
class eth_interface
{
	// interface name, suitable for pcap_open*
	std::string m_name;
	mac_addr m_mac;

#ifdef NMRPFLASH_LINUX
	bool m_stp_enabled;
#endif

#ifdef NMRPFLASH_WINDOWS
	std::string m_ansi;
	std::wstring m_alias;
	NET_IFINDEX m_index;
	NET_LUID m_luid;
	GUID m_guid;
#else
	unsigned m_index;
#endif

	std::map<ip_addr, mac_addr> m_undo_arp;
	std::set<ip_addr> m_undo_ip;

	public:
	eth_interface(const std::string& intf);
	eth_interface(const pcap_if_t* dev);
	~eth_interface();

	void add_ip(const ip_addr& ip)
	{ add_del_ip(ip, true); }

	void del_ip(const ip_addr& ip)
	{ add_del_ip(ip, false); }

	void add_arp(const mac_addr& mac, const ip_addr& ip)
	{ add_del_arp(mac, ip, true); }

	void del_arp(const ip_addr& ip)
	{ add_del_arp(mac_addr(), ip, false); }

	bool is_unplugged() const;

#ifdef NMRPFLASH_LINUX
	bool is_stp_enabled() const
	{ return m_stp_enabled; }

	void enable_stp(bool enable);
#else
	bool is_stp_enabled() const
	{ return false; }

	void enable_stp(bool enable)
	{}
#endif

	const std::string& name() const
	{ return m_name; }

	const mac_addr& hwaddr() const
	{ return m_mac; }

#ifdef NMRPFLASH_WINDOWS
	const std::string& ansi() const
	{ return m_ansi_name; }

	const std::wstring& alias() const
	{ return m_pretty_name; }

	DWORD index() const
	{ return m_index; }
#endif

	static std::list<eth_interface> all();

	private:
	void add_del_ip(const ip_addr& ip, bool add);
	void add_del_arp(const mac_addr& mac, const ip_addr& ip, bool add);

	void init_index(const std::string& intf);
	void init_from_pcap(const pcap_if_t* dev);
	void init_from_name(const std::string& intf);
};

class eth_sock
{
	eth_interface& m_iface;
	uint16_t m_proto;
	mac_addr m_peer;
	pcap_t* m_pcap;
	unsigned m_timeout;
	bool m_stp_enabled;

#ifdef NMRPFLASH_WINDOWS
	HANDLE m_handle = nullptr;
#else
	int m_fd = -1;
#endif

	public:
	eth_sock(eth_interface& iface, uint16_t ethertype);
	~eth_sock()
	{ shutdown(); }

	void connect(const mac_addr& peer);
	void disconnect();

	void send(const void* data, size_t size, const mac_addr& dest = mac_addr::broadcast);
	void send(const std::string& buf, const mac_addr& dest = mac_addr::broadcast);

	std::string recv(unsigned timeout = 0)
	{ return recv(timeout, nullptr); }

	std::string recv(mac_addr& src, unsigned timeout = 0)
	{ return recv(timeout, &src); }

	void timeout(unsigned timeout)
	{ m_timeout = timeout; }

	private:
	std::string recv(unsigned timeout, mac_addr* src);
	void init();
	void shutdown();
};
}
#endif
