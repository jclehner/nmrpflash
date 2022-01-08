#ifndef NMRPFLASH_ADDRESS_H
#define NMRPFLASH_ADDRESS_H
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/range/adaptors.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iterator>
#include <iostream>
#include <variant>
#include <iomanip>
#include <sstream>
#include <string>
#include "util.h"

#define HAVE_AF_PACKET

#ifdef HAVE_AF_PACKET
#include <linux/if_packet.h>
#endif

namespace nmrpflash {
typedef boost::asio::ip::address ip_addr;
typedef boost::asio::ip::address_v4 ip4_addr;
typedef boost::asio::ip::address_v6 ip6_addr;

ip_addr ip_from_sockaddr(gsl::not_null<const sockaddr*> addr);
ip4_addr ip4_from_sockaddr(gsl::not_null<const sockaddr_in*> addr);
ip6_addr ip6_from_sockaddr(gsl::not_null<const sockaddr_in6*> addr);

typedef boost::asio::ip::network_v4 ip4_net;
typedef boost::asio::ip::network_v6 ip6_net;

class ip_net
{
	public:
	ip_net(const ip_addr& addr, const ip_addr& netmask);

	bool is_v4() const
	{ return m_net.index() == 0; }

	bool is_v6() const
	{ return !is_v4(); }

	ip4_net to_v4() const
	{ return std::get<ip4_net>(m_net); }

	ip6_net to_v6() const
	{ return std::get<ip6_net>(m_net); }

	friend std::ostream& operator<<(std::ostream& os, const ip_net& net)
	{
		if (net.is_v4()) {
			os << net.to_v4();
		} else {
			os << net.to_v6();
		}
		return os;
	}

	private:
	std::variant<ip4_net, ip6_net> m_net;
};

class mac_addr
{
	public:
	static constexpr size_t length = 6;

	mac_addr()
	{
		memset(m_addr.data(), 0, length);
	}

	mac_addr(const uint8_t (&addr)[length])
	: mac_addr(addr, nullptr)
	{}

	mac_addr(const std::string& addr);

	bool operator==(const mac_addr& other)
	{
		return !memcmp(m_addr.data(), other.m_addr.data(), length);
	}

	bool operator<(const mac_addr& other)
	{
		return memcmp(m_addr.data(), other.m_addr.data(), length) < 0;
	}

	friend std::ostream& operator<<(std::ostream& os, const mac_addr& addr);

	static mac_addr from_raw(const uint8_t* addr)
	{
		return mac_addr(addr, nullptr);	
	}

	private:
	mac_addr(const uint8_t* addr, nullptr_t)
	{
		memcpy(m_addr.data(), addr, length);
	}

	std::array<uint8_t, length> m_addr;
};

#if 0
template<> void
generic_addr<af_ethernet>::copy_to(typename addr_helper_impl<af_ethernet>::sockaddr_type&) = delete;

template<> inline std::string generic_addr<af_ethernet>::to_string() const
{
}

template<> inline bool generic_addr<af_ethernet>::from_string(const std::string& addr)
{
	std::vector<std::string> parts;
	boost::split(parts, addr, boost::algorithm::is_any_of(":-"));

	if (parts.size() != addr_size) {
		return false;
	}

	for (size_t i = 0; i < parts.size(); ++i) {
		if (parts[i].size() != 2) {
			return false;
		}

		size_t k;
		int n = stoi(parts[i], &k, 16);

		if (k != 2 || n < 0 || n > 0xff) {
			return false;
		}

		m_addr[i] = n & 0xff;
	}

	return true;
}

} // namespace nmrpflash
#endif
}
#endif
