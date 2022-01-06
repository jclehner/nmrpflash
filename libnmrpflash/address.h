#ifndef NMRPFLASH_ADDRESS_H
#define NMRPFLASH_ADDRESS_H
#include <boost/algorithm/string.hpp>
#include <boost/range/adaptors.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iterator>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include "util.h"

namespace nmrpflash {
namespace detail {
/// A dummy Ethernet address family. That way, we can reuse generic_addr
/// for both IPv{4,6} and MAC adddresses.
const int af_ethernet = AF_INET + AF_INET6;

template<int AF> struct addr_helper_impl;

template<> struct addr_helper_impl<AF_INET>
{
	typedef sockaddr_in sockaddr_type;
	typedef in_addr addr_type;

	static constexpr size_t addrstr_len = INET_ADDRSTRLEN;

	static std::string name() { return "IPv4"; }
};

template<> struct addr_helper_impl<AF_INET6>
{
	typedef sockaddr_in6 sockaddr_type;
	typedef in6_addr addr_type;

	static constexpr size_t addrstr_len = INET6_ADDRSTRLEN;

	static std::string name() { return "IPv6"; }
};

template<> struct addr_helper_impl<af_ethernet>
{
	typedef void sockaddr_type;
	typedef uint8_t addr_type[6];

	static std::string name() { return "MAC"; }
};

template<int AF> class generic_addr
{
	public:
	typedef addr_helper_impl<AF> addr_helper;

	static constexpr int addr_family = AF;
	static constexpr size_t addr_size = sizeof(typename addr_helper::addr_type);

	generic_addr()
	{
		memset(&m_addr, 0, sizeof(m_addr));
	}

	generic_addr(const uint8_t (&addr)[addr_size])
	{
		static_assert(addr_size == sizeof(m_addr));
		memcpy(reinterpret_cast<uint8_t*>(&m_addr), addr, sizeof(m_addr));
	}

	generic_addr(const std::string& addr)
	{
		if (!from_string(addr)) {
			throw std::invalid_argument("invalid " + addr_helper::name() + " address: " + addr);
		}
	}

	template<int AF2> friend std::ostream& operator<<(std::ostream& os, const generic_addr<AF2>& addr);

	friend std::ostream& operator<<(std::ostream& os, const generic_addr& addr)
	{
		os << addr.to_string();
		return os;
	}

	private:
	bool from_string(const std::string& addr)
	{
		return inet_pton(AF, addr.c_str(), &m_addr) == 1;
	}

	std::string to_string() const
	{
		char buf[addr_helper::addrstr_len];
		const char* str = inet_ntop(AF, &m_addr, buf, sizeof(buf));

		if (!str) {
			throw std::runtime_error("failed to convert " + addr_helper::name() + " address to string");
		}

		return str;
	}

	typename addr_helper::addr_type m_addr;
};

template<> std::string generic_addr<af_ethernet>::to_string() const
{
	using std::ostringstream;
	using std::hex;
	using std::setw;
	using boost::algorithm::join;
	using boost::adaptors::transformed;

	return join(m_addr | transformed([](uint8_t b) { return to_hex(b); }), ":");
}


template<> bool generic_addr<af_ethernet>::from_string(const std::string& addr)
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
} // namespace detail

typedef detail::generic_addr<AF_INET> ip4_addr;
typedef detail::generic_addr<AF_INET6> ip6_addr;
typedef detail::generic_addr<detail::af_ethernet> mac_addr;

} // namespace nmrpflash
#endif
