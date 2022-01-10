#include <array>
#include "address.h"
using namespace std;

namespace nmrpflash {
namespace {
unsigned ip6_netmask_to_prefix_len(const ip6_addr::bytes_type& a)
{
	size_t i = 0;

	for (; i < a.size() && a[i] == 0xff; ++i) {
		;
	}

	if (i < a.size()) {
		unsigned r = 0;

		for (uint8_t b = a[i]; b & 0x80; b <<= 1) {
			++r;
		}

		do {
			if (((0xff << (8 - r)) & 0xff) != a[i]) {
				break;
			}

			auto k = i + 1;

			for (; k < a.size(); ++k) {
				if (a[k]) {
					break;
				}
			}

			if (k < a.size()) {
				break;
			}

			return i * 8 + r;
		} while (false);

		throw invalid_argument("discontignuous netmask");
	}

	return i * 8;
}
}

ip_addr ip_from_sockaddr(gsl::not_null<const sockaddr*> addr)
{
	if (addr->sa_family == AF_INET) {
		return ip4_from_sockaddr(reinterpret_cast<const sockaddr_in*>(addr.get()));
	} else if (addr->sa_family == AF_INET6) {
		return ip6_from_sockaddr(reinterpret_cast<const sockaddr_in6*>(addr.get()));
	} else {
		throw invalid_argument("unsupported address family");
	}
}

ip4_addr ip4_from_sockaddr(gsl::not_null<const sockaddr_in*> addr)
{
	return ip4_addr(htonl(addr->sin_addr.s_addr));
}

ip6_addr ip6_from_sockaddr(gsl::not_null<const sockaddr_in6*> addr)
{
	return ip6_addr(to_array(addr->sin6_addr.s6_addr));
}

ip_net::ip_net(const ip_addr& addr, const ip_addr& netmask)
{
	if (addr.is_v4() && netmask.is_v4()) {
		m_net = ip4_net(addr.to_v4(), netmask.to_v4());
	} else if (addr.is_v6() && netmask.is_v6()) {
		m_net = ip6_net(addr.to_v6(), ip6_netmask_to_prefix_len(netmask.to_v6().to_bytes()));
	} else {
		throw invalid_argument("unsupported address and netmask combination");
	}
}

mac_addr::mac_addr(const string& addr)
{
	do {
		vector<string> parts;
		boost::split(parts, addr, boost::algorithm::is_any_of(":-"));

		if (parts.size() != length) {
			break;			
		}

		for (size_t i = 0; i < length; ++i) {
			if (parts[i].size() != 2) {
				break;
			}

			size_t k;
			int n = stoi(parts[i], &k, 16);

			if (k != 2 || n < 0 || n > 0xff) {
				break;
			}

			m_addr[i] = n & 0xff;
		}

		return;
	} while (false);

	throw invalid_argument("invalid MAC address: " + addr);
}

ostream& operator<<(ostream& os, const mac_addr& addr)
{
	using boost::algorithm::join;
	using boost::adaptors::transformed;

	os << join(addr.m_addr | transformed([](uint8_t b) { return to_hex(b); }), ":");
	return os;
}
}
