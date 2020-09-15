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
#include "util.h"
using namespace std;

namespace nmrpflash {
namespace {
uint32_t prefix_to_netmask(int prefix)
{
	return 0xffffffff << (32 - prefix);
}
}

const mac_addr mac_addr::none;
const mac_addr mac_addr::broadcast({ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff });

mac_addr::mac_addr(const string& str)
{
	unsigned mac[6];

	int n = sscanf(str.c_str(),
			"%02x:%02x:%02x:%02x:%02x:%02x",
			&mac[0], &mac[1], &mac[2],
			&mac[3], &mac[4], &mac[5]);

	if (n != 6) {
		throw invalid_argument("Invalid MAC address: " + str);
	}

	init(mac);
}

string mac_addr::to_string(char delim) const
{
	string ret;

	for (int i = 0; i < sizeof(m_mac); ++i) {
		if (i) {
			ret += delim;
		}

		ret += (boost::format("%02x") % m_mac[i]).str();
	}

	return ret;
}

ip_addr::ip_addr(const std::string& ip)
{
	auto tok = split(ip, '/', 2);

	in_addr addr;
	if (!inet_aton(tok[0].c_str(), &addr)) {
		throw invalid_argument("Invalid IP address: " + tok[1]);
	}

	m_ip = addr.s_addr;
	
	if (tok.size() > 1) {
		prefix(stoi(tok[1]));
	}
}

ip_addr ip_addr::address() const
{
	return { m_ip, 0 };
}

ip_addr ip_addr::netmask() const
{
	return { prefix_to_netmask(m_prefix), 0 };
}

ip_addr ip_addr::broadcast() const
{
	if (m_prefix) {
		uint32_t mask = prefix_to_netmask(m_prefix);
		return { (m_ip & mask) | ~mask, 0 };
	} else {
		return { 0, 0 };
	}
}

ostream& operator<<(ostream& os, const ip_addr& ip)
{
	os << inet_ntoa(in_addr { ip.m_ip });
	if (ip.m_prefix) {
		os << '/' << ip.m_prefix;
	}
	return os;
}

void ip_addr::prefix(int pfx)
{
	if (pfx < 0 || pfx > 31) {
		throw invalid_argument("IP prefix length out of range: " + to_string(pfx));
	}

	m_prefix = pfx;
}
}
