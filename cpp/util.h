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
#ifndef NMRPFLASH_UTIL_H
#define NMRPFLASH_UTIL_H
#include <boost/format.hpp>
#include <boost/predef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <functional>
#include <unistd.h>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <vector>
#include <string>
#include <memory>
#include <pcap.h>

namespace nmrpflash {
class scoped_fd
{
	int m_fd;

	public:
	scoped_fd(int fd = -1)
	: m_fd(fd) {}

	~scoped_fd()
	{ close(m_fd); }

	void reset(int fd)
	{ m_fd = fd; }

	int operator*() const
	{ return m_fd; }
};

#if 0
template<class R, class... Args> class cleaner
{
	const std::function<R(Args...)> m_func;
	bool m_invalid;

	cleaner(std::function<R(Args...)>&& func)
	: m_func(func), m_invalid(false)
	{}

	public:
	~cleaner()
	{
		if (!m_invalid) {
			m_func();
		}
	}

	void invalidate(bool invalid = true)
	{ m_invalid = invalid; }

	template<class R2, class... Args2> friend auto make_cleaner(std::function<R2(Args2...)>&& f)
	{
		return cleaner<R2(Args2...)>(f);
	}
};
#endif

class mac_addr
{
	uint8_t m_mac[6];

	public:
	mac_addr()
	: mac_addr({0, 0, 0, 0, 0, 0})
	{}

	mac_addr(const uint8_t (&mac)[6])
	{ memcpy(m_mac, mac, sizeof(m_mac)); }

	template<class T> mac_addr(const T (&mac)[6])
	{
		init(mac);
	}

	explicit mac_addr(const void* raw)
	{ memcpy(m_mac, raw, sizeof(m_mac)); }

	mac_addr(const std::string& mac);

	template<class T> void apply_to(T* other) const
	{
		memcpy(other, m_mac, sizeof(m_mac));
	}

	std::string to_string(char delim = ':') const;

	bool operator==(const mac_addr& other) const
	{ return !memcmp(m_mac, other.m_mac, sizeof(m_mac)); }

	bool operator!=(const mac_addr& other) const
	{ return !operator==(other); }

	bool operator<(const mac_addr& other) const
	{ return memcmp(m_mac, other.m_mac, sizeof(m_mac)) < 0; }

	explicit operator bool() const
	{ return operator!=(none); }

	friend std::ostream& operator<<(std::ostream& os, const mac_addr& other)
	{ return os << other.to_string(); }

	static const mac_addr broadcast;
	static const mac_addr none;

	private:
	template<class T> void init(const T (&mac)[6])
	{
		for (int i = 0; i < sizeof(m_mac); ++i) {
			m_mac[i] = mac[i] & 0xff;
		}
	}

};

class ip_addr
{
	uint32_t m_ip;
	int m_prefix;

	public:
	ip_addr()
	: ip_addr(0)
	{}

	explicit ip_addr(uint32_t ip)
	: ip_addr(ip, 0)
	{}

	ip_addr(uint32_t ip, int prefix)
	: m_ip(htonl(ip))
	{
		this->prefix(m_prefix);
	}

	ip_addr(uint8_t a, uint8_t b, uint8_t c, uint8_t d, int prefix = 0)
	: ip_addr(htonl(a << 24 | b << 16 | c << 8 | d), prefix)
	{}

	ip_addr(const std::string& ip);

	int prefix() const
	{ return m_prefix; }

	ip_addr address() const;
	ip_addr netmask() const;
	ip_addr broadcast() const;

	void apply_to(in_addr& other) const
	{ other.s_addr = m_ip; }

	void apply_to(sockaddr_in& other) const
	{
		other.sin_family = AF_INET;
		apply_to(other.sin_addr);
	}

	void apply_to(sockaddr& other) const
	{ apply_to(*reinterpret_cast<sockaddr_in*>(&other)); }

	uint32_t to_uint() const 
	{ return ntohl(m_ip); }

	bool operator==(const ip_addr& other) const
	{ return m_ip == other.m_ip && m_prefix == other.m_prefix; }

	bool operator!=(const ip_addr& other) const
	{ return !operator==(other); }

	bool operator<(const ip_addr& other) const
	{
		if (m_ip == other.m_ip) {
			return m_prefix < other.m_prefix;
		} else {
			return m_ip < other.m_ip;
		}
	}

	explicit operator bool() const
	{ return m_ip != 0; }

	friend std::ostream& operator<<(std::ostream& os, const ip_addr& ip);

	private:
	void prefix(int prefix);
};

template<class T, class D>
auto wrap_unique(T* ptr, D&& del) -> std::unique_ptr<T, D>
{
	return std::unique_ptr<T, D>(ptr, del);
}

int xsocket(int domain, int type, int protocol);

bool select_readfd(int fd, unsigned timeout);

template<class T> std::string stringify(const T& t);
std::string format(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
std::vector<std::string> split(const std::string& str, char delim, unsigned max);
template<class CharT> std::basic_string<CharT> quote(const std::basic_string<CharT>& str);

int run(const std::string& cmd, bool throw_on_error = true);

class errno_error : public std::system_error
{
	public:
	errno_error(const std::string& what, int error = errno)
	: std::system_error(error, std::system_category(), what), m_interrupted(error == EINTR)
	{}

	bool interrupted() const noexcept
	{ return m_interrupted; }

	private:
	bool m_interrupted;
};

class pcap_error : public std::runtime_error
{
	public:
	pcap_error(const std::string& what, pcap_t* p)
	: std::runtime_error(what + ": " + pcap_geterr(p))
	{}
};

class log
{
	public:
	static void w(const std::string& msg);
};

}
#endif
