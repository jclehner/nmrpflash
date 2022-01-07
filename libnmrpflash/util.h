#ifndef NMRPFLASH_UTIL_H
#define NMRPFLASH_UTIL_H
#include <boost/algorithm/string.hpp>
#include <boost/range/adaptors.hpp>
#include <gsl/gsl>
#include <cerrno>
#include <iostream>
#include <cstdint>
#include <sstream>
#include <array>

namespace nmrpflash {
template<typename T> auto as_bytes(const T& t)
{
	return gsl::span<const uint8_t, sizeof(T)>(reinterpret_cast<const uint8_t*>(&t), sizeof(T));
}

template<typename T> std::string to_hex(const T& t)
{
	std::ostringstream ostr;

	for (auto b : as_bytes(t)) {
		ostr << std::setw(2) << std::setfill('0') << std::hex << int(b);
	}

	return ostr.str();
}

class errno_error : public std::system_error
{
	errno_error(const std::string& msg, int val = errno)
	: std::system_error(val, std::system_category(), msg)
	{}
};

#if BOOST_OS_WINDOWS
class winapi_error : public std::system_error
{
	winapi_error(const std::string& msg, int val = GetLastError())
	: std::system_error(val, std::system_category(), msg)
	{}
};
#endif
}
#endif
