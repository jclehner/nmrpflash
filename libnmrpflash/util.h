#ifndef NMRPFLASH_UTIL_H
#define NMRPFLASH_UTIL_H
#include <boost/algorithm/string.hpp>
#include <boost/range/adaptors.hpp>
#include <iostream>
#include <cstdint>
#include <sstream>

namespace nmrpflash {
template<typename T> std::string to_hex(const T& t)
{
	const uint8_t* data = reinterpret_cast<const uint8_t*>(&t);
	std::ostringstream ostr;

	for (size_t i = 0; i < sizeof(T); ++i) {
		ostr << std::setw(2) << std::setfill('0') << std::hex << int(data[i]);
	}
	
	return ostr.str();
}
}
#endif
