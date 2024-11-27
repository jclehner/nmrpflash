#include <iomanip>
#include <sstream>
#include <string>
#include <cctype>

namespace nmrpflash {
typedef std::basic_string<uint8_t> buffer;

template<class T> buffer to_buffer(const T& t, size_t size)
{
	return buffer(reinterpret_cast<const uint8_t*>(&t), size);
}

template<class T> buffer to_buffer(const T& t)
{
	return to_buffer(t, sizeof(t));
}

template<> buffer to_buffer(const std::string& str)
{
	return buffer(reinterpret_cast<const uint8_t*>(str.data()), str.size());
}

std::string to_string(const buffer& b)
{
	std::stringstream ss;
	ss << std::setfill('0') << std::hex;

	for (size_t i = 0; i < b.size(); ++i) {
		ss << "\\x" << std::setw(2) << int(b[i]);
	}

	return ss.str();
}
}
