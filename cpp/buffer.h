#ifndef NMRPFLASH_BUFFER_H
#define NMRPFLASH_BUFFER_H
#include <iomanip>
#include <sstream>
#include <string>
#include <cctype>
#include <boost/endian.hpp>

namespace nmrpflash {
typedef std::string buffer;
//typedef std::basic_string<uint8_t> buffer;

constexpr auto endian_native = boost::endian::order::native;
constexpr auto endian_big = boost::endian::order::big;
constexpr auto endian_little = boost::endian::order::little;

template<class T> buffer to_buffer(const T& data, size_t size = sizeof(data))
{
	if constexpr (std::is_same_v<const buffer&, T>) {
		return data.substr(0, size);
	} else if constexpr (std::is_pointer_v<T>) {
		return buffer(reinterpret_cast<const char*>(data), size);
	} else {
		return buffer(reinterpret_cast<const char*>(&data), size);
	}
}

template<> buffer to_buffer(const buffer&, size_t) = delete;

template<class T, size_t N> buffer to_buffer(const T(&data)[N])
{
	return to_buffer<const T*>(data, N);
}

std::string to_hex(const buffer& b);

namespace detail {
template<boost::endian::order O, class T> T conditional_reverse(T value)
{
	return boost::endian::conditional_reverse<endian_native, O>(value);
}
}

template<class T, boost::endian::order O> T unpack(const buffer& b, size_t off = 0)
{
	static_assert(std::is_pod<T>::value);
	if ((off + sizeof(T)) > b.size()) {
		throw std::out_of_range("unpack: offset=" + std::to_string(off));
	}

	return detail::conditional_reverse<O>(*reinterpret_cast<const T*>(&b[off]));
}

template<boost::endian::order O, class T> buffer& pack(buffer& b, size_t off, T val)
{
	val = detail::conditional_reverse<O>(val);
	return b.replace(off, sizeof(T), reinterpret_cast<const char*>(&val));
}

template<boost::endian::order O, class T> buffer& pack(buffer& b, T val)
{
	val = detail::conditional_reverse<O>(val);
	return b.append(reinterpret_cast<const char*>(&val), sizeof(T));
}
}
#endif
