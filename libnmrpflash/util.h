#ifndef NMRPFLASH_UTIL_H
#define NMRPFLASH_UTIL_H
#include <boost/algorithm/string.hpp>
#include <boost/range/adaptors.hpp>
#include <boost/lexical_cast.hpp>
#include <gsl/gsl>
#include <cerrno>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <sstream>
#include <array>

#if BOOST_OS_MACOS
#include <CoreFoundation/CoreFoundation.h>
#endif

namespace nmrpflash {
namespace detail {
// Apple's clang doesn't yet support std::to_array. This is taken from
// https://en.cppreference.com/w/cpp/container/array/to_array
template <class T, std::size_t N, std::size_t... I>
constexpr std::array<std::remove_cv_t<T>, N> to_array_impl(T (&a)[N], std::index_sequence<I...>)
{
    return {{ a[I]... }};
}
}

template <class T, std::size_t N>
constexpr std::array<std::remove_cv_t<T>, N> to_array(T (&a)[N])
{
    return detail::to_array_impl(a, std::make_index_sequence<N>{});
}

template<typename T> std::string stringify(const T& t)
{
	return boost::lexical_cast<std::string>(t);
}

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

template<typename To, typename From> To ugly_c_cast(From from)
{
	return (To)from;
}

class errno_error : public std::system_error
{
	errno_error(const std::string& msg, int val = errno)
	: std::system_error(val, std::system_category(), msg)
	{}
};

#if BOOST_OS_LINUX
bool nm_is_managed(const std::string& dev);
void nm_set_managed(const std::string& dev, bool managed);
std::string nm_get_connection(const std::string& dev);

struct nm_unmanaged_scope
{
	const std::string dev;
	const bool is_managed;

	nm_unmanaged_scope(const std::string& dev)
	: dev(dev), is_managed(nm_is_managed(dev))
	{
		if (is_managed) {
			nm_set_managed(dev, false);
		}
	}

	~nm_unmanaged_scope()
	{
		if (is_managed) {
			nm_set_managed(dev, true);
		}
	}
};
#elif BOOST_OS_WINDOWS
class winapi_error : public std::system_error
{
	winapi_error(const std::string& msg, int val = GetLastError())
	: std::system_error(val, std::system_category(), msg)
	{}
};
#elif BOOST_OS_MACOS
namespace detail {
template<typename T> struct cf_type_id;

template<> struct cf_type_id<CFDictionaryRef>
{
	static constexpr bool check = true;
	static CFTypeID value() { return CFDictionaryGetTypeID(); }
};

template<> struct cf_type_id<CFStringRef>
{
	static constexpr bool check = true;
	static CFTypeID value() { return CFStringGetTypeID(); }
};

template<> struct cf_type_id<CFTypeRef>
{
	static constexpr bool check = false;
};

template<> struct cf_type_id<void*>
{
	static constexpr bool check = false;
};
}

std::string from_cf_string(const CFStringRef str);

template<typename To, typename From> To cf_cast(From from)
{
	if constexpr (detail::cf_type_id<To>::check) {
		auto from_type = CFGetTypeID(from);
		auto to_type = detail::cf_type_id<To>::value();

		if (from_type != to_type) {
			throw std::invalid_argument("cannot cast " + from_cf_string(CFCopyTypeIDDescription(from_type))
					+ " to " + from_cf_string(CFCopyTypeIDDescription(to_type)));
		}
	}

	return reinterpret_cast<To>(from);
}

template<typename T> class cf_ref
{
	public:
	typedef T element_type;

	cf_ref()
	: m_ref(nullptr), m_view(true)
	{}

	cf_ref(T ref, bool view)
	: cf_ref(ref, view, false)
	{}

	cf_ref(const cf_ref& other)
	: cf_ref(other.m_ref, other.m_view, true)
	{}

	cf_ref(cf_ref&& other)
	: m_ref(other.m_ref), m_view(other.m_view)
	{
		other.m_ref = nullptr;
	}

	~cf_ref()
	{
		if (!m_view && m_ref) {
			CFRelease(m_ref);
		}
	}

	template<typename U> cf_ref<U> as() const
	{
		return cf_ref<U>(cf_cast<U>(m_ref), m_view).retain();
	}

	T get()
	{
		return const_cast<T>(std::as_const(*this).get());
	}

	const T get() const
	{
		if (m_ref) {
			return m_ref;
		}

		throw std::runtime_error("accessing NULL CFTypeRef");
	}

	const void** get_p() const
	{
		if (!m_view) {
			throw std::runtime_error("accessing pointer to non-view CFTypeRef");
		}

		return ugly_c_cast<const void**>(&m_ref);
	}

	cf_ref& retain()
	{
		if (m_ref && !m_view) {
			CFRetain(m_ref);
		}

		return *this;
	}

	explicit operator bool() const
	{
		return m_ref != nullptr;
	}

	private:
	cf_ref(T ref, bool view, bool copy)
	: m_ref(ref), m_view(view)
	{
		if (copy) {
			retain();
		}

	}

	T m_ref;
	bool m_view;
};

template<typename U> cf_ref<U> make_cf_ref(U ref)
{
	return cf_ref<U>(ref, false);
}

template<typename U> cf_ref<U> make_cf_view(U ref)
{
	return cf_ref<U>(ref, true);
}

inline std::string from_cf_string(const cf_ref<CFStringRef>& str)
{
	return from_cf_string(str.get());
}

cf_ref<CFStringRef> to_cf_string(const std::string& str);

#endif
}
#endif
