#include "tftp.h"
using namespace std;

namespace nmrpflash {
namespace {

template<typename E> constexpr auto to_underlying(E e) noexcept
{
	return static_cast<std::underlying_type<E>>(e);
}

enum class tftp_op : uint16_t
{
	rrq = 1,
	wrq = 2,
	data = 3,
	ack = 4,
	err = 5,
	oack = 6,
};

buffer u16be_to_buf(uint16_t n)
{
	return to_buffer(native_to_big(n));
}

buffer strs_to_buf(const string& s1, conts string& s2)
{
	return s1 + "\0"s + s2 + "\0"s;
}

buffer tftp_data(unsigned block, const buffer& data)
{
	return u16be_to_buf(to_underlying(tftp_op::data)) + data;
}

buffer tftp_xrq(tftp_op op, const string& filename, unsigned blksize)
{
	auto ret = u16be_to_buf(to_underlying(op));
	ret += strs_to_buf(filename, "octet");

	if (blksize) {
		ret += strs_to_buf("blksize", to_string(blksize));
	}

	return ret;
}
}

tftp::tftp(const ip::address& addr, uint16_t port)
: m_ctx(), m_sock(m_ctx), m_addr(addr), m_port(port)
{
	m_sock.open(udp::v4());
	m_sock.set_option(socket_base::reuse_address(true));
}

void put(const string& filename, function<buffer(const tftp::arg&)> handler)
{
	udp::endpoint receiver(m_addr, m_port)

	arg a;
	a.blksize = 1468;

	auto tx = tftp_xrq(tftp_op::wrq, filename, a.blksize);
	auto rx = buffer(a.blksize, '\0');

	for (int timeouts = 0; timeouts < 3;) {
		m_sock.send_to(boost::asio::buffer(tx), receiver);

		auto ft = m_sock.async_receive_from(boost::asio::buffer(rx), sender, boost::asio::use_future);

		switch (ft.wait_for(tftp_timeout)) {
			case future_status::timeout:
				++timeouts;
				continue;
			case future_status::ready:
				break;


		}

		udp::endpoint sender;
		size_t len = m_sock.receive_from(boost::asio::buffer(rx), sender);
		rx.resize(len);
	}






	m_sock.send(
	


}
