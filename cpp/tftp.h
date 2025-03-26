#ifndef NMRPFLASH_TFTP_H
#define NMRPFLASH_TFTP_H
#include <boost/asio.hpp>
#include "buffer.h"

namespace asio = boost::asio;

namespace nmrpflash {
class tftp
{
	public:
	struct arg
	{
		unsigned blksize;
		unsigned block;
	};

	tftp(const asio::ip::addresss& addr, uint16_t port = 69);
	~tftp();

	void put(const std::string& filename, std::function<buffer(const arg&)> handler);
	void get(const std::string& filename, std::function<void(buffer, const arg&)> handler);

	private:
	asio::io_context m_ctx;
	asio::ip::udp::socket m_socket;
	asio::ip::address m_addr;
	uint16_t m_port;
};
}
