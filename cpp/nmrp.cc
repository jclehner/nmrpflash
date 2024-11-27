
	static nmrp_pkt from_bytes(const buffer& b);

	static nmrp_pkt advertise(const std::string& magic = "NTGR");
	static nmrp_pkt conf_ack(uint32_t ip, uint32_t mask, uint16_t region = r_none);
	static nmrp_pkt tftp_ul_req(const std::string& filename);

	nmrp_pkt(code c = c_none, uint8_t id = 0, uint16_t reserved = 0);
	nmrp_pkt& opt(opt_type t, const buffer& b);

	const buffer& operator[](opt_type t) const;

	buffer to_bytes() const;

	private:
	code m_code;
	uint16_t m_reserved;
	uint8_t m_id;

	std::map<opt_type, buffer> m_opts;

#include "nmrp.h"
using namespace std;

namespace nmrpflash {
	static constexpr uint16_t msg_hdr_len = 6;
	static constexpr uint16_t opt_hdr_len = 4;

	nmrp_pkt::nmrp_pkt(nmrp_pkt::code code, uint8_t id, uint16_t reserved)
	: m_code(code), m_id(id), m_reserved(reserved)
	{}

	nmrp_pkt& nmrp_pkt::opt(opt_type t, const buffer& b)
	{
		m_opt[t] = b;
		return *this;
	}

	const buffer& operator[](opt_type t) const
	{
		auto it = m_opt.find(t);
		if (it == m_opt.end()) {
			throw invalid_argument("no such option: " + to_string(t));
		}

		return it->second;
	}

	nmrp_pkt nmrp_pkt::from_bytes(const buffer& b, bool strict)
	{
		size_t i = 0;

		auto reserved = b.unpack_be<uint16_t>(i);
		uint8_t code = b[i++];
		uint8_t id = b[i++];
		auto len = b.unpack_be<uint16_t>(i);

		if (len > b.size()) {
			throw invalid_argument("invalid message size");
		}

		nmrp_pkt ret(code, id, reserved);

		while (i < len) {
			auto olen = b.unpack_be<uint16_t>(i);
			if (olen < opt_hdr_len || (i + olen) > len) {
				throw invalid_argument("invalid option size");
			}

			auto type = b.unpack_be<uint16_t>(i);
			ret.opt(type, b.substr(i, olen));
		}

		return ret;
	}

	buffer nmrp_pkt::to_bytes() const
	{
		buffer opt_data;



		ret.pack(




	}


