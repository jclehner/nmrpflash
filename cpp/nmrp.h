#include <string>
#include "buffer.h"

namespace nmrpflash {

class nmrp_pkt
{
	public:
	enum code : uint8_t
	{
		c_none = 0,
		c_advertise = 1,
		c_conf_req = 2,
		c_conf_ack = 3,
		c_close_req = 4,
		c_close_ack = 5,
		c_keep_alive_req = 6,
		c_keep_alive_ack = 7,
		c_tftp_ul_req = 16
	};

	enum opt_type : uint16_t
	{
		o_magic_no = 0x0001,
		o_dev_ip = 0x0002,
		o_dev_region = 0x0004,
		o_fw_up = 0x0101,
		o_st_up = 0x0102,
		o_filename = 0x0181
	};

	enum region_code : uint16_t
	{
		r_none = 0
		r_na, // North America
		r_ww, // world wide
		r_gr, // Greece?
		r_pr, //
		r_ru, // Russia
		r_bz, // Brazil
		r_in, // India
		r_ko, // Korea
		r_jp, // Japan
	};

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
};


