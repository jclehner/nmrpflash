#include <boost/numeric/conversion/cast.hpp>
#include <boost/algorithm/string.hpp>
#include <gsl/pointers>
#include <stdexcept>
#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <map>
#include "fwimage.h"
#include "sha256.h"
#include "test.h"
using namespace std;
using boost::endian::big_uint32_buf_t;
using boost::endian::big_uint16_buf_t;
using gsl::not_null;

namespace nmrpflash {
namespace {
const auto chunk_size = 1024 * 1024;

class sha256_hasher
{
	public:
	sha256_hasher()
	{
		reset();
	}

	sha256_hasher& reset()
	{
		sha256_init(&m_ctx);
		return *this;
	}

	sha256_hasher& update(const buffer& b)
	{
		sha256_update(&m_ctx, reinterpret_cast<const uint8_t*>(b.data()), b.size());
		return *this;
	}

	buffer finish()
	{
		uint8_t digest[SHA256_BLOCK_SIZE];
		sha256_final(&m_ctx, digest);
		return to_buffer(digest);
	}

	private:
	sha256_ctx m_ctx;
};

class fwver
{
	public:
	fwver() = default;
	fwver(const fwver&) = default;

	void update(const fwver& v)
	{
		if (m_parts.size() != v.m_parts.size()) {
			throw invalid_argument("version format mismatch");
		}

		m_parts = v.m_parts;
	}

	static fwver from_string(string_view str)
	{
		vector<string> parts_s;

		char prefix = 0;

		if (tolower(str[0]) == 'v') {
			prefix = str[0];
			str = str.substr(1);
		}

		boost::split(parts_s, str, boost::is_any_of("._"));

		vector<uint8_t> parts;
		for (auto p : parts_s) {
			parts.push_back(boost::numeric_cast<uint8_t>(boost::lexical_cast<int>(p)));
		}

		return { parts, prefix };
	}

	static fwver from_binary(const buffer& buf)
	{
		auto begin = reinterpret_cast<const uint8_t*>(buf.data());
		auto end = begin + buf.size();
		return {{ begin, end }};
	}

	string str(bool with_prefix = false) const
	{
		if (m_parts.empty()) {
			return "";
		}

		string ret;

		if (with_prefix && m_prefix) {
			ret += m_prefix;
		}

		ret += to_string(int(m_parts[0]));

		for (size_t i = 1; i < m_parts.size(); ++i) {
			ret += ((i == 4) ? '_' : '.');
			ret += to_string(m_parts[i]);
		}

		return ret;
	}

	auto data() const
	{
		return m_parts.data();
	}

	auto size() const
	{
		return m_parts.size();
	}

	private:
	fwver(const vector<uint8_t>& parts, char prefix = 0)
	: m_parts(parts), m_prefix(prefix)
	{}

	vector<uint8_t> m_parts;
	char m_prefix;
};

ostream& operator<<(ostream& os, const fwver& v)
{
	return os << v.str();
}

size_t check_offset(gsl::not_null<const fwimage*> img, ssize_t soff)
{
	if (soff < 0) {
		soff += img->size();
	}

	if (soff >= 0) {
		auto off = boost::numeric_cast<size_t>(soff);
		if (off < img->size()) {
			return off;
		}
	}

	throw invalid_argument("offset out of range: " + to_string(soff));
}

class fwimage_base : public fwimage
{
	public:
	virtual unique_ptr<fwimage_base> create() const = 0;

	void open(const string& filename)
	{
		ifstream in;
		in.exceptions(ios::failbit | ios::badbit);
		in.open(filename.c_str(), ios::binary | ios::ate);

		ostringstream ss;
		ss << in.rdbuf();
		parse(ss.str());
	}

	void parse(const buffer& b)
	{
		m_buf = b;
		read_metadata();
	}

	size_t size() const override
	{
		return m_buf.size();
	}

	buffer read(ssize_t soff, size_t n) const override
	{
		auto off = check_offset(this, soff);
		if (n == buffer::npos) {
			n = size();
		}

		n = min(n, size() - off);
		return m_buf.substr(off, n);
	}

	template<class T> T read(ssize_t off) const
	{
		return unpack<T, boost::endian::order::native>(read(off, sizeof(T)));
	}

	std::string version() const override = 0;

	void version(const string& v) final
	{
		update_version(fwver::from_string(v));
		patch_checksum();
	}

	void patch(ssize_t off, const buffer& data, size_t len) override
	{
		m_buf.replace(check_offset(this, off), len, data);
	}

	protected:
	fwimage_base() = default;

	virtual void read_metadata() = 0;
	virtual void patch_checksum() = 0;
	virtual void update_version(const fwver& v) = 0;

	private:
	buffer m_buf;
};

class fwimage_with_str_version : public fwimage_base
{
	public:
	string version() const final
	{
		return m_version.str();
	}

	protected:
	virtual void patch_version(const string& v_new, size_t off, size_t v_old_len) = 0;

	void update_version(const fwver& v) final
	{
		m_version.update(v);
		auto vs = m_version.str(true);
		patch_version(vs, m_version_off, m_version_len);
		m_version_len = vs.size();
	}

	void store_version(const buffer& buf, size_t off, size_t len)
	{
		m_version = fwver::from_string(buf);
		m_version_off = off;
		m_version_len = len;
	}

	private:
	fwver m_version;
	size_t m_version_off;
	size_t m_version_len;
};

class fwimage_dni : public fwimage_with_str_version
{
	public:
	unique_ptr<fwimage_base> create() const override
	{
		return make_unique<fwimage_dni>();
	}

	string type() const override { return "dni"; }

	protected:
	static constexpr auto header_size = 128;

	void read_metadata() override
	{
		auto hdr = read(0, header_size);

		auto beg = hdr.find("device:");
		if (beg != 0) {
			throw invalid_argument("bad magic");
		}

		static const string key_version = "version:";
		beg = hdr.find(key_version);

		if (beg == string::npos) {
			throw invalid_argument("unexpected header format");
		}

		auto off = beg + key_version.size();
		auto end = hdr.find('\n', off);
		if (end == string::npos) {
			throw invalid_argument("unexpected header format");
		}

		auto len = end - off;
		store_version(hdr.substr(off, len), off, len);

		if (uint8_t(read(-1, 1).at(0)) != calc_checksum()) {
			throw runtime_error("checksum error");
		}
	}

	void patch_version(const string& v_new, size_t off, size_t v_old_len) override
	{
		auto hdr = read(0, header_size);
		hdr.replace(off, v_old_len, v_new);
		hdr.resize(header_size);
		fwimage::patch(0, hdr);
	}

	void patch_checksum() override
	{
		fwimage::patch(-1, string(1, calc_checksum()));
	}

	private:
	uint8_t calc_checksum() const
	{
		uint8_t ret = 0;
		size_t off = 0;
		uint8_t last_c = 0;

		buffer data;

		while (off < size()) {
			data = read(off, chunk_size);
			for (uint8_t c : data) {
				ret += c;
				last_c = c;
			}
			off += data.size();
		}

		// last byte was the checksum itself
		return 0xff - (ret - last_c);
	}
};

class fwimage_chk : public fwimage_base
{
	public:
	unique_ptr<fwimage_base> create() const override
	{
		return make_unique<fwimage_chk>();
	}

	string type() const override { return "chk"; }

	string version() const override
	{
		return m_version.str();
	}

	protected:
	static constexpr auto magic = "\x2a\x23\x24\x5e";
	static constexpr auto hdr_len_offset = 1 * 4;
	static constexpr auto region_offset = 2 * 4;
	static constexpr auto version_offset = region_offset + 1;
	static constexpr auto version_len = 7;
	static constexpr auto hdr_checksum_offset = 9 * 4;

	void read_metadata() override
	{
		if (read(0, 4) != magic) {
			throw runtime_error("bad magic");
		}

		m_hdr_len = read<big_uint32_buf_t>(hdr_len_offset);
		m_region = read(region_offset, 1).at(0);

		m_version = fwver::from_binary(read(version_offset, version_len));

		m_hdr_checksum = read<big_uint32_buf_t>(hdr_checksum_offset);

		if (m_hdr_checksum.value() != calc_hdr_checksum()) {
			throw runtime_error("checksum error");
		}
	}

	void patch_checksum() override
	{
		fwimage::patch(version_offset, to_buffer(m_version.data(), m_version.size()));
		m_hdr_checksum = calc_hdr_checksum();
		fwimage::patch(hdr_checksum_offset, to_buffer(m_hdr_checksum));
	}

	void update_version(const fwver& v) override
	{
		m_version.update(v);
	}

	private:
	uint32_t calc_hdr_checksum() const
	{
		buffer hdr = read(0, m_hdr_len.value());

		uint32_t c0 = 0;
		uint32_t c1 = 0;
		size_t i;

		for (i = 0; i < hdr_checksum_offset; ++i) {
			c0 += hdr.at(i) & 0xff;
			c1 += c0;
		}

		for (; i < hdr_checksum_offset + 4; ++i) {
			// ignore header checksum (same effect as all-zero checksum)
			c1 += c0;
		}

		for (; i < m_hdr_len.value(); ++i) {
			c0 += hdr.at(i) & 0xff;
			c1 += c0;
		}

		uint32_t b;
		b = (c0 & 65535) + ((c0 >> 16) & 65535);
		c0 = ((b >> 16) + b) & 65535;
		b = (c1 & 65535) + ((c1 >> 16) & 65535);
		c1 = ((b >> 16) + b) & 65535;

		return ((c1 << 16) | c0);
	}

	big_uint32_buf_t m_hdr_len;
	uint8_t m_region;
	fwver m_version;
	big_uint32_buf_t m_hdr_checksum;
};

class fwimage_rax : public fwimage_with_str_version
{
	public:
	unique_ptr<fwimage_base> create() const override
	{
		return make_unique<fwimage_rax>();
	}

	string type() const override { return "rax"; }

	protected:
	static constexpr uint16_t hdr_checksum_offset = 4;
	static constexpr uint16_t hdr_tlv_len_offset = 2;
	static constexpr uint16_t hdr_tlv_type_end = 0x0001;
	static constexpr uint16_t hdr_tlv_type_version = 0x0002;

	void read_metadata() override
	{
		static const char checksum_len = 32;
		static const auto magic = "\x00\x01\x00"s + checksum_len;

		if (read(0, magic.size()) != magic) {
			throw runtime_error("bad magic");
		}

		static const auto padding = "\x00\x00\x00\x00"s;
		if (read(magic.size() + checksum_len, padding.size()) != padding) {
			throw runtime_error("bad padding");
		}

		auto checksum = read(magic.size(), checksum_len);
		if (checksum != calc_checksum()) {
			throw runtime_error("checksum error");
		}

		size_t off = magic.size() + checksum_len + padding.size();
		while (true) {
			uint16_t tlv_t = read<big_uint16_buf_t>(off).value();
			uint16_t tlv_l = read<big_uint16_buf_t>(off + hdr_tlv_len_offset).value();

			if (tlv_t == hdr_tlv_type_end && !tlv_l) {
				break;
			}

			off += 4;
			if ((off + tlv_l) >= size()) {
				throw runtime_error("tlv length out of range");
			}

			if (tlv_t == hdr_tlv_type_version) {
				store_version(read(off, tlv_l), off, tlv_l);
			}

			off += tlv_l;
		}

		if (version().empty()) {
			throw runtime_error("missing version field");
		}
	}

	void patch_version(const string& v_new, size_t off, size_t v_old_len) override
	{
		patch(off, v_new, v_old_len);
		fwimage::patch(off - hdr_tlv_len_offset, to_buffer(big_uint16_buf_t(v_new.size())));
	}

	void patch_checksum() override
	{
		fwimage::patch(hdr_checksum_offset, calc_checksum());
	}

	private:
	buffer calc_checksum() const
	{
		static const auto header_offset = 4 + 32;
		static const auto salt1 = "hr89sdfgjkehx"s;
		static const auto salt2 = "nohsli9fjh3f"s;

		sha256_hasher h;

		h.update(salt1);

		fwimage::read([&h] (const buffer& b) {
				h.update(b);
		}, chunk_size, header_offset);

		return h.update(salt2).finish();
	}
};

class fwimage_generic : public fwimage_base
{
	public:
	unique_ptr<fwimage_base> create() const override
	{
		return make_unique<fwimage_generic>();
	}

	string type() const override
	{
		return m_type;
	}

	string version() const override { return ""; }

	protected:
	void update_version(const fwver&) override
	{
		throw invalid_argument("image type doesn't support version patching");
	}

	void patch_checksum() override {}
	void read_metadata() override
	{
		static const map<buffer, string> signatures {
			{ "PK\x03\x04",       "zip" },
			{ "HDR0",             "trx" },
			{ "\x27\x05\x19\x56", "uimage" },
			{ "\xd0\x0d\xfe\xed", "dtb" },
		};

		m_type = "(generic)";

		for (const auto& [m, t] : signatures) {
			if (read(0, m.size()) == m) {
				m_type = t;
				break;
			}
		}
	}

	private:
	string m_type;
};

unique_ptr<fwimage> fwimage_open_or_parse(const string& filename, const buffer& buf)
{
	static vector<unique_ptr<fwimage_base>> types;
	if (types.empty()) {
		types.emplace_back(new fwimage_chk());
		types.emplace_back(new fwimage_dni());
		types.emplace_back(new fwimage_rax());
		// this must be the last element
		types.emplace_back(new fwimage_generic());
	}

	string last_err;

	for (const auto& t : types) {
		try {
			auto ret = t->create();
			if (!filename.empty()) {
				ret->open(filename);
			} else if (!buf.empty()) {
				ret->parse(buf);
			}
			return ret;
		} catch (const ios_base::failure& e) {
			throw e;
		} catch (const exception& e) {
			last_err = e.what();
			// TODO log?
		}
	}

	throw runtime_error(last_err);
}
}

buffer fwimage::read() const
{
	return read(0, size());
}

void fwimage::read(function<void(const buffer&)> f, size_t n, ssize_t soff) const
{
	auto off = check_offset(this, soff);
	while (off < size()) {
		auto b = read(off, n);
		f(b);
		off += b.size();
	}
}

void fwimage::patch(ssize_t off, const buffer& buf)
{
	patch(off, buf, buf.size());
}

unique_ptr<fwimage> fwimage::open(const string& filename)
{
	return fwimage_open_or_parse(filename, "");
}

unique_ptr<fwimage> fwimage::parse(const buffer& buf)
{
	return fwimage_open_or_parse("", buf);
}
}
