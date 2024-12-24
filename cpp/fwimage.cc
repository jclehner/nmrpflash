#include <boost/numeric/conversion/cast.hpp>
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

buffer read_is(istream& in, size_t n, bool partial = false)
{
	buffer ret(n, '\x00');
	in.read(reinterpret_cast<char*>(ret.data()), ret.size());
	auto rlen = boost::numeric_cast<size_t>(in.gcount());

	if (rlen < ret.size()) {
		if (partial || in.eof()) {
			ret.resize(rlen);
		} else {
			throw runtime_error("short read: " + to_string(rlen) + "b");
		}
	}

	return ret;
}

vector<uint8_t> split_version(const string& str)
{
	istringstream istr(str);

	if (istr.peek() == 'V') {
		istr.seekg(1);
	}

	vector<uint8_t> ret;
	int n;

	while ((istr >> n)) {
		if (n < 0 || n > 0xff) {
			throw invalid_argument("invalid version part: " + to_string(n));
		}

		ret.push_back(n & 0xff);

		int c = istr.peek();

		if (c == '.' || c == '_') {
			(void) istr.get();
		}
	}

	return ret;
}

string join_version(const vector<uint8_t>& version)
{
	if (version.empty()) {
		return "";
	}

	ostringstream ostr;
	ostr << int(version[0]);

	for (size_t i = 1; i < version.size(); ++i) {
		if (i == 4) {
			ostr << '_';
		} else {
			ostr << '.';
		}

		ostr << int(version[i]);
	}

	return ostr.str();
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
		m_fs = make_unique<ifstream>(filename.c_str(), ios::binary | ios::ate);
		m_fs->exceptions(ios::failbit | ios::badbit);
		m_size = m_fs->tellg();
		read_metadata();
	}

	void parse(const buffer& b)
	{
		m_fs = make_unique<istringstream>(b);
		m_fs->exceptions(ios::failbit | ios::badbit);
		m_size = b.size();
		read_metadata();
	}

	size_t size() const override
	{
		return m_size;
	}

	buffer read(ssize_t soff, size_t n) const override
	{
		auto off = check_offset(this, soff);
		if (n == buffer::npos) {
			n = size();
		}

		m_fs->seekg(off);

		n = min(n, size() - off);
		buffer buf = read_is(*m_fs, n);

		MY_ASSERT_EQ(buf.size(), n);

		// example:
		//   read(1024, 64)
		//
		//   m_patch[1024] = (4) "\xaa\xbb\xcc\xdd";
		//   m_patch[1086] = (3) "foo";


		for (auto [patch_off, patch_buf] : m_patches) {
			auto beg = max(patch_off, off);
			const auto end = min(patch_off + patch_buf.size(), off + n);
			if (beg >= end) {
				continue;
			}

			const auto len = end - beg;
			beg -= off;
			const auto patch_beg = (patch_off < beg) ? (beg - patch_off) : 0;

			buf.replace(beg, len, patch_buf.substr(patch_beg, len));
			MY_ASSERT_EQ(buf.size(), n);
		}

		return buf;
	}

	template<class T> T read(ssize_t off) const
	{
		return unpack<T, boost::endian::order::native>(read(off, sizeof(T)));
	}

	virtual std::string version() const = 0;

	void version(const string& v) final
	{
		auto v_old = split_version(version());
		auto v_new = split_version(v);

		if (v_old.size() != v_new.size()) {
			throw invalid_argument("invalid version format");
		}

		set_version(v_new);
		update_metadata();
	}

	void patch(ssize_t off, const buffer& data) override
	{
		m_patches[check_offset(this, off)] = data;
	}

	protected:
	fwimage_base() = default;

	virtual void read_metadata() = 0;
	virtual void update_metadata() = 0;
	virtual void set_version(const vector<uint8_t>& v) = 0;

	private:

	unique_ptr<istream> m_fs;
	// key = offset
	map<size_t, buffer> m_patches;
	size_t m_size;
};

class fwimage_dni : public fwimage_base
{
	public:
	unique_ptr<fwimage_base> create() const override
	{
		return make_unique<fwimage_dni>();
	}

	string type() const override { return "dni"; }

	string version() const override
	{
		return m_hdr.at("version");
	}

	protected:
	static constexpr auto header_size = 128;

	void read_metadata() override
	{
		istringstream hdr(read(0, header_size));
		string line;

		while (getline(hdr, line) && isalpha(line[0])) {
			auto i = line.find(':');
			if (i == string::npos) {
				break;
			}

			auto key = line.substr(0, i);
			if (key.empty()) {
				break;
			}

			m_hdr[key] = line.substr(i + 1);
			m_hdr_keys.push_back(key);
		}

		if (m_hdr_keys.empty() || m_hdr_keys[0] != "device") {
			throw invalid_argument("bad magic");
		}

		auto version = m_hdr.at("version");
		if (tolower(version.at(0)) == 'v') {
			m_version_prefix = version.at(0);
			m_hdr["version"] = version.substr(1);
		} else {
			m_version_prefix = 0;
		}

		// throw if this field 't exist. not sure if hd_id is required too, but
		// OpenWRT's mkdniimg tool doesn't add it unless `-H <hd_id>` is specified.
		(void) m_hdr.at("region");

		m_checksum = read(-1, 1).at(0);

		if (m_checksum != calc_checksum()) {
			throw runtime_error("checksum error");
		}
	}

	void set_version(const vector<uint8_t>& v) override
	{
		m_hdr["version"] = join_version(v);
	}

	void update_metadata() override
	{
		string hdr;

		for (auto key : m_hdr_keys) {
			auto value = m_hdr[key];
			if (key == "version" && m_version_prefix) {
				value = m_version_prefix + value;
			}

			hdr.append(key + ":" + value + "\n");
		}

		if (hdr.size() > header_size) {
			throw runtime_error("header size out of range");
		}

		hdr.resize(header_size);

		patch(0, hdr);
		patch(-1, string(1, calc_checksum()));
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

	bool has(const string& key) const
	{
		return m_hdr.find(key) != m_hdr.end();
	}

	map<string, string> m_hdr;
	vector<string> m_hdr_keys;
	uint8_t m_checksum;
	char m_version_prefix;
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
		return join_version(m_version);
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

		auto v = read(version_offset, version_len);
		m_version = { v.begin(), v.end() };

		m_hdr_checksum = read<big_uint32_buf_t>(hdr_checksum_offset);

		if (m_hdr_checksum.value() != calc_hdr_checksum()) {
			throw runtime_error("checksum error");
		}
	}

	void update_metadata() override
	{
		patch(version_offset, to_buffer(m_version.data(), m_version.size()));
		m_hdr_checksum = calc_hdr_checksum();
		patch(hdr_checksum_offset, to_buffer(m_hdr_checksum));
	}

	void set_version(const vector<uint8_t>& v) override
	{
		m_version = v;
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
	vector<uint8_t> m_version { 0, 0, 0, 0, 0, 0, 0 };
	big_uint32_buf_t m_hdr_checksum;
};

class fwimage_rax : public fwimage_base
{
	public:
	unique_ptr<fwimage_base> create() const override
	{
		return make_unique<fwimage_rax>();
	}

	string type() const override { return "rax"; }

	string version() const override
	{
		return join_version(split_version(m_hdr.at(hdr_field_img_version)));
	}

	protected:
	static constexpr uint16_t hdr_field_unknown = 0x0000;
	static constexpr uint16_t hdr_field_checksum = 0x0001;
	static constexpr uint16_t hdr_field_img_version = 0x0002;
	static constexpr uint16_t hdr_field_unk_version = 0x0003;

	void read_metadata() override
	{
		const auto magic = "\x00\x01\x00\x20"s;
		if (read(0, 4) != magic) {
			throw runtime_error("bad magic");
		}

		size_t off = 0;

		while (true) {
			uint16_t t = read<big_uint16_buf_t>(off).value();
			uint16_t len = read<big_uint16_buf_t>(off + 2).value();
			if (t == hdr_field_checksum && !len) {
				break;
			}

			m_hdr[t] = read(off + 4, len);
			m_hdr_keys.push_back(t);

			auto val = m_hdr[t];

			off += (len + 4);
		}

		(void) m_hdr.at(hdr_field_img_version);

		auto checksum = calc_checksum();

		if (m_hdr.at(hdr_field_checksum) != checksum) {
			cerr << to_hex(m_hdr.at(hdr_field_checksum)) << endl;
			cerr << to_hex(checksum) << endl;
			throw runtime_error("checksum error");
		}
	}

	void update_metadata() override
	{
		throw runtime_error(__PRETTY_FUNCTION__);
	}

	void set_version(const vector<uint8_t>&) override
	{
		throw runtime_error(__PRETTY_FUNCTION__);
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

	map<uint16_t, buffer> m_hdr;
	vector<uint16_t> m_hdr_keys;
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
	void set_version(const vector<uint8_t>&) override
	{
		throw invalid_argument("image type doesn't support version patching");
	}

	void update_metadata() override {}
	void read_metadata() override
	{
		static const map<buffer, string> signatures {
			{ "PK\x03\x04",       "zip" },
			{ "HDR0",             "trx" },
			{ "\x27\x05\x19\x56", "uimage" },
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

unique_ptr<fwimage> fwimage::open(const string& filename)
{
	return fwimage_open_or_parse(filename, "");
}

unique_ptr<fwimage> fwimage::parse(const buffer& buf)
{
	return fwimage_open_or_parse("", buf);
}
}
