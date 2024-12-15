#include <boost/polymorphic_pointer_cast.hpp>
#include <boost/endian/buffers.hpp>
#include <gsl/pointers>
#include <stdexcept>
#include <iostream>
#include <cstring>
#include <vector>
#include <map>
#include "fwimage.h"
using namespace std;
using boost::endian::big_uint32_buf_t;
using boost::polymorphic_pointer_cast;
using gsl::not_null;

namespace nmrpflash {
namespace {
const auto chunk_size = 1024 * 64;

buffer read_is(istream& in, size_t n, bool partial = false)
{
	buffer ret(n, '\x00');
	in.read(reinterpret_cast<char*>(ret.data()), ret.size());

	if (in.gcount() < ret.size()) {
		if (partial || in.eof()) {
			ret.resize(in.gcount());
		} else {
			throw runtime_error("short read: " + to_string(n) + "b");
		}
	}

	return ret;
}

vector<uint8_t> split_version(const string& str)
{
	istringstream istr(str);

	if (istr.peek() == 'V') {
		istr.get();
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
			istr.get();
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

class fwimage_base : public fwimage
{
	public:
	virtual ~fwimage_base() {}

	virtual unique_ptr<fwimage_base> create() const = 0;

	void open(const string& filename)
	{
		m_fs.exceptions(ios::failbit | ios::badbit);
		m_fs.open(filename.c_str(), ios::binary | ios::ate);
		m_size = m_fs.tellg();
		m_fs.seekg(0);
		read_metadata();
	}

	size_t size() const override
	{
		return m_size;
	}

	buffer read(ssize_t offset, size_t size) const override
	{
		if (offset < 0) {
			offset += this->size();
		}

		m_fs.seekg(offset);

		buffer buf = read_is(m_fs, size);

		// example:
		//   read(1024, 64)
		//
		//   m_patch[1024] = (4) "\xaa\xbb\xcc\xdd";
		//   m_patch[1086] = (3) "foo";

		for (auto [patch_off, patch_buf] : m_patches) {
			if (patch_off < offset || patch_off > (offset + size)) {
				continue;
			}

			size_t buf_off = patch_off - offset;
			size_t patch_size = size - buf_off;

			buf.replace(buf_off, patch_size, patch_buf.substr(0, patch_size));
		}

		return buf;
	}

	template<class T> T read(ssize_t offset) const
	{
		return unpack<boost::endian::order::native, T>(read(offset, sizeof(T)));
	}

	virtual void version(const string& v) override
	{
		auto v_old = split_version(fwimage::version());
		auto v_new = split_version(v);

		if (v_old.size() != v_new.size()) {
			throw invalid_argument("invalid version format");
		}

		version(v_new);
		update_metadata();
	}

	virtual void patch(size_t offset, const buffer& data) override
	{
		m_patches[offset] = data;
	}

	protected:
	fwimage_base() {}

	virtual void read_metadata() = 0;
	virtual void update_metadata() = 0;
	virtual void version(const vector<uint8_t>& v) = 0;

	private:
	mutable ifstream m_fs;
	// key = offset
	map<size_t, buffer> m_patches;
	size_t m_size;
};

class fwimage_dni : public fwimage_base
{
	public:
	virtual unique_ptr<fwimage_base> create() const override
	{
		return make_unique<fwimage_dni>();
	}

	virtual string type() const override { return "dni"; }

	virtual string version() const override
	{
		return m_hdr.at("version");
	}

	protected:
	static constexpr auto header_size = 128;

	virtual void read_metadata() override
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

		if (m_hdr_keys.at(0) != "device") {
			throw runtime_error("unexpected first header field: " + m_hdr_keys[0]);
		}

		(void) split_version(m_hdr.at("version"));
		// throw if one of these fields doesn't exist
		(void) m_hdr.at("hd_id");
		(void) m_hdr.at("region");

		m_checksum = read(-1, 1).at(0);

		if (m_checksum != calc_checksum()) {
			throw runtime_error("checksum error");
		}
	}

	virtual void version(const vector<uint8_t>& v) override
	{
		m_hdr["version"] = join_version(v);
	}

	virtual void update_metadata() override
	{
		string hdr;

		for (auto key : m_hdr_keys) {
			auto value = m_hdr[key];
			if (key == "version") {
				value = "V" + value;
			}

			hdr.append(key + ":" + value + "\n");
		}

		if (hdr.size() > header_size) {
			throw runtime_error("header size out of range");
		}

		hdr.resize(header_size);

		patch(0, hdr);
		patch(size() - 1, string(1, calc_checksum()));
	}

	private:
	uint8_t calc_checksum() const
	{
		uint8_t ret = 0;
		size_t off = 0;
		uint8_t last_c = 0;

		buffer data;

		while (!(data = read(off, chunk_size)).empty()) {
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
};

class fwimage_chk : public fwimage_base
{
	public:
	virtual unique_ptr<fwimage_base> create() const override
	{
		return make_unique<fwimage_chk>();
	}

	virtual string type() const override { return "chk"; }
	virtual string version() const override
	{
		return join_version(m_version);
	}

	protected:
	static constexpr auto hdr_len_offset = 1 * 4;
	static constexpr auto region_offset = 2 * 4;
	static constexpr auto version_offset = region_offset + 1;
	static constexpr auto version_len = 7;
	static constexpr auto hdr_checksum_offset = 9 * 4;

	virtual void read_metadata() override
	{
		m_hdr_len = read<big_uint32_buf_t>(hdr_len_offset);
		m_region = read(region_offset, 1).at(0);

		auto v = read(version_offset, version_len);
		m_version = { v.begin(), v.end() };

		m_hdr_checksum = read<big_uint32_buf_t>(hdr_checksum_offset);

		if (m_hdr_checksum.value() != calc_hdr_checksum()) {
			throw runtime_error("checksum error");
		}
	}

	virtual void update_metadata() override
	{
		patch(version_offset, to_buffer(m_version.data(), m_version.size()));
		m_hdr_checksum = calc_hdr_checksum();
		patch(hdr_checksum_offset, to_buffer(m_hdr_checksum));
	}

	virtual void version(const vector<uint8_t>& v) override
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
			c0 += hdr.at(i);
			c1 += c0;
		}

		for (; i < hdr_checksum_offset + 4; ++i) {
			// ignore header checksum (same effect as all-zero checksum)
			c1 += c0;
		}

		for (; i < m_hdr_len.value(); ++i) {
			c0 += hdr.at(i);
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

class fwimage_generic : public fwimage_base
{
	public:
	virtual unique_ptr<fwimage_base> create() const override
	{
		return make_unique<fwimage_chk>();
	}

	virtual string type() const override { return ""; }
	virtual string version() const override { return ""; }

	virtual void version(const vector<uint8_t>& v) override
	{
		throw invalid_argument("image type doesn't support version patching");
	}

	protected:
	virtual void update_metadata() override {}
	virtual void read_metadata() override {}
};
}

fwimage::~fwimage() {}

unique_ptr<fwimage> fwimage::open(const string& filename)
{
	typedef unique_ptr<fwimage_base> fwimage_ptr;
	static vector<fwimage_ptr> types;
	if (types.empty()) {
		types.emplace_back(new fwimage_chk());
		types.emplace_back(new fwimage_dni());
		// this must be the last element
		types.emplace_back(new fwimage_generic());
	}

	for (const auto& t : types) {
		try {
			auto ret = t->create();
			ret->open(filename);
			return ret;
		} catch (const ios_base::failure& e) {
			throw e;
		} catch (const exception& e) {
			if (t->type().empty()) {
				// we've reached fwimage_generic - bail out!
				throw e;
			}
			cerr << t->type() << ": error: " << e.what() << endl;
		}
	}

	// fwimage_generic::open() shouldn't fail for anything other than
	// iostream errors

	throw logic_error("unreachable");
}
}
