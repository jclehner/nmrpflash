#include <arpa/inet.h>
#include <stdexcept>
#include <iostream>
#include <cstring>
#include <vector>
#include <map>
#include "fwimage.h"
using namespace std;

namespace nmrpflash {
namespace {

typedef istreambuf_iterator<char> isb_it;

const map<string, buffer> signatures {
	{ "chk", "\x2a\x23\x24\x53" },
	{ "dni", "device:" },
	{ "rax", "\x00\x01\x00\x20" },
};

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

vector<uint8_t> parse_version(const string& str)
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

string version_to_string(const vector<uint8_t>& version)
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

uint32_t read_u32(istream& is)
{
	uint32_t ret;
	is.read(reinterpret_cast<char*>(&ret), sizeof(ret));
	return ntohl(ret);
}

void write_u32(ostream& os, uint32_t val)
{
	val = htonl(val);
	os.write(reinterpret_cast<char*>(&val), sizeof(val));
}
}

class fwimage::impl
{
	public:
	impl() {}
	virtual ~impl() {}

	virtual std::string type() const { return ""; }
	virtual void read_metadata(istream& is) {}
	virtual bool is_checksum_valid(istream& is) const { return false; }

	virtual vector<uint8_t> version() const { return {}; }

	virtual void patch_version(iostream& is, const vector<uint8_t>& v)
	{
		throw runtime_error("image format doesn't support version patching");
	}
};

namespace {
class chk_impl : public fwimage::impl
{
	public:
	static constexpr auto magic = "\x2a\x23\x24\x5e";

	virtual string type() const override { return "chk"; }
	virtual vector<uint8_t> version() const override { return m_version; }

	virtual void read_metadata(istream& is) override
	{
		is.seekg(hdr_len_offset);
		m_hdr_len = read_u32(is);

		m_region = is.get() & 0xff;

		for (size_t i = 0; i < m_version.size(); ++i) {
			m_version[i] = is.get() & 0xff;
		}

		is.seekg(hdr_chksum_offset);
		m_hdr_chksum = read_u32(is);

		if (!is) {
			throw runtime_error("error reading header fields");
		}
	}

	virtual bool is_checksum_valid(istream& is) const override
	{
		return m_hdr_chksum == calc_hdr_checksum(is);
	}

	virtual void patch_version(iostream& is, const vector<uint8_t>& v) override
	{
		m_version = v;
		is.seekp(version_offset);

		for (uint8_t n : m_version) {
			is.put(n);
		}

		is.seekp(hdr_chksum_offset);
		write_u32(is, calc_hdr_checksum(is));
	}

	private:
	static constexpr auto hdr_len_offset = 1 * 4;
	static constexpr auto version_offset = 2 * 4 + 1;
	static constexpr auto hdr_chksum_offset = 9 * 4;

	uint32_t m_hdr_len;
	uint8_t m_region;
	vector<uint8_t> m_version { 0, 0, 0, 0, 0, 0, 0 };
	uint32_t m_hdr_chksum;

	uint32_t calc_hdr_checksum(istream& is) const
	{
		is.seekg(0);

		uint32_t c0 = 0;
		uint32_t c1 = 0;
		size_t i;

		for (i = 0; i < hdr_chksum_offset; ++i) {
			c0 += is.get() & 0xff;
			c1 += c0;
		}

		for (; i < hdr_chksum_offset + 4; ++i) {
			// discard
			is.get();
			c1 += c0;
		}

		for (; i < m_hdr_len; ++i) {
			c0 += is.get() & 0xff;
			c1 += c0;
		}

		uint32_t b;
		b = (c0 & 65535) + ((c0 >> 16) & 65535);
		c0 = ((b >> 16) + b) & 65535;
		b = (c1 & 65535) + ((c1 >> 16) & 65535);
		c1 = ((b >> 16) + b) & 65535;

		return ((c1 << 16) | c0);
	}
};

class dni_impl : public fwimage::impl
{
	public:
	static constexpr auto header_size = 128;
	static constexpr auto magic = "device:";

	virtual string type() const override { return "dni"; }

	virtual void read_metadata(istream& is) override
	{
		is.seekg(0);

		istringstream header(read_is(is, header_size));
		string line;

		while (getline(header, line) && isalpha(line[0])) {
			auto i = line.find(':');
			if (i == string::npos) {
				break;
			}

			auto key = line.substr(0, i);
			auto value = line.substr(i + 1);

			m_hdr[key] = value;
		}

		if (!has("device") || !has("version") || !has("hd_id")) {
			throw invalid_argument("incomplete header");
		}

		parse_version(m_hdr.at("version"));

		is.seekg(-1, ios::end);
		m_checksum = string(1, is.peek() & 0xff);
	}

	virtual bool is_checksum_valid(istream& is) const override
	{
		return m_checksum.at(0) == calc_checksum(is);
	}

	virtual vector<uint8_t> version() const override
	{
		return parse_version(m_hdr.at("version"));
	}

	virtual void patch_version(iostream& is, const vector<uint8_t>& v) override
	{
		m_hdr["version"] = "V" + version_to_string(v);

		is.seekp(0);
		write_hdr(is, "device");
		write_hdr(is, "version");
		write_hdr(is, "region");
		write_hdr(is, "hd_id");

		ssize_t diff = header_size - is.tellp();
		if (diff < 0) {
			throw invalid_argument("patched header size exceeds maximum of " + to_string(header_size));
		}

		is << string(diff, '\x00');

		is.seekp(-1, ios::end);
		is.put(calc_checksum(is));
	}

	private:
	bool has(const string& key) const
	{
		return m_hdr.find(key) != m_hdr.end();
	}

	void write_hdr(iostream& is, const string& key)
	{
		is << key << ':' << m_hdr.at(key) << "\n";
	}

	uint8_t calc_checksum(istream& is) const
	{
		uint8_t ret = 0;
		int c;

		is.seekg(0);
		while (is.peek() != EOF) {
			c = is.get();
			ret += c;
		}

		// last byte read was the checksum itself
		return 0xff - (ret - c);
	}

	map<string, string> m_hdr;
	buffer m_checksum;
};

class rax_impl

template<class T> auto fwimage_create(istream& is)
{
	is.seekg(0);
	unique_ptr<fwimage::impl> ret;

	if (read_is(is, strlen(T::magic)) == T::magic) {
		ret = make_unique<T>();
	}

	is.seekg(0);

	return ret;
}

auto fwimage_detect(istream& is)
{
	auto p = fwimage_create<dni_impl>(is);
	if (p) {
		return p;
	}

	p = fwimage_create<chk_impl>(is);
	if (p) {
		return p;
	}

#if 0
	p = fwimage_create<rax_impl>(is);
	if (p) {
		return p;
	}
#endif

	return make_unique<fwimage::impl>();
}
}

fwimage::fwimage(const string& filename)
{
	ifstream fs(filename.c_str(), ios::in | ios::binary);

	if (!fs.seekg(0) || !fs.good()) {
		throw invalid_argument(filename + ": error accessing firmware file");
	}

	m_ss << fs.rdbuf() << flush;

#if 0
	if (!fs.eof() || !fs.good()) {
		throw runtime_error(filename + ": error buffering firmware file");
	}
#endif

	m_impl = fwimage_detect(m_ss);

	if (!m_impl->type().empty()) {
		try {
			m_impl->read_metadata(m_ss);
			if (m_impl->is_checksum_valid(m_ss)) {
				return;
			} else {
				cerr << "invalid checksum" << endl;
			}
		} catch (const exception& e) {
			throw runtime_error(filename + ": error reading header: "s + e.what());
		}
	}

	m_impl = make_unique<fwimage::impl>();
}

fwimage::~fwimage() {}

size_t fwimage::size() const
{
	return m_ss.view().size();
}

void fwimage::rewind() const
{
	m_ss.seekg(0);
}

bool fwimage::eof() const
{
	return m_ss.eof();
}

buffer fwimage::read(size_t size) const
{
	return read_is(m_ss, size);
}

string fwimage::type() const
{
	return m_impl->type();
}

string fwimage::version() const
{
	return version_to_string(m_impl->version());
}

void fwimage::patch_version(const string& v)
{
	auto v_old = m_impl->version();
	auto v_new = parse_version(v);
	if (v_new.size() != v_old.size()) {
		throw invalid_argument("version format mismatch ("
			+ version_to_string(v_new) + " vs " + version_to_string(v_old) + ")");
	}

	m_impl->patch_version(m_ss, v_new);
}
}
