#include <map>
#include "fwimage.h"
using namespace std;

namespace nmrpflash {
namespace {

constexpr map<fwimage::file_format, string> signatures = {
	{ fwimage::chk, "\x2a\x23\x24\x53" },
	{ fwimage::dni, "device:" },
	{ fwimage::rax, "\x00\x01\x00\x20" },
};

buffer read_is(const shared_ptr<istream>& in, size_t n, bool partial = false)
{
	buffer ret(n);
	in->read(reinterpret_cast<char*>(ret.data()), ret.size());

	if (ret->gcount() < ret.size()) {
		if (partial) {
			ret.resize(ret->gcount());
		} else {
			throw runtime_error("failed to read " + to_string(n) + "b");
		}
	}

	return ret;
}

class fwhelper
{
	public:
	void read_metadata(istream& in, string& version, buffer& checksum, size_t& size) const = 0;
	buffer patch_version(istream& in, const string& version) const = 0;
};

fwimage::fwimage(const string& filename)
: m_fs(new ifstream(filename.c_str(), ios::in | ios::binary)), m_format(fwimage::unknown)
{
	if (!m_fs->good()) {
		throw invalid_argument(filename + ": error opening file");
	}

	try {
		do {
			string magic = read_is(m_fs, 4);

			for (auto s : signatures) {
				if (magic == s.second) {
					m_format = s.first;
					break;
				}
			}

			m_fs->seekg(0);

			if (!m_format) {
				return;
			} else if (m_format == fwimage::chk) {
				m_hlp = make_shared<chk_helper>();
			} else if (m_format == fwimage::dni) {
				m_hlp = make_shared<dni_helper>();
			} else if (m_format == fwimage::rax) {
				m_hlp = make_shared<rax_helper>();
			}
		} while (0);
	} catch (const exception& e) {
		throw invalid_argument(filename + ": error reading header: "s + e.what());
	}

	throw invalid_argument(filename + ": error reading header");
}


