#ifndef NMRPFLASH_FWIMAGE_H
#define NMRPFLASH_FWIMAGE_H
#include <fstream>
#include <sstream>
#include <utility>
#include <memory>
#include <string>

namespace nmrpflash {
typedef std::string buffer;

class fwimage
{
	public:
	class impl;

	fwimage(const std::string& filename);
	~fwimage();

	size_t size() const;

	bool eof() const;
	void rewind() const;
	std::string read(size_t n) const;

	// returns type of firmware image (such as "dni", "chk", etc.), or empty string
	std::string type() const;
	// only valid if type() is non-empty
	std::string version() const;
	// only valid if type() is non-empty
	buffer checksum() const;

	void patch_version(const std::string& version);

	private:
	mutable std::stringstream m_ss;

	std::unique_ptr<impl> m_impl;
};
}
#endif
