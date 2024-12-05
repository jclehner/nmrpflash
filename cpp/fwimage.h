#ifndef NMRPFLASH_FWIMAGE_H
#define NMRPFLASH_FWIMAGE_H
#include <fstream>
#include <memory>
#include <string>

namespace nmrpflash {


class fwimage
{
	public:
	enum file_format
	{
		unknown = 0,
		chk,
		dni,
		trx,
		rax,
		uimage,
		tar,
		zip,
	};

	fwimage(const std::string& filename);

	const std::string& version() const;
	const buffer& checksum() const;

	file_format format() const;

	std::string read(size_t n) const;

	void patch_version(const std::string& version);

	private:
	std::shared_ptr<std::istream> m_stream;
	file_format m_format;
	std::string m_version;
	buffer m_checksum;
};
}
