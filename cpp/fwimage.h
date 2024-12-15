#ifndef NMRPFLASH_FWIMAGE_H
#define NMRPFLASH_FWIMAGE_H
#include <fstream>
#include <sstream>
#include <utility>
#include <memory>
#include <string>
#include "buffer.h"

namespace nmrpflash {
class fwimage
{
	public:
	static std::unique_ptr<fwimage> open(const std::string& filename);

	virtual ~fwimage();

	virtual size_t size() const = 0;
	virtual buffer read(ssize_t offset, size_t size) const = 0;

	// returns type of firmware image (such as "dni", "chk", etc.), or empty string
	virtual std::string type() const = 0;
	// only valid if type() is non-empty
	virtual std::string version() const = 0;

	virtual void version(const std::string& v) = 0;

	virtual void patch(size_t offset, const buffer& data) = 0;

	protected:
	fwimage();
};
}
#endif
