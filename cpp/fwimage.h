#ifndef NMRPFLASH_FWIMAGE_H
#define NMRPFLASH_FWIMAGE_H
#include <functional>
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
	static std::unique_ptr<fwimage> parse(const buffer& buf);

	virtual ~fwimage() = default;

	virtual size_t size() const = 0;
	virtual buffer read(ssize_t off, size_t n) const = 0;

	buffer read() const;
	void read(std::function<void(const buffer&)> f, size_t n, ssize_t off = 0) const;

	// returns type of firmware image (such as "dni", "chk", etc.), or empty string
	virtual std::string type() const = 0;
	// only valid if type() is non-empty
	virtual std::string version() const = 0;

	virtual void version(const std::string& v) = 0;

	virtual void patch(ssize_t offset, const buffer& data, size_t len) = 0;
	void patch(ssize_t offset, const buffer& data);

	protected:
	fwimage() = default;
};
}
#endif
