#ifndef NMRPFLASH_GUI_UTIL_H
#define NMRPFLASH_GUI_UTIL_H
#include <filesystem>
#include <string>
#include <cerrno>
#include <system_error>
#include <wx/stream.h>

namespace nmrpflash {
namespace fs = std::filesystem;

class errno_error : public std::system_error
{
public:
    errno_error(int ev=errno)
    : std::system_error(ev, std::system_category())
    {}

    template<class T> errno_error(const T& what_arg, int ev=errno)
    : std::system_error(ev, std::system_category(), what_arg)
    {}
};

bool ReadLine(wxInputStream* stream, std::string& buf, bool raw=false);
}
#endif