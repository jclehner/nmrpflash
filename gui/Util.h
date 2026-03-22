/**
 * nmrpflash - Netgear Unbrick Utility
 * Copyright (C) 2016-2026 Joseph Lehner <joseph.c.lehner@gmail.com>
 *
 * nmrpflash is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nmrpflash is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with nmrpflash.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef NMRPFLASH_GUI_UTIL_H
#define NMRPFLASH_GUI_UTIL_H
#include <filesystem>
#include <utility>
#include <string>
#include <cerrno>
#include <system_error>
#include <wx/stream.h>
#include <boost/algorithm/string.hpp>
#include "../nmrpd.h"

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