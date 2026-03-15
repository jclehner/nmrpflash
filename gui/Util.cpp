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
#include <wx/stream.h>
#include "Util.h"

namespace nmrpflash {
namespace {
}

bool ReadLine(wxInputStream* stream, std::string& buf, bool raw)
{
	bool ret = false;

	while (stream->CanRead() && !stream->Eof()) {
		int c = stream->GetC();
		if (c < 0) {
			break;
		}

		ret = true;

		if (c == '\n') {
            if (raw) {
                buf += '\n';
            } else if (!buf.empty() && buf.back() == '\r') {
                // remove final CRLF
                buf.resize(buf.length() - 1);
            }

            break;
		}

		buf += c;
	}

	return ret;
}
}