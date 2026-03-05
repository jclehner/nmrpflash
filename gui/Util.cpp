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