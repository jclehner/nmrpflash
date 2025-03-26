#include <iomanip>
#include <sstream>
#include "buffer.h"
using namespace std;

namespace nmrpflash {
string to_hex(const buffer& b)
{
	ostringstream ostr;
	for (char c : b) {
		ostr << setw(2) << setfill('0') << hex << (c & 0xff);
	}

	return ostr.str();
}
}
