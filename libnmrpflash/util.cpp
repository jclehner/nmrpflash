#include <boost/process.hpp>
#include "util.h"
using namespace boost::process;
using namespace std;

namespace nmrpflash {
namespace {
template<typename... T> vector<string> run(const string& cmd, const vector<string>& argv)
{
	try {
		ipstream pipe;
		child c(cmd, args(argv), std_out > pipe);

		vector<string> ret;
		string line;

		while (pipe && getline(pipe, line)) {
			ret.push_back(line);
		}

		c.wait();

		return ret;
	} catch (const exception& e) {
		return {};
	}
}

std::string nm_get(const string& dev, const string& property)
{
	auto lines = run("/usr/bin/nmcli", { "-g", property, "device", "show", dev });
	return lines.empty() ? "" : lines[0];
}
}

bool nm_is_managed(const string& dev)
{
	auto s = nm_get(dev, "GENERAL.STATE");
	if (s.find("unmanaged") != string::npos) {
		return false;
	}

	return true;
}

string nm_get_connection(const string& dev)
{
	return nm_get(dev, "GENERAL.CONNECTION");
}
}
