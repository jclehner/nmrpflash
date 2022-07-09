#include <boost/range/adaptor/filtered.hpp>
#include <iostream>
#include "eth_interface.h"
using namespace std;
using namespace nmrpflash;

void print(const eth_interface& intf)
{
	using boost::adaptors::filtered;

	cout << left << setw(17) << intf.get_name();

	auto nets = intf.list_networks(true);

	if (nets.empty()) {
		cout << string(18, ' ');
	} else {
		auto net = stringify(*nets.begin());
		net.resize(18, ' ');
		cout << net;
	}

	cout << "  " << intf.get_mac_addr();

	auto pretty = intf.get_pretty_name();
	if (!pretty.empty()) {
		cout << "  (" << pretty << ")";
	}

	cout << endl;
}

int main(int argc, char** argv)
{
	if (argc < 2) {
		auto interfaces = eth_interface::list();
		for (auto i : interfaces) {
			print(i);
		}
	} else {
		print(eth_interface(argv[1]));
	}
}
