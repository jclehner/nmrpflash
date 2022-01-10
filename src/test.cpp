#include <iostream>
#include "eth_interface.h"
using namespace std;
using namespace nmrpflash;

int main(int argc, char** argv)
{
	auto interfaces = eth_interface::list();
	for (auto i : interfaces) {
		cout << left << setw(16) << i.get_name();
		cout << " " << i.get_mac_addr() << " ";

		auto pretty = i.get_pretty_name();
		if (!pretty.empty()) {
			cout << " (" << pretty << ")";
		}

		cout << endl;

		for (auto net : i.list_networks()) {
			cout << "- " << net << endl;
		}
	}
}
