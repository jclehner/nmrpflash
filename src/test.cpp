#include <iostream>
#include "eth_interface.h"
using namespace std;
using namespace nmrpflash;

int main(int argc, char** argv)
{
	auto interfaces = eth_interface::list();
	for (auto i : interfaces) {
		cout << i.get_pcap_name() << endl;
		for (auto net : i.list_networks()) {
			cout << "  " << net << endl;
		}
	}
}
