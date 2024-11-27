#include <iostream>
#include "buffer.h"
using namespace std;
using namespace nmrpflash;

int main(int argc, char** argv)
{
	uint32_t ip_and_mask[] = { htonl(0xc0a80001), htonl(0xffffff00) };

	auto b1 = to_buffer(ip_and_mask);
	auto b2 = to_buffer(0x11223344);
	auto b3 = to_buffer("foobar"s);
	auto b4 = to_buffer("barfoo");

	cout << to_string(b1) << endl;
	cout << to_string(b2) << endl;
	cout << to_string(b3) << endl;
	cout << to_string(b4) << endl;
}
