#include <stdio.h>
#include "nmrpd.h"

void usage()
{
	printf(
			"Usage: nmrpd [options] [command] [command args]\n"
			"\n"
			"Available options:\n"
			" -m [mac]        MAC address of target device (xx:xx:xx:xx:xx:xx)\n"
			" -a [ipaddr]     IP address to assign to target device\n"
			" -M [netmask]    Subnet mask to assign to target device\n"
			" -t [timeout]    Timeout (in milliseconds) for regular messages\n"
			" -T [timeout]    Time to wait after successfull TFTP upload\n"
			" -p [port]       Port to use for TFTP upload\n"
			" -i [interface]  Network interface directly connected to device\n"
			"\n"
			"Available commands:\n"
			" set-region      Set region of device\n"
			" upload-firmware Upload new firmware\n"
			" upload-strings  Upload string table\n"
			"\n"
	  );
}



int main(int argc, char **argv)
{
	struct nmrpd_args args = {
		.rx_timeout = 200,
		.ul_timeout = 60000,
		.filename = argc >= 2 ? argv[1] : NULL,
		.ipaddr = "192.168.2.2",
		.ipmask = "255.255.255.0",
		.intf = "enp4s0",
		.mac = "ff:ff:ff:ff:ff:ff",
		.op = NMRP_UPLOAD_FW,
		.port = 69,
		.force_root = 0
	};

	return nmrp_do(&args);
}
