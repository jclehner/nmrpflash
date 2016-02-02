/**
 * nmrp-flash - Netgear Unbrick Utility
 * Copyright (C) 2016 Joseph Lehner <joseph.c.lehner@gmail.com>
 *
 * nmrp-flash is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nmrp-flash is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with nmrp-flash.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include "nmrpd.h"
#include "ethsock.h"

void usage(FILE *fp)
{
	fprintf(fp,
			"Usage: nmrp-flash [OPTIONS...]\n"
			"\n"
			"Options (-a, -i and -f are mandatory):\n"
			" -a <ipaddr>     IP address to assign to target device\n"
			" -f <firmware>   Firmware file\n"
			" -i <interface>  Network interface directly connected to device\n"
			" -m <mac>        MAC address of target device (xx:xx:xx:xx:xx:xx)\n"
			" -M <netmask>    Subnet mask to assign to target device\n"
			" -t <timeout>    Timeout (in milliseconds) for regular messages\n"
			" -T <timeout>    Time to wait after successfull TFTP upload\n"
			" -p <port>       Port to use for TFTP upload\n"
			" -V              Print version and exit\n"
			" -L              List network interfaces\n"
			" -h              Show this screen\n"
			"\n"
			"Example:\n"
			"\n"
			"$ sudo nmrp-flash -a 192.168.1.254 -i eth0 -f firmware.bin\n"
			"\n"
			"nmrp-flash v%s, Copyright (C) 2016 Joseph C. Lehner\n"
			"nmrp-flash is free software, licensed under the GNU GPLv3.\n"
			"Source code at https://github.com/jclehner/nmrp-flash\n"
			"\n",
			NMRPD_VERSION
	  );
}

int main(int argc, char **argv)
{
	int c, val, max;
	struct nmrpd_args args = {
		.rx_timeout = 200,
		.ul_timeout = 60000,
		.tftpcmd = NULL,
		.filename = NULL,
		.ipaddr = NULL,
		.ipmask = "255.255.255.0",
		.intf = NULL,
		.mac = "ff:ff:ff:ff:ff:ff",
		.op = NMRP_UPLOAD_FW,
		.port = 69,
		.force_root = 1
	};

	opterr = 0;

	while ((c = getopt(argc, argv, "a:f:i:m:M:p:t:T:hLV")) != -1) {
		max = 0x7fffffff;
		switch (c) {
			case 'a':
				args.ipaddr = optarg;
				break;
			case 'f':
				args.filename = optarg;
				break;
			case 'i':
				args.intf = optarg;
				break;
			case 'm':
				args.mac = optarg;
				break;
			case 'M':
				args.ipmask = optarg;
				break;
			case 'p':
				max = 0xffff;
			case 'T':
			case 't':
				val = atoi(optarg);
				if (val <= 0 || val > max) {
					fprintf(stderr, "Invalid numeric value for -%c.\n", c);
					return 1;
				}

				if (c == 'p') {
					args.port = val;
				} else if (c == 't') {
					args.rx_timeout = val;
				} else {
					args.ul_timeout = val;
				}

				break;
			case 'V':
				printf("nmrp-flash v%s\n", NMRPD_VERSION);
				return 0;
			case 'L':
				return ethsock_list_all();
			case 'h':
				usage(stdout);
				return 0;
			default:
				usage(stderr);
				return 1;
		}
	}

	if (!args.filename || !args.intf || !args.ipaddr) {
		usage(stderr);
		return 1;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "This program must be run as root!\n");
		return 1;
	}

	return nmrp_do(&args);
}
