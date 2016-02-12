/**
 * nmrpflash - Netgear Unbrick Utility
 * Copyright (C) 2016 Joseph Lehner <joseph.c.lehner@gmail.com>
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

#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include "nmrpd.h"

int verbosity = 0;

void usage(FILE *fp)
{
	fprintf(fp,
			"Usage: nmrpflash [OPTIONS...]\n"
			"\n"
			"Options (-a, -i and -f and/or -c are mandatory):\n"
			" -a <ipaddr>     IP address to assign to target device\n"
			" -c <command>    Command to run before (or instead of) TFTP upload\n"
			" -f <firmware>   Firmware file\n"
			" -i <interface>  Network interface directly connected to device\n"
			" -m <mac>        MAC address of target device (xx:xx:xx:xx:xx:xx)\n"
			" -M <netmask>    Subnet mask to assign to target device\n"
			" -t <timeout>    Timeout (in milliseconds) for regular messages\n"
			" -T <timeout>    Time (seconds) to wait after successfull TFTP upload\n"
			" -p <port>       Port to use for TFTP upload\n"
#ifdef NMRPFLASH_TFTP_TEST
			" -U              Test TFTP upload\n"
#endif
			" -v              Be verbose\n"
			" -V              Print version and exit\n"
			" -L              List network interfaces\n"
			" -h              Show this screen\n"
			"\n"
			"Example:\n"
			"\n"
#ifndef NMRPFLASH_WINDOWS
			"$ sudo nmrpflash -i eth0 -a 192.168.1.254 -f firmware.bin\n"
#else
			"C:\\> nmrpflash.exe -i net0 -a 192.168.1.254 -f firmware.bin\n"
#endif
			"\n"
			"nmrpflash %s, Copyright (C) 2016 Joseph C. Lehner\n"
			"nmrpflash is free software, licensed under the GNU GPLv3.\n"
			"Source code at https://github.com/jclehner/nmrpflash\n"
			"\n",
			NMRPFLASH_VERSION
	  );
}

int main(int argc, char **argv)
{
	int c, val, max;
	struct nmrpd_args args = {
		.rx_timeout = 200,
		.ul_timeout = 120000,
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
#ifdef NMRPFLASH_WINDOWS
	WSADATA wsa;

	val = WSAStartup(MAKEWORD(2, 2), &wsa);
	if (val != 0) {
		win_perror2("WSAStartup", val);
		return 1;
	}
#endif

	opterr = 0;

	while ((c = getopt(argc, argv, "a:c:f:i:m:M:p:t:T:hLVvU")) != -1) {
		max = 0x7fffffff;
		switch (c) {
			case 'a':
				args.ipaddr = optarg;
				break;
			case 'c':
				args.tftpcmd = optarg;
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
					args.ul_timeout = val * 1000;
				}

				break;
			case 'V':
				printf("nmrpflash %s\n", NMRPFLASH_VERSION);
				val = 0;
				goto out;
			case 'v':
				++verbosity;
				break;
			case 'L':
				val = ethsock_list_all();
				goto out;
			case 'h':
				usage(stdout);
				val = 0;
				goto out;
#ifdef NMRPFLASH_TFTP_TEST
			case 'U':
				if (args.ipaddr && args.filename) {
					val = tftp_put(&args);
					goto out;
				}
				/* fall through */
#endif
			default:
				usage(stderr);
				val = 1;
				goto out;
		}
	}

	if ((!args.filename && !args.tftpcmd) || !args.intf || !args.ipaddr) {
		usage(stderr);
		return 1;
	}

#ifndef NMRPFLASH_WINDOWS
	if (geteuid() != 0) {
		fprintf(stderr, "This program must be run as root!\n");
		return 1;
	}
#endif

	val = nmrp_do(&args);

out:
#ifdef NMRPFLASH_WINDOWS
	WSACleanup();
#endif
	return val;
}
