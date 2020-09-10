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

void usage(FILE *fp)
{
	fprintf(fp,
			"Usage: nmrpflash [OPTIONS...]\n"
			"\n"
			"Options (-i, and -f or -c are mandatory):\n"
			" -a <ipaddr>     IP address to assign to target device\n"
			" -A <ipaddr>     IP address to assign to selected interface\n"
			" -B              Blind mode (don't wait for response packets)\n"
			" -c <command>    Command to run before (or instead of) TFTP upload\n"
			" -f <firmware>   Firmware file\n"
			" -F <filename>   Remote filename to use during TFTP upload\n"
			" -i <interface>  Network interface directly connected to device\n"
			" -m <mac>        MAC address of target device (xx:xx:xx:xx:xx:xx)\n"
			" -M <netmask>    Subnet mask to assign to target device\n"
			" -t <timeout>    Timeout (in milliseconds) for NMRP packets\n"
			" -T <timeout>    Time (seconds) to wait after successfull TFTP upload\n"
			" -p <port>       Port to use for TFTP upload\n"
#ifdef NMRPFLASH_SET_REGION
			" -R <region>     Set device region (NA, WW, GR, PR, RU, BZ, IN, KO, JP)\n"
#endif
			" -S <n>          Skip <n> bytes of the firmware file\n"
#ifdef NMRPFLASH_TFTP_TEST
			" -U              Test TFTP upload\n"
#endif
			" -v              Be verbose\n"
			" -V              Print version and exit\n"
			" -L              List network interfaces\n"
			" -h              Show this screen\n"
			"\n"
			"Example: (run as "
#ifndef NMRPFLASH_WINDOWS
			"root"
#else
			"administrator"
#endif
			")\n\n"
#ifndef NMRPFLASH_WINDOWS
			"# nmrpflash -i eth0 -f firmware.bin\n"
#else
			"C:\\> nmrpflash.exe -i net0 -f firmware.bin\n"
#endif
			"\n"
			"When using -c, the environment variables IP, PORT, NETMASK\n"
			"and MAC are set to the device IP address, TFTP port, subnet\n"
			"mask and MAC address, respectively.\n"
			"\n"
			"nmrpflash %s, Copyright (C) 2016 Joseph C. Lehner\n"
			"nmrpflash is free software, licensed under the GNU GPLv3.\n"
			"Source code at https://github.com/jclehner/nmrpflash\n"
			"\n",
			NMRPFLASH_VERSION
	  );
}

#ifdef NMRPFLASH_WINDOWS
void require_admin()
{
	SID_IDENTIFIER_AUTHORITY auth = { SECURITY_NT_AUTHORITY };
	PSID group = NULL;
	BOOL admin, success = AllocateAndInitializeSid(
		&auth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &group
	);

	if (success) {
		success = CheckTokenMembership(NULL, group, &admin);
		FreeSid(group);
		if (success) {
			if (!admin) {
				fprintf(stderr, "Error: must be run as administrator\n");
				exit(1);
			} else {
				return;
			}
		}
	}

	fprintf(stderr, "Warning: failed to check administrator privileges\n");
}

void show_exit_prompt()
{
	DWORD pid;
	HWND win = GetConsoleWindow();
	if (!win || !GetWindowThreadProcessId(win, &pid)) {
		return;
	}

	if (GetCurrentProcessId() == pid) {
		printf("Press any key to exit\n");
		getch();
	}
}
#else
void require_admin()
{
	if (getuid() != 0) {
		fprintf(stderr, "Error: must be run as root\n");
		exit(1);
	}
}
#endif

int main(int argc, char **argv)
{
	int c, val, max;
	bool list = false, have_dest_mac = false;
	struct nmrpd_args args = {
		.rx_timeout = 1000,
		.ul_timeout = 5 * 60,
		.tftpcmd = NULL,
		.file_local = NULL,
		.file_remote = NULL,
		.ipaddr_intf = NULL,
		.ipaddr = NULL,
		.ipmask = "255.255.255.0",
		.intf = NULL,
		.mac = "ff:ff:ff:ff:ff:ff",
		.op = NMRP_UPLOAD_FW,
		.port = 69,
		.region = NULL,
		.blind = false,
		.offset = 0,
	};
#ifdef NMRPFLASH_WINDOWS
	char *newpath = NULL;
	char *oldpath = NULL;
	char *windir = NULL;
	WSADATA wsa;

	atexit(&show_exit_prompt);

	val = WSAStartup(MAKEWORD(2, 2), &wsa);
	if (val != 0) {
		win_perror2("WSAStartup", val);
		return 1;
	}


#ifndef _WIN64
	// This dirty hack works around the WOW64 file system redirector[1], which would prevent
	// us from calling programs residing in %windir%\System32 when running on a 64bit system
	// (since nmrpflash is currently shipped as 32bit only).
	//
	// [1] https://msdn.microsoft.com/en-us/library/windows/desktop/aa384187(v=vs.85).aspx

	oldpath = getenv("PATH");
	windir = getenv("WINDIR");
	if (oldpath && windir) {
		newpath = malloc(strlen(oldpath) + strlen(windir) + 32);
		sprintf(newpath, "%s;%s\\Sysnative", oldpath, windir);
		SetEnvironmentVariable("PATH", newpath);
		free(newpath);
	}
#endif
#endif

	opterr = 0;

	while ((c = getopt(argc, argv, "a:A:Bc:f:F:i:m:M:p:R:S:t:T:hLVvU")) != -1) {
		max = 0x7fffffff;
		switch (c) {
			case 'a':
				args.ipaddr = optarg;
				break;
			case 'A':
				args.ipaddr_intf = optarg;
				break;
			case 'B':
				args.blind = true;
				break;
			case 'c':
				args.tftpcmd = optarg;
				break;
			case 'f':
				args.file_local = optarg;
				break;
			case 'F':
				args.file_remote = optarg;
				break;
			case 'i':
				args.intf = optarg;
				break;
			case 'm':
				args.mac = optarg;
				have_dest_mac = true;
				break;
			case 'M':
				args.ipmask = optarg;
				break;
#ifdef NMRPFLASH_SET_REGION
			case 'R':
				args.region = optarg;
				break;
#endif
			case 'p':
			case 'S':
			case 'T':
			case 't':
				if (c == 'p') {
					max = 0xffff;
				}

				val = atoi(optarg);
				if (val <= 0 || val > max) {
					fprintf(stderr, "Invalid numeric value for -%c.\n", c);
					return 1;
				}

				if (c == 'p') {
					args.port = val;
				} else if (c == 't') {
					args.rx_timeout = val;
				} else if (c == 'T') {
					args.ul_timeout = val * 1000;
				} else if (c == 'S') {
					args.offset = val;
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
				list = true;
				break;
			case 'h':
				usage(stdout);
				val = 0;
				goto out;
#ifdef NMRPFLASH_TFTP_TEST
			case 'U':
				if (args.ipaddr && args.file_local) {
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

	if (args.ipaddr_intf && !args.ipaddr) {
		fprintf(stderr, "Error: cannot use -A <ipaddr> without using -a <ipaddr>.\n");
		return 1;
	}

	if (args.blind && !have_dest_mac) {
		fprintf(stderr, "Error: use of -B requires -m <mac>.\n");
		return 1;
	}

#ifndef NMRPFLASH_FUZZ
	if (!list && ((!args.file_local && !args.tftpcmd) || !args.intf)) {
		usage(stderr);
		return 1;
	}

	if (!list) {
		require_admin();
	}
#endif
	val = !list ? nmrp_do(&args) : ethsock_list_all();

out:
#ifdef NMRPFLASH_WINDOWS
	WSACleanup();
#endif
	return val;
}
