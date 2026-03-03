#include <string.h>
#include <stdio.h>
#include "nmrpd.h"

int main(int argc, char** argv)
{
	verbosity = 2;

	struct nmrpd_args args = {
		.rx_timeout = 60,
		.ul_timeout = 60,
		.ipaddr = "10.10.10.10",
		.ipmask = "255.255.255.0",
		.mac = "ff:ff:ff:ff:ff:ff",
		.op = NMRP_UPLOAD_FW,
		.port = 69,
	};

	int ret = 1;

 	if (argc == 3 && !strcmp(argv[1], "tftp")) {
		args.file_local = argv[2];
		ret = tftp_put(&args);
		printf("\n");
	} else if (argc == 2 && !strcmp(argv[1], "nmrp")) {
		ret = nmrp_do(&args);
	} else {
		fprintf(stderr, "Error: bad arguments: argc=%d", argc);
	}

	return ret;
}
