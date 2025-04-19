#include <stdlib.h>
#include <stdio.h>
#include "nmrpd.h"

int main(int argc, char** argv)
{
	if (argc < 3 || argc > 4) {
		fprintf(stderr, "usage: %s <file> <ip> [<port>]\n", argv[0]);
		return 1;
	}

#ifdef NMRPFLASH_WINDOWS
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

	verbosity = 2;

	struct nmrpd_args args = {
		.rx_timeout = NMRP_DEFAULT_RX_TIMEOUT_MS,
		.file_local = argv[1],
		.ipaddr = argv[2],
		.blind = false,
		.port = (argc == 4 ? atoi(argv[3]) : 69),
		.offset = 0,
		.sock = NULL,
	};

	tftp_put(&args);
}
