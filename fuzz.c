#include "nmrpd.h"

int main(int argc, char** argv)
{
	struct nmrpd_args args = {
		.rx_timeout = 60,
		.ul_timeout = 60,
		.ipmask = "255.255.255.0",
		.mac = "ff:ff:ff:ff:ff:ff",
		.op = NMRP_UPLOAD_FW,
		.port = 69,
	};
#ifdef NMRPFLASH_FUZZ_TFTP
	if (argc != 2) {
		return 1;
	}
	args.file_local = argv[1];

	return tftp_put(&args);
#else
	return nmrp_do(&args);
#endif
}
