#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

enum tftp_opcode {
	RRQ  = 1,
	WRQ  = 2,
	DATA = 3,
	ACK  = 4,
	ERR  = 5,
	OACK = 6
};

static inline char *pkt_mknum(char *pkt, uint16_t n)
{
	*(uint16_t*)pkt = htons(n);
	return pkt + 2;
}

static char *pkt_mkopt(char *pkt, const char *opt, const char* val)
{
	strcpy(pkt, opt);
	pkt += strlen(opt) + 1;
	strcpy(pkt, val);
	pkt += strlen(val) + 1;
	return pkt;
}

int main(int argc, char** argv)
{
	if (argc != 2) {
		return 1;
	}

	const size_t fsize = 4096;

	char pkt[1024];
	char* p;
	size_t len = 512;

	memset(pkt, 0, sizeof(pkt));

	if (argc == 2 && argv[1][0] == 'k') {
		len = 1024;

		p = pkt_mknum(pkt, OACK);
		pkt_mkopt(p, "blksize", "1024");
	} else {
		p = pkt_mknum(pkt, ACK);
		pkt_mknum(p, 0);
	}

	write(STDOUT_FILENO, pkt, 512);

	size_t i = 0;

	for (; i < fsize/len; ++i) {
		memset(pkt, 0, len);
		p = pkt_mknum(pkt, ACK);
		pkt_mknum(p, i + 1);
		write(STDOUT_FILENO, pkt, len);
	}
}
