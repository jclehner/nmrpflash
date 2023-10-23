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

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include "nmrpd.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define TFTP_BLKSIZE 1456

static const char *opcode_names[] = {
	"RRQ", "WRQ", "DATA", "ACK", "ERR", "OACK"
};

enum tftp_opcode {
	RRQ  = 1,
	WRQ  = 2,
	DATA = 3,
	ACK  = 4,
	ERR  = 5,
	OACK = 6
};

static bool is_netascii(const char *str)
{
	uint8_t *p = (uint8_t*)str;

	for (; *p; ++p) {
		if (*p < 0x20 || *p > 0x7f) {
			return false;
		}
	}

	return true;
}

static inline char *pkt_mknum(char *pkt, uint16_t n)
{
	*(uint16_t*)pkt = htons(n);
	return pkt + 2;
}

static inline uint16_t pkt_num(char *pkt)
{
	return ntohs(*(uint16_t*)pkt);
}

static char *pkt_mkopt(char *pkt, const char *opt, const char* val)
{
	strcpy(pkt, opt);
	pkt += strlen(opt) + 1;
	strcpy(pkt, val);
	pkt += strlen(val) + 1;
	return pkt;
}

static bool pkt_nextstr(char **pkt, char **str, size_t *rem)
{
	size_t len;

	if (!isprint(**pkt) || !(len = strnlen(*pkt, *rem))) {
		return false;
	} else if (str) {
		*str = *pkt;
	}

	*pkt += len + 1;

	if (*rem > 1) {
		*rem -= len + 1;
	} else {
		*rem = 0;
	}

	return true;
}

static bool pkt_nextopt(char **pkt, char **opt, char **val, size_t *rem)
{
	return pkt_nextstr(pkt, opt, rem) && pkt_nextstr(pkt, val, rem);
}

static char *pkt_optval(char* pkt, const char* name)
{
	size_t rem = 512;
	char *opt, *val;
	pkt += 2;

	while (pkt_nextopt(&pkt, &opt, &val, &rem)) {
		if (!strcasecmp(name, opt)) {
			return val;
		}
	}

	return NULL;
}

static size_t pkt_xrqlen(char *pkt)
{
	size_t rem = 512;

	pkt += 2;
	while (pkt_nextopt(&pkt, NULL, NULL, &rem)) {
		;
	}

	return 514 - rem;
}

static void pkt_mkwrq(char *pkt, const char *filename, unsigned blksize)
{
	filename = leafname(filename);
	if (!tftp_is_valid_filename(filename)) {
		fprintf(stderr, "Overlong/illegal filename; using 'firmware'.\n");
		filename = "firmware";
	} else if (!strcmp(filename, "-")) {
		filename = "firmware";
	}

	pkt = pkt_mknum(pkt, WRQ);
	pkt = pkt_mkopt(pkt, filename, "octet");

	if (blksize && blksize != 512) {
		pkt = pkt_mkopt(pkt, "blksize", lltostr(blksize, 10));
	}
}

static inline void pkt_print(char *pkt, FILE *fp)
{
	uint16_t opcode = pkt_num(pkt);
	size_t rem;
	char *opt, *val;

	if (!opcode || opcode > OACK) {
		fprintf(fp, "(%d)", opcode);
	} else {
		fprintf(fp, "%s", opcode_names[opcode - 1]);
		if (opcode == ACK || opcode == DATA) {
			fprintf(fp, "(%d)", pkt_num(pkt + 2));
		} else if (opcode == WRQ || opcode == RRQ) {
			fprintf(fp, "(%s, %s)", pkt + 2, pkt + 2 + strlen(pkt + 2) + 1);
		} else if (opcode == OACK) {
				fprintf(fp, "(");
				rem = 512;
				pkt += 2;
				while (pkt_nextopt(&pkt, &opt, &val, &rem)) {
					fprintf(fp, " %s=%s ", opt, val);
				}
				fprintf(fp, ")");
		}
	}
}

static ssize_t tftp_recvfrom(int sock, char *pkt, uint16_t* port,
		unsigned timeout, size_t pktlen)
{
	ssize_t len;
	struct sockaddr_in src;
#ifndef NMRPFLASH_WINDOWS
	socklen_t alen;
#else
	int alen;
#endif

	len = select_fd(sock, timeout);
	if (len < 0) {
		return -1;
	} else if (!len) {
		return 0;
	}

#ifndef NMRPFLASH_FUZZ
	alen = sizeof(src);
	len = recvfrom(sock, pkt, pktlen, 0, (struct sockaddr*)&src, &alen);
	if (len < 0) {
		sock_perror("recvfrom");
		return -1;
	}
#else
	len = read(sock, pkt, pktlen);
	if (len < 0) {
		perror("read");
		return -1;
	}
#endif

	*port = ntohs(src.sin_port);

	uint16_t opcode = pkt_num(pkt);

	if (opcode == ERR) {
		fprintf(stderr, "Error (%d): %.511s\n", pkt_num(pkt + 2), pkt + 4);
		return -1;
	} else if (isprint(pkt[0])) {
		/* In case of a firmware checksum error, the EX2700 I've tested this
		 * on sends a raw UDP packet containing just an error message starting
		 * at offset 0. The limit of 32 chars is arbitrary.
		 */
		fprintf(stderr, "Error: %.32s\n", pkt);
		return -2;
	} else if (!opcode || opcode > OACK) {
		fprintf(stderr, "Received invalid packet: ");
		pkt_print(pkt, stderr);
		fprintf(stderr, ".\n");
		return -1;
	}

	if (verbosity > 2) {
		printf(">> ");
		pkt_print(pkt, stdout);
		printf("\n");
	}

	return len;
}

static ssize_t tftp_sendto(int sock, char *pkt, size_t len,
		struct sockaddr_in *dst)
{
	ssize_t sent;

	switch (pkt_num(pkt)) {
		case RRQ:
		case WRQ:
		case OACK:
			len = pkt_xrqlen(pkt);
			break;
		case DATA:
			len += 4;
			break;
		case ACK:
			len = 4;
			break;
		case ERR:
			len = 4 + strlen(pkt + 4);
			break;
		default:
			fprintf(stderr, "Attempted to send invalid packet ");
			pkt_print(pkt, stderr);
			fprintf(stderr, "; this is a bug!\n");
			return -1;
	}

	if (verbosity > 2) {
		printf("<< ");
		pkt_print(pkt, stdout);
		printf("\n");
	}

#ifndef NMRPFLASH_FUZZ
	sent = sendto(sock, pkt, len, 0, (struct sockaddr*)dst, sizeof(*dst));
	if (sent < 0) {
		sock_perror("sendto");
	}
#else
	sent = len;
#endif

	return sent;
}

const char *leafname(const char *path)
{
	if (!path) {
		return NULL;
	}

	const char *slash, *bslash;

	slash = strrchr(path, '/');
	bslash = strrchr(path, '\\');

	if (slash && bslash) {
		path = 1 + (slash > bslash ? slash : bslash);
	} else if (slash) {
		path = 1 + slash;
	} else if (bslash) {
		path = 1 + bslash;
	}

	return path;
}

#ifdef NMRPFLASH_WINDOWS
void sock_perror(const char *msg)
{
	win_perror2(msg, WSAGetLastError());
}
#endif

inline bool tftp_is_valid_filename(const char *filename)
{
	return strlen(filename) <= 255 && is_netascii(filename);
}

static const char *spinner = "\\|/-";

ssize_t tftp_put(struct nmrpd_args *args)
{
	struct sockaddr_in addr;
	uint16_t block, port, op, blksize;
	ssize_t len, last_len, bytes;
	int fd, sock, ret, timeouts, errors, ackblock;
	char rx[2048], tx[2048];
	const char *file_remote = args->file_remote;
	char *val, *end;
	bool rollover;
	const unsigned rx_timeout = MAX(args->rx_timeout / 50, 200);
	const unsigned max_timeouts = args->blind ? 3 : 5;
#ifndef NMRPFLASH_WINDOWS
	int enabled = 1;
#else
	char enabled = TRUE;
#endif

	sock = -1;
	ret = -1;
	fd = -1;

	if (g_interrupted) {
		goto cleanup;
	}

	if (!strcmp(args->file_local, "-")) {
		fd = STDIN_FILENO;
		if (!file_remote) {
			file_remote = "firmware";
		}
	} else {
		fd = open(args->file_local, O_RDONLY | O_BINARY);
		if (fd < 0) {
			xperror("open");
			goto cleanup;
		} else if (!file_remote) {
			file_remote = args->file_local;
		}

		if (lseek(fd, args->offset, SEEK_SET) == (off_t)-1) {
			xperror("lseek");
			goto cleanup;
		}
	}

#ifndef NMRPFLASH_FUZZ_TFTP
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		sock_perror("socket");
		goto cleanup;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
		sock_perror("setsockopt");
		goto cleanup;
	}

#else
	sock = STDIN_FILENO;
#endif

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

	// check if we have an interface address, and bind to it if we do
	if (args->ipaddr_intf) {
		addr.sin_addr.s_addr = inet_addr(args->ipaddr_intf);
		if ((addr.sin_addr.s_addr = inet_addr(args->ipaddr_intf)) == INADDR_NONE) {
			xperror("inet_addr");
			goto cleanup;
		}

		if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
			sock_perror("bind");
			goto cleanup;
		}
	}

	if ((addr.sin_addr.s_addr = inet_addr(args->ipaddr)) == INADDR_NONE) {
		xperror("inet_addr");
		goto cleanup;
	}

	addr.sin_port = htons(args->port);

	blksize = 512;
	block = 0;
	last_len = -1;
	len = 0;
	bytes = 0;
	errors = 0;
	rollover = false;
	/* Not really, but this way the loop sends our WRQ before receiving */
	timeouts = 1;

	pkt_mkwrq(tx, file_remote, TFTP_BLKSIZE);

	while (!g_interrupted) {
		ackblock = -1;
		op = pkt_num(rx);

		if (!timeouts) {
			if (op == ACK) {
				ackblock = pkt_num(rx + 2);
			} else if (op == OACK) {
				ackblock = 0;
				if ((val = pkt_optval(rx, "blksize"))) {
					blksize = strtol(val, &end, 10);
					if (*end != '\0' || blksize < 8 || blksize > TFTP_BLKSIZE) {
						fprintf(stderr, "Error: invalid blksize in OACK: %s\n", val);
						ret = -1;
						goto cleanup;
					}

					if (verbosity) {
						printf("Remote accepted blksize option: %d b\n", blksize);
					}
				}
			}
		}

		if (timeouts || ackblock == block) {
			if (!timeouts) {
				if (++block == 0) {
					if (!rollover) {
						printf("Warning: TFTP block rollover. Upload might fail!\n");
						rollover = true;
					}
				}

				printf("%c ", spinner[block & 3]);
				fflush(stdout);
				printf("\b\b");

				pkt_mknum(tx, DATA);
				pkt_mknum(tx + 2, block);
				len = read(fd, tx + 4, blksize);
				if (len < 0) {
					xperror("read");
					ret = len;
					goto cleanup;
				} else if (!len) {
					if (last_len != blksize && last_len != -1) {
						break;
					}
				}

				last_len = len;
				bytes += len;
			}

			ret = tftp_sendto(sock, tx, len, &addr);
			if (ret < 0) {
				goto cleanup;
			}
		} else if ((op != OACK && op != ACK) || ackblock > block) {
			if (verbosity) {
				fprintf(stderr, "Expected ACK(%d), got ", block);
				pkt_print(rx, stderr);
				fprintf(stderr, ".\n");
			}

			if (ackblock != -1 && ++errors > 5) {
				fprintf(stderr, "Protocol error; bailing out.\n");
				ret = -1;
				goto cleanup;
			}
		}

		ret = tftp_recvfrom(sock, rx, &port, rx_timeout, blksize + 4);
		nmrp_discard(args->sock);

		if (ret < 0) {
			goto cleanup;
		} else if (!ret) {
			if (++timeouts < max_timeouts || (!block && timeouts < (max_timeouts * 4))) {
				continue;
			} else if (args->blind) {
				timeouts = 0;
				// fake an ACK packet
				pkt_mknum(rx, ACK);
				pkt_mknum(rx + 2, block);
				continue;
			} else if (block) {
				fprintf(stderr, "Timeout while waiting for ACK(%d).\n", block);
			} else {
				fprintf(stderr, "Timeout while waiting for ACK(0)/OACK.\n");
			}
			ret = -1;
			goto cleanup;
		} else {
			timeouts = 0;
			ret = 0;

			if (!block && port != args->port) {
				if (verbosity > 1) {
					printf("Switching to port %d\n", port);
				}
				addr.sin_port = htons(port);
			}
		}
	}

	ret = !g_interrupted ? 0 : -1;

cleanup:
	if (fd >= 0) {
		close(fd);
	}

	if (sock >= 0) {
#ifndef NMRPFLASH_WINDOWS
		shutdown(sock, SHUT_RDWR);
		close(sock);
#else
		shutdown(sock, SD_BOTH);
		closesocket(sock);
#endif
	}

	return (ret == 0) ? bytes : ret;
}
