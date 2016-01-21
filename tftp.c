#define _BSD_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#define TFTP_PKT_SIZE 516

static const char *opcode_names[] = { 
	"RRQ", "WRQ", "DATA", "ACK", "ERR"
};

enum tftp_opcode {
	RRQ  = 1,
	WRQ  = 2,
	DATA = 3,
	ACK  = 4,
	ERR  = 5,
	NETGEAR_ERR = 0x4669
};

static inline void pkt_mknum(char *pkt, uint16_t n)
{
	*(uint16_t*)pkt = htons(n);
}

static inline uint16_t pkt_num(char *pkt)
{
	return ntohs(*(uint16_t*)pkt);
}

static void pkt_mkwrq(char *pkt, const char *filename, const char *mode)
{
	size_t len = 2;

	pkt_mknum(pkt, WRQ);

	strcpy(pkt + len, filename);
	len += strlen(filename) + 1;
	strcpy(pkt + len, mode);
	len += strlen(mode) + 1;
}

static inline void pkt_print(char *pkt, FILE *fp)
{
	uint16_t opcode = pkt_num(pkt);
	if (!opcode || opcode > ERR) {
		fprintf(fp, "(%d)", opcode);
	} else {
		fprintf(fp, "%s", opcode_names[opcode - 1]);
		if (opcode == ACK || opcode == DATA) {
			fprintf(fp, "(%d)", pkt_num(pkt + 2));
		} else if (opcode == WRQ) {
			fprintf(fp, "(%s, %s)", pkt + 2, pkt + 2 + strlen(pkt + 2) + 1);
		}
	}
}

static ssize_t tftp_recvfrom(int sock, char *pkt, struct sockaddr_in *src)
{
	static int fail = 0;
	socklen_t socklen;
	ssize_t len;

	len = recvfrom(sock, pkt, TFTP_PKT_SIZE, 0, NULL, NULL);
	if (len < 0) {
		if (errno != EAGAIN) {
			perror("recvfrom");
			return -1;
		}

		return -2;
	}

	uint16_t opcode = pkt_num(pkt);

	if (opcode == ERR) {
		fprintf(stderr, "Error (%d): %.511s\n", pkt_num(pkt + 2), pkt + 4);
		return -1;
	} else if (!opcode || opcode > ERR) {
		/* The EX2700 I've tested this on sends a raw TFTP packet with no
		 * opcode, and an error message starting at offset 0.
		 */
		fprintf(stderr, "Error: %.32s\n", pkt);
		return -3;
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
			len = 2 + strlen(pkt + 2) + 1;
			len += strlen(pkt + len) + 1;
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
			fprintf(stderr, "Error: Invalid packet ");
			pkt_print(pkt, stderr);
			return -1;
	}

	sent = sendto(sock, pkt, len, 0, (struct sockaddr*)dst, sizeof(*dst));
	if (sent < 0) {
		perror("sendto");
	}

	return sent;
}

int sock_set_rx_timeout(int fd, unsigned msec)
{
	struct timeval tv;

	if (msec) {
		tv.tv_usec = (msec % 1000) * 1000;
		tv.tv_sec = msec / 1000;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
			perror("setsockopt(SO_RCVTIMEO)");
			return 1;
		}
	}

	return 0;
}

int tftp_put(const char *filename, const char *ipaddr, uint16_t port)
{
	struct sockaddr_in dst, src;
	enum tftp_opcode opcode;
	struct timeval tv;
	uint16_t block;
	ssize_t len;
	int fd, sock, err, done, i, last_len;
	char pkt[TFTP_PKT_SIZE];

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		err = fd;
		goto cleanup;
	}

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		perror("socket");
		err = sock;
		goto cleanup;
	}

	err = sock_set_rx_timeout(sock, 999);
	if (err) {
		goto cleanup;
	}

	err = !inet_aton(ipaddr, &dst.sin_addr);
	if (err) {
		perror("inet_aton");
		goto cleanup;
	}

	dst.sin_family = AF_INET;
	dst.sin_port = htons(port);

	pkt_mkwrq(pkt, filename, "octet");

	len = tftp_sendto(sock, pkt, 0, &dst);
	if (len < 0) {
		err = len;
		goto cleanup;
	}

	len = tftp_recvfrom(sock, pkt, &dst);
	if (len < 0) {
		err = len;
		goto cleanup;
	}

	//dst.sin_port = src.sin_port;

	block = 0;
	done = 0;
	last_len = -1;

	do {
		if (pkt_num(pkt) == ACK && pkt_num(pkt + 2) == block) {
			++block;
			pkt_mknum(pkt, DATA);
			pkt_mknum(pkt + 2, block);
			len = read(fd, pkt + 4, 512);
			if (len < 0) {
				perror("read");
				err = len;
				goto cleanup;
			} else if (!len) {
				done = last_len != 512;
			}

			last_len = len;

			len = tftp_sendto(sock, pkt, len, &dst);
			if (len < 0) {
				err = len;
				goto cleanup;
			}
		} else {
			fprintf(stderr, "Expected ACK(%d), got ", block);
			pkt_print(pkt, stderr);
			fprintf(stderr, "!\n");
			err = 1;
			goto cleanup;
		}

		len = tftp_recvfrom(sock, pkt, &dst);
		if (len < 0) {
			if (len == -2) {
				fprintf(stderr, "Timeout while waiting for ACK(%d).\n", block);
			}
			err = len;
			goto cleanup;
		}
	} while(!done);

	err = 0;

cleanup:
	if (fd >= 0) {
		close(fd);
	}

	if (sock >= 0) {
		close(sock);
	}

	return err;
}
