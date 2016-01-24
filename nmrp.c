#define _BSD_SOURCE
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#define NMRP_HDR_LEN 6
#define NMRP_OPT_LEN 4
#define NMRP_MAX_OPT 6
#define NMRP_MIN_PKT_LEN (sizeof(struct ether_header) +  NMRP_HDR_LEN)

#define ETH_P_NMRP 0x0912
#define IP_LEN 4
#define PACKED __attribute__((__packed__))
#define MAX_LOOP_RECV 1024

#define IS_OOO_CODE(x) (x == NMRP_C_CLOSE_REQ \
		|| x == NMRP_C_KEEP_ALIVE_REQ \
		|| x == NMRP_C_TFTP_UL_REQ)

extern int tftp_put(const char *filename, const char *ipaddr, uint16_t port);
extern int sock_set_rx_timeout(int fd, unsigned msec);

enum nmrp_code {
	NMRP_C_NONE = 0,
	NMRP_C_ADVERTISE = 1,
	NMRP_C_CONF_REQ = 2,
	NMRP_C_CONF_ACK = 3,
	NMRP_C_CLOSE_REQ = 4,
	NMRP_C_CLOSE_ACK = 5,
	NMRP_C_KEEP_ALIVE_REQ = 6,
	NMRP_C_KEEP_ALIVE_ACK = 7,
	NMRP_C_TFTP_UL_REQ = 16
};

enum nmrp_opt_type {
	NMRP_O_MAGIC_NO = 0x0001,
	NMRP_O_DEV_IP = 0x0002,
	NMRP_O_DEV_REGION = 0x0004,
	NMRP_O_FW_UP = 0x0101,
	NMRP_O_ST_UP = 0x0102,
	NMRP_O_FILE_NAME = 0x0181
};

struct nmrp_opt {
	uint16_t type;
	uint16_t len;
	union {
		uint8_t magic[4];
		struct {
			uint8_t addr[IP_LEN];
			uint8_t mask[IP_LEN];
		} ip;
	} val;
} PACKED;

struct nmrp_msg {
	uint16_t reserved;
	uint8_t code;
	uint8_t id;
	uint16_t len;
	struct nmrp_opt opts[6];
	uint32_t num_opts;
} PACKED;

struct nmrp_pkt {
	struct ether_header eh;
	struct nmrp_msg msg;
} PACKED;

static void msg_update_len(struct nmrp_msg *msg)
{
	uint32_t i = 0;
	msg->len = NMRP_HDR_LEN;
	for (; i != msg->num_opts; ++i) {
		msg->len += msg->opts[i].len;
	}
}

static void msg_hton(struct nmrp_msg *msg)
{
	uint32_t i = 0;

	msg->reserved = htons(msg->reserved);
	msg->len = htons(msg->len);

	for (; i != msg->num_opts; ++i) {
		msg->opts[i].len = htons(msg->opts[i].len);
		msg->opts[i].type = htons(msg->opts[i].type);
	}
}

static void msg_hdr_ntoh(struct nmrp_msg *msg)
{
	msg->reserved = ntohs(msg->reserved);
	msg->len = ntohs(msg->len);
}

static int msg_ntoh(struct nmrp_msg *msg)
{
	struct nmrp_opt *opt = msg->opts;
	int remaining;
   
	msg_hdr_ntoh(msg);
	remaining = msg->len - NMRP_HDR_LEN;

	while (remaining > 0) {
		if (remaining < NMRP_OPT_LEN) {
			fprintf(stderr, "malformed message (rem=%d)\n", remaining);
			return 1;
		}

		opt->type = ntohs(opt->type);
		opt->len = ntohs(opt->len);

		remaining -= opt->len;
	}

	return 0;
}

static void msg_dump(struct nmrp_msg *msg)
{
	struct nmrp_opt *opt;
	int remain_len, len, i;

	printf("res=0x%04x, code=0x%02x, id=0x%02x, len=%u", msg->reserved, 
			msg->code, msg->id, msg->len);

	remain_len = msg->len - NMRP_HDR_LEN;
	printf("%s\n", remain_len ? "" : " (no opts)");

	opt = msg->opts;

	while (remain_len > 0) {
		len = opt->len;
		printf("  opt type=%u, len=%u", opt->type, len);
		for (i = 0; i != len - NMRP_OPT_LEN; ++i) {
			if (!(i % 16)) {
				printf("\n  ");
			}

			printf("%02x ", ((char*)&opt->val)[i] & 0xff);
		}
		printf("\n");
		remain_len -= len;
		opt = (struct nmrp_opt*)(((char*)opt) + len);
	}
}

static int intf_get_index_and_addr(int fd, const char *name, int *index, 
		uint8_t *hwaddr)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl(SIOCGIFINDEX)");
		return -1;
	}
	*index = ifr.ifr_ifindex;

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		return -1;
	}
	memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	return 0;
}

static int pkt_send(int fd, struct sockaddr_ll *addr, struct nmrp_pkt *pkt)
{
	size_t len = ntohs(pkt->msg.len) + sizeof(pkt->eh);
	return sendto(fd, pkt, len, 0, (struct sockaddr*)addr, sizeof(*addr));
}

static int pkt_recv(int fd, struct nmrp_pkt *pkt)
{
	struct sockaddr_ll from;
	socklen_t addrlen;
	ssize_t bytes, len;

	memset(pkt, 0, sizeof(*pkt));
	bytes = recvfrom(fd, pkt, NMRP_MIN_PKT_LEN, MSG_PEEK, 
			(struct sockaddr*)&from, &addrlen);

	if (bytes < 0) {
		if (errno == EAGAIN) {
			return 2;
		}
		perror("recvfrom(pkt)");
		return 1;
	} else if (ntohs(pkt->eh.ether_type) != ETH_P_NMRP) {
		return 3;
	} else if (bytes < NMRP_MIN_PKT_LEN) {
		fprintf(stderr, "short packet (%zi bytes)\n", bytes);
		return 1;
	}

	msg_hdr_ntoh(&pkt->msg);
	len = pkt->msg.len + sizeof(pkt->eh);

	bytes = recvfrom(fd, pkt, len, MSG_DONTWAIT, NULL, NULL);
	if (bytes < 0) {
		perror("recvfrom(msg)");
		return 1;
	} else if (bytes != len) {
		fprintf(stderr, "short message (%zi bytes)\n", len);
		return 1;
	} else {
		if (msg_ntoh(&pkt->msg) != 0) {
			return 1;
		}
		msg_dump(&pkt->msg);

		return 0;
	}

	return 1;
}

static int sock_bind_to_intf(int fd, const char *name)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
		perror("setsockopt(SO_BINDTODEVICE)");
		return 1;
	}

	return 0;
}

//static const char *arg_filename = "EX2700-V1.0.1.8.img";
static unsigned arg_rx_timeout = 250;
static unsigned arg_ul_timeout = 60000;
static const char *arg_filename = "bad.img";
static const char *arg_ipaddr = "192.168.2.2";
static const char *arg_ipmask = "255.255.255.0";
static const char *arg_intf = "enp4s0";
static uint16_t arg_port = 69;
#if 0
static uint8_t target[ETH_ALEN] = { 0xa4, 0x2b, 0x8c, 0x10, 0xc2, 0x96 };
#else
static uint8_t target[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
#endif

static const char *spinner = "\\|/-";

int main(int argc, char **argv)
{
	struct nmrp_pkt tx, rx;
	struct sockaddr_ll addr;
	uint8_t hwaddr[ETH_ALEN];
	int i, fd, err, ulreqs, expect;

	err = 1;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_NMRP));
	if (fd == -1) {
		perror("socket");
		return 1;
	}

	if (intf_get_index_and_addr(fd, arg_intf, &addr.sll_ifindex, hwaddr)) {
		return 1;
	}

	if (sock_bind_to_intf(fd, arg_intf)) {
		return 1;
	}

	if (sock_set_rx_timeout(fd, arg_rx_timeout)) {
		return 1;
	}

	addr.sll_family = PF_PACKET;
	//addr.sll_hatype = ARPHRD_ETHER;
	//addr.sll_pkttype = PACKET_OTHERHOST;
	addr.sll_protocol = htons(ETH_P_NMRP);
	addr.sll_halen = ETH_ALEN;
	memcpy(addr.sll_addr, target, ETH_ALEN);

	memcpy(tx.eh.ether_shost, hwaddr, ETH_ALEN);
	memcpy(tx.eh.ether_dhost, target, ETH_ALEN);
	tx.eh.ether_type = htons(ETH_P_NMRP);

	tx.msg.reserved = 0;
	tx.msg.code = NMRP_C_ADVERTISE;
	tx.msg.id = 0;
	tx.msg.num_opts = 1;
	tx.msg.opts[0].type = NMRP_O_MAGIC_NO;
	tx.msg.opts[0].len = NMRP_OPT_LEN + 4;
	tx.msg.opts[0].val.magic[0] = 'N';
	tx.msg.opts[0].val.magic[1] = 'T';
	tx.msg.opts[0].val.magic[2] = 'G';
	tx.msg.opts[0].val.magic[3] = 'R';

	msg_update_len(&tx.msg);
	msg_hton(&tx.msg);

	i = 0;

	while (1) {
		printf("\rAdvertising NMRP server on %s ... %c", arg_intf, spinner[i]);
		fflush(stdout);
		i = (i + 1) & 3;

		if (pkt_send(fd, &addr, &tx) < 0) {
			perror("sendto");
			goto out;
		}

		err = pkt_recv(fd, &rx);
		if (err == 0) {
			break;
		} else if (err == 1) {
			printf("ERR\n");
			goto out;
		}
	}

	printf("\n");

	expect = NMRP_C_CONF_REQ;
	ulreqs = 0;

	do {
		if (expect != NMRP_C_NONE && rx.msg.code != expect) {
			fprintf(stderr, "Received code 0x%02x while waiting for 0x%02x!\n", 
					rx.msg.code, expect);
		}

		tx.msg.code = NMRP_C_NONE;
		tx.msg.reserved = 0;
		tx.msg.id = 0;
		tx.msg.num_opts = 0;
		tx.msg.len = 0;

		err = 1;

		switch (rx.msg.code) {
			case NMRP_C_CONF_REQ:
				tx.msg.code = NMRP_C_CONF_ACK;
				tx.msg.num_opts = 2;

				tx.msg.opts[0].type = NMRP_O_DEV_IP;
				tx.msg.opts[0].len = NMRP_OPT_LEN + 2 * IP_LEN;

				inet_aton(arg_ipaddr, 
						(struct in_addr*)tx.msg.opts[0].val.ip.addr);
				inet_aton(arg_ipmask, 
						(struct in_addr*)tx.msg.opts[0].val.ip.mask);

				tx.msg.opts[1].type = NMRP_O_FW_UP;
				tx.msg.opts[1].len = NMRP_OPT_LEN;

				expect = NMRP_C_TFTP_UL_REQ;

				printf("Configuration request received from "
						"%02x:%02x:%02x:%02x:%02x:%02x.\n",
						rx.eh.ether_shost[0], rx.eh.ether_shost[1],
						rx.eh.ether_shost[2], rx.eh.ether_shost[3],
						rx.eh.ether_shost[4], rx.eh.ether_shost[5]);
				printf("Sending configuration: ip %s, mask %s.\n", arg_ipaddr,
						arg_ipmask);

				break;
			case NMRP_C_TFTP_UL_REQ:
				if (++ulreqs > 5) {
					fprintf(stderr, "Device re-requested file upload %d "
							"times; aborting.\n", ulreqs);
					tx.msg.code = NMRP_C_CLOSE_REQ;
					break;
				}
				printf("Uploading %s ... ", arg_filename);
				fflush(stdout);
				err = tftp_put(arg_filename, arg_ipaddr, arg_port);
				if (!err) {
					printf("OK\nWaiting for router to respond.\n");
					sock_set_rx_timeout(fd, arg_ul_timeout);
					expect = NMRP_C_CLOSE_REQ;
				} else if (err != -3) {
					goto out;
				}
				break;
			case NMRP_C_KEEP_ALIVE_REQ:
				tx.msg.code = NMRP_C_KEEP_ALIVE_ACK;
				break;
			case NMRP_C_CLOSE_REQ:
				tx.msg.code = NMRP_C_CLOSE_ACK;
				break;
			case NMRP_C_CLOSE_ACK:
				err = 0;
				goto out;
			default:
				fprintf(stderr, "Unhandled message code 0x%02x!\n",
						rx.msg.code);
		}

		if (tx.msg.code != NMRP_C_NONE) {
			msg_update_len(&tx.msg);
			msg_hton(&tx.msg);

			if (pkt_send(fd, &addr, &tx) < 0) {
				perror("sendto");
				goto out;
			}
		}

		if (rx.msg.code == NMRP_C_CLOSE_REQ) {
			printf("Remote requested to close connection.\n");
			break;
		}

		err = pkt_recv(fd, &rx);
		if (err) {
			if (err == 2) {
				fprintf(stderr, "Timeout while waiting for 0x%02x.\n", expect);
			}
			goto out;
		}

		sock_set_rx_timeout(fd, arg_rx_timeout);

	} while (1);

	err = 0;

out:
	close(fd);

	return err;
}
