#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdint.h>
#include <string.h>
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

enum nmrp_code {
	NMRP_ADVERTISE = 1,
	NMRP_CONF_REQ = 2,
	NMRP_CONF_ACK = 3,
	NMRP_CLOSE_REQ = 4,
	NMRP_CLOSE_ACK = 5,
	NMRP_KEEP_ALIVE_REQ = 6,
	NMRP_KEEP_ALIVE_ACK = 7,
	NMRP_TFTP_UPLOAD_REQ = 16
};

enum nmrp_opt_type {
	NMRP_MAGIC_NO = 0x0001,
	NMRP_DEV_IP = 0x0002
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

static void msg_hton(struct nmrp_msg *msg)
{
	uint16_t len = NMRP_HDR_LEN;
	uint32_t i = 0;

	msg->reserved = htons(msg->reserved);

	for (; i != msg->num_opts; ++i) {
		len += msg->opts[i].len;
		msg->opts[i].len = htons(msg->opts[i].len);
		msg->opts[i].type = htons(msg->opts[i].type);
	}

	msg->len = htons(len);
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

	printf("res=0x%04x, code=%u, id=0x%02x, len=%u", msg->reserved, 
			msg->code, msg->id, msg->len);

	remain_len = msg->len - NMRP_HDR_LEN;
	printf("%s\n", remain_len ? " (no opts)" : "");

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

static int get_intf_info(int fd, const char *name, int *index, uint8_t *hwaddr)
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

static int sock_set_rx_timeout(int fd, unsigned msec)
{
	struct timeval tv;

	if (msec) {
		tv.tv_sec = 0;
		tv.tv_usec = msec * 1000;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
			perror("setsockopt(SO_RCVTIMEO)");
			return 1;
		}
	}

	return 0;
}

static int sock_bind(int fd, const char *name)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
		perror("setsockopt(SO_BINDTODEVICE)");
		return 1;
	}

	return 0;
}

static uint8_t ipaddr[4] = { 192, 168, 2, 2 };
static uint8_t ipmask[4] = { 255, 255, 255, 0 };

static const char *interface = "enp4s0";
#if 1
static uint8_t target[ETH_ALEN] = { 0xa4, 0x2b, 0x8c, 0x10, 0xc2, 0x96 };
#else
static uint8_t target[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
#endif

static const char *spinner = "\\|/-";

int main(int argc, char **argv)
{
	struct nmrp_pkt pkt, rx;
	struct sockaddr_ll addr;
	uint8_t hwaddr[ETH_ALEN];
	int i, fd, err, status, expect;

	err = 1;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_NMRP));
	if (fd == -1) {
		perror("socket");
		return 1;
	}

	if (get_intf_info(fd, interface, &addr.sll_ifindex, hwaddr)) {
		return 1;
	}

	if (sock_bind(fd, interface)) {
		return 1;
	}

#if 1
	if (sock_set_rx_timeout(fd, 10)) {
		return 1;
	}
#endif
	addr.sll_family = PF_PACKET;
	//addr.sll_hatype = ARPHRD_ETHER;
	//addr.sll_pkttype = PACKET_OTHERHOST;
	addr.sll_protocol = htons(ETH_P_NMRP);
	addr.sll_halen = ETH_ALEN;
	memcpy(addr.sll_addr, target, ETH_ALEN);

	memcpy(pkt.eh.ether_shost, hwaddr, ETH_ALEN);
	memcpy(pkt.eh.ether_dhost, target, ETH_ALEN);
	pkt.eh.ether_type = htons(ETH_P_NMRP);

	pkt.msg.reserved = 0;
	pkt.msg.code = NMRP_ADVERTISE;
	pkt.msg.id = 0;
	pkt.msg.num_opts = 1;
	pkt.msg.opts[0].type = NMRP_MAGIC_NO;
	pkt.msg.opts[0].len = NMRP_OPT_LEN + 4;
	pkt.msg.opts[0].val.magic[0] = 'N';
	pkt.msg.opts[0].val.magic[1] = 'T';
	pkt.msg.opts[0].val.magic[2] = 'G';
	pkt.msg.opts[0].val.magic[3] = 'R';

	msg_hton(&pkt.msg);

	i = 0;

	while (1) {
		printf("\rAdvertising NMRP server on %s ... %c", 
				interface, spinner[i]);
		fflush(stdout);
		i = (i + 1) & 3;

		if (pkt_send(fd, &addr, &pkt) < 0) {
			perror("sendto");
			break;
		}

		status = pkt_recv(fd, &rx);
		if (status == 0) {
			break;
		} else if (status == 1) {
			printf("ERR\n");
			goto out;
		}
	}

	printf("\n");

	expect = NMRP_CONF_REQ;

	do {
		if (rx.msg.code == expect || rx.msg.code == NMRP_KEEP_ALIVE_REQ) {
			pkt.msg.reserved = 0;
			pkt.msg.id = 0;

			switch (rx.msg.code) {
				case NMRP_KEEP_ALIVE_REQ:
					pkt.msg.code = NMRP_KEEP_ALIVE_ACK;
					pkt.msg.num_opts = 0;
					break;
				case NMRP_CONF_REQ:
					pkt.msg.code = NMRP_CONF_ACK;
					pkt.msg.num_opts = 1;
					pkt.msg.opts[0].type = NMRP_DEV_IP;
					pkt.msg.opts[0].len = NMRP_OPT_LEN + 2 * IP_LEN;
					memcpy(pkt.msg.opts[0].val.ip.addr, ipaddr, IP_LEN);
					memcpy(pkt.msg.opts[0].val.ip.mask, ipmask, IP_LEN);
					expect = -1;
					break;
				default:
					fprintf(stderr, "Unhandled message code %02x!\n",
							rx.msg.code);
			}
			
			if (pkt_send(fd, &addr, &pkt) < 0) {
				perror("sendto");
				break;
			}
		} else if (rx.msg.code != NMRP_KEEP_ALIVE_REQ) {
			fprintf(stderr, "Received code %02x while waiting for %02x!", 
					rx.msg.code, expect);
		}

		i = 0;

		while ((status = pkt_recv(fd, &rx)) != 0) {
			if (++i == MAX_LOOP_RECV) {
				fprintf(stderr, "Timeout while waiting for %02x.\n", expect);
				goto out;
			}
		}
	} while (status != 1);

	err = 0;

out:
	close(fd);

	return err;
}
