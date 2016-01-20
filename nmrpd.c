#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define ETH_P_NMRP 0x0912
#define NMRP_MAX_OPT 6
#define PACKED __attribute__((__packed__))
#define NMRP_HDR_LEN 6
#define IP_LEN 4

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
	NMRP_MAGIC_NO = 1,
	NMRP_DEV_IP = 2
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
	} value;
} PACKED;

struct nmrp_msg {
	uint16_t reserved;
	uint8_t code;
	uint8_t id;
	uint16_t len;
	struct nmrp_opt opts[6];
	uint32_t num_opts;
} PACKED;

struct nmrp_msg_pkt {
	struct ether_header eth;
	struct nmrp_msg msg;
} PACKED;

static uint16_t msg_len_htons(struct nmrp_msg *msg)
{
	uint16_t len = NMRP_HDR_LEN;
	uint32_t i = 0;

	for (; i != msg->num_opts; ++i) {
		len += ntohs(msg->opts[i].len);
	}

	printf("msg: len=%u\n", len);

	return htons(len);
}

static int intf_to_index(int fd, const char *interface)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl: SIOCGIFINDEX");
		return -1;
	}

	return ifr.ifr_ifindex;
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

static int send_msg(int fd, struct sockaddr_ll *addr, struct nmrp_msg *msg)
{
	return sendto(fd, msg, ntohs(msg->len), 0, (struct sockaddr*)addr, sizeof(*addr));
}

static void dump_msg(struct nmrp_msg *msg)
{
	struct nmrp_opt *opt;
	int remain_len, len, i;

	printf("res=0x%04x, code=%u, id=0x%02x, len=%u\n",
			msg->reserved, msg->code, msg->id, ntohs(msg->len));

	remain_len = ntohs(msg->len) - NMRP_HDR_LEN;
	opt = msg->opts;

	while (remain_len > 0) {
		len = ntohs(opt->len);
		printf("  opt type=%u, len=%u\n  ", ntohs(opt->type), len);
		for (i = 0; i != len - 4; ++i) {
			printf("%02x ", ((char*)&opt->value)[i] & 0xff);
		}
		printf("\n");
		remain_len -= len;
		opt = (struct nmrp_opt*)(((char*)opt) + len);
	}
	printf("remain_len=%d\n", remain_len);
}

static uint8_t addr[4] = { 192, 168, 2, 2 };
static uint8_t mask[4] = { 255, 255, 255, 0 };

static const char *interface = "enp4s0";
static uint8_t target[ETH_ALEN] = { 0xa4, 0x2b, 0x8c, 0x10, 0xc2, 0x96 };

static const char *spinner = "\\|/-";

int main(int argc, char **argv)
{
	struct nmrp_msg_pkt pkt;
	struct sockaddr_ll addr;
	uint8_t hwaddr[ETH_ALEN];
	int hwindex;
	int i;
	int fd;

	fd = socket(AF_PACKET, SOCK_DGRAM, ETH_P_NMRP);
	if (fd == -1) {
		perror("socket");
		return 1;
	}

	if (get_intf_info(fd, interface, &addr.sll_ifindex, hwaddr)) {
		return 1;
	}

	addr.sll_halen = ETH_ALEN;
	memcpy(addr.sll_addr, target, ETH_ALEN);

	pkt.msg.reserved = 0;
	pkt.msg.code = NMRP_ADVERTISE;
	pkt.msg.id = 0;
	pkt.msg.opts[0].type = NMRP_MAGIC_NO;
	pkt.msg.opts[0].len = htons(8);
	pkt.msg.opts[0].value.magic[0] = 'N';
	pkt.msg.opts[0].value.magic[1] = 'T';
	pkt.msg.opts[0].value.magic[2] = 'G';
	pkt.msg.opts[0].value.magic[3] = 'R';
	pkt.msg.num_opts = 1;
	pkt.msg.len = msg_len_htons(&pkt.msg);

	dump_msg(&pkt.msg);

	i = 0;

#if 1
	while (1) {
		printf("\rFlooding %s with NMRP_ADVERTISE ... %c", 
				interface, spinner[i]);
		fflush(stdout);
		i = (i + 1) & 3;

		if (send_msg(fd, &addr, &pkt.msg) < 0) {
			perror("sendto");
			return 1;
		}

		usleep(10);
		//sleep(5);
	}
#else
	printf("\nuint8_t pkt[] = {");

	for (; i != ntohs(msg.len); ++i) {
		if (i) {
			printf(",");
		}

		if (!(i % 8)) {
			printf("\n\t");
		}

		printf(" 0x%02x", ((char*)&msg)[i]);
	}

	printf("\n};\n");
#endif

	return 0;
}
