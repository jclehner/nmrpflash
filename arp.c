#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "nmrpd.h"

#ifndef PACKED
#define PACKED __attribute__((packed))
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

#define REQUEST_COUNT 256

struct arp
{
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t oper;
	uint8_t sha[6];
	uint32_t spa;
	uint8_t tha[6];
	uint32_t tpa;
} PACKED;

struct arppkt
{
	struct eth_hdr eth;
	struct arp arp;
	uint8_t padding[18];
} PACKED;

static bool is_arp(void *pktbuf, size_t len)
{
	if (len < 28) {
		return false;
	}

	len -= 14;
	pktbuf += 14;

	struct arp *pkt = pktbuf;
	return ntohs(pkt->htype) == 1 && ntohs(pkt->ptype) == 0x0800
		&& pkt->hlen == 6 && pkt->plen == 4;
}

static bool is_reply(void *pktbuf, size_t len, struct ethsock *sock)
{
	struct arppkt *pkt = pktbuf;
	return is_arp(pktbuf, len) && htons(pkt->arp.oper) == 2
		&& !memcmp(ethsock_get_hwaddr(sock), pkt->arp.tha, 6);
}

static const char *u32toa(uint32_t u32)
{
	struct in_addr addr = { .s_addr = u32 };
	return inet_ntoa(addr);
}

static int ip_callback(struct ethsock_ip_callback_args *args)
{
	uint32_t *ip = args->arg;
	ip[0] = args->ipaddr->s_addr;
	ip[1] = args->ipmask->s_addr;

	return 0;
}

static void init_request(struct arppkt *pkt, struct ethsock *sock, uint32_t spa, uint32_t tpa)
{
	memcpy(pkt->eth.ether_shost, ethsock_get_hwaddr(sock), 6);
	memset(pkt->eth.ether_dhost, 0xff, 6);
	pkt->eth.ether_type = htons(0x0806);
	memset(pkt->padding, 0, sizeof(pkt->padding));

	pkt->arp.htype = htons(1);
	pkt->arp.ptype = htons(0x0800);
	pkt->arp.hlen = 6;
	pkt->arp.plen = 4;
	pkt->arp.oper = htons(1);

	memcpy(pkt->arp.sha, ethsock_get_hwaddr(sock), 6);
	pkt->arp.spa = htonl(spa);

	memset(pkt->arp.tha, 0xff, 6);
	pkt->arp.tpa = htonl(tpa);
}

int arp_find_free_ip(const char *intf, uint32_t *addr)
{
	struct arppkt pkt;
	uint32_t srcip[2];
	struct ethsock *arpsock = NULL;
	uint32_t min, max, ip;
	int i, timeouts;
	bool replies[REQUEST_COUNT] = { 0 };
	int ret = -1;

	arpsock = ethsock_create(intf, ETH_P_ARP);
	if (!arpsock) {
		return -1;
	}

	if (ethsock_set_timeout(arpsock, 1000) != 0) {
		goto out;
	}

	if (ethsock_for_each_ip(arpsock, &ip_callback, srcip) != 0) {
		goto out;
	}

	printf("IP is %s/", u32toa(srcip[0]));
	printf("%s", u32toa(srcip[1]));

	srcip[0] = ntohl(srcip[0]);
	srcip[1] = ntohl(srcip[1]);

	printf(" aka 0x%08x/0x%08x\n", srcip[0], srcip[1]);

	if (~srcip[1]) {
		min = srcip[0] & srcip[1];
		// highest possible address, minus 1 (e.g. for 192.168.0.1/24,
		// set value to 192.168.0.254)
		max = min | (~srcip[1] - 1);
		ip = max;

		if (verbosity) {
			printf("ARPinging range %s-", u32toa(htonl(min)));
			printf("%s\n", u32toa(htonl(max)));
		}

		for (i = 0; i < REQUEST_COUNT && ip > min; --ip, ++i) {
			if (ip == srcip[0] || replies[i]) {
				continue;
			}

			init_request(&pkt, arpsock, srcip[0], ip);
			if (ethsock_send(arpsock, &pkt, sizeof(pkt)) != 0) {
				goto out;
			}
		}

		min = ip;
		timeouts = 0;

		while (1) {
			ssize_t bytes = ethsock_recv(arpsock, &pkt, sizeof(pkt));
			if (bytes < 0) {
				goto out;
			} else if (!bytes) {
				if (++timeouts >= 5) {
					break;
				}
				continue;
			}

			timeouts = 0;

			if (!is_reply(&pkt, sizeof(pkt), arpsock)) {
				continue;
			}

			uint32_t spa = ntohl(pkt.arp.spa);

			if (spa > min && spa <= max) {
				replies[spa - min] = true;
				if (verbosity > 1) {
					printf("Got ARP reply for %s from %s.\n", u32toa(pkt.arp.spa), mac_to_str(pkt.arp.sha));
				}
			} else if (verbosity > 1) {
				printf("Got unexpected ARP reply for %s (min=", u32toa(pkt.arp.spa));
				printf("%s, max=", u32toa(htonl(min)));
				printf("%s)\n", u32toa(htonl(max)));
			}
		}

		for (; i; --i) {
			if (!replies[i - 1]) {
				*addr = htonl(min + i);
				printf("Found free address %s.\n", u32toa(*addr));
				ret = 0;
				break;
			}
		}
	}

out:
	ethsock_close(arpsock);
	if (ret != 0) {
		fprintf(stderr, "Failed to find free ip address on %s\n", intf);
	}

	return ret;
}
