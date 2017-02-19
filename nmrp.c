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

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include "nmrpd.h"

#define NMRP_HDR_LEN 6
#define NMRP_OPT_HDR_LEN 4
#define NMRP_MIN_PKT_LEN (sizeof(struct eth_hdr) +  NMRP_HDR_LEN)

#define ETH_P_NMRP 0x0912

#ifndef PACKED
#define PACKED __attribute__((__packed__))
#endif

#ifdef NMRPFLASH_WINDOWS
#define setenv(name, value, overwrite) SetEnvironmentVariable(name, value)
#endif

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
	char val[1];
} PACKED;

struct nmrp_msg {
	uint16_t reserved;
	uint8_t code;
	uint8_t id;
	uint16_t len;
	char opts[44];
} PACKED;

struct nmrp_pkt {
	struct eth_hdr eh;
	struct nmrp_msg msg;
} PACKED;

static const char *msg_code_str(uint16_t code)
{
#define MSG_CODE(x) case NMRP_C_ ## x: return #x
	static char buf[16];

	switch (code) {
		MSG_CODE(ADVERTISE);
		MSG_CODE(CONF_REQ);
		MSG_CODE(CONF_ACK);
		MSG_CODE(CLOSE_REQ);
		MSG_CODE(CLOSE_ACK);
		MSG_CODE(KEEP_ALIVE_REQ);
		MSG_CODE(KEEP_ALIVE_ACK);
		MSG_CODE(TFTP_UL_REQ);
		default:
			snprintf(buf, sizeof(buf), "%04x", ntohs(code));
			return buf;
	}
#undef MSG_CODE
}

static uint16_t to_region_code(const char *region)
{
#define REGION_CODE(r, c) if (!strcasecmp(region, r)) return htons(c)
	REGION_CODE("NA", 0x0001);
	REGION_CODE("WW", 0x0002);
	REGION_CODE("GR", 0x0003);
	REGION_CODE("PR", 0x0004);
	REGION_CODE("RU", 0x0005);
	REGION_CODE("BZ", 0x0006);
	REGION_CODE("IN", 0x0007);
	REGION_CODE("KO", 0x0008);
	REGION_CODE("JP", 0x0009);
#undef REGION_CODE
	return 0;
}

static void msg_dump(struct nmrp_msg *msg)
{
	int rem;

	fprintf(stderr, "res=0x%04x, code=0x%02x, id=0x%02x, len=%u",
			ntohs(msg->reserved), msg->code, msg->id, ntohs(msg->len));

	rem = ntohs(msg->len) - NMRP_HDR_LEN;
	fprintf(stderr, "%s\n", rem ? "" : " (no opts)");
}

static void *msg_opt(struct nmrp_msg *msg, uint16_t type, uint16_t* len)
{
	struct nmrp_opt* opt = (struct nmrp_opt*)msg->opts;
	size_t rem = ntohs(msg->len) - NMRP_HDR_LEN;
	uint16_t olen;

	do {
		olen = ntohs(opt->len);
		if (olen < NMRP_OPT_HDR_LEN || olen > rem) {
			break;
		}

		if (ntohs(opt->type) == type) {
			if (len) {
				*len = olen;
			}

			return opt->val;
		}

		rem -= olen;
	} while (rem);

	return NULL;
}

static char *msg_filename(struct nmrp_msg *msg)
{
	static char buf[256];
	uint16_t len;
	char *p = msg_opt(msg, NMRP_O_FILE_NAME, &len);
	if (p) {
		len = MIN(sizeof(buf) - 1, len);
		memcpy(buf, p, len);
		buf[len] = '\0';
		return buf;
	}

	return NULL;
}

static inline void msg_init(struct nmrp_msg *msg, uint16_t code)
{
	memset(msg, 0, sizeof(*msg));
	msg->len = htons(NMRP_HDR_LEN);
	msg->code = code;
}

static char *msg_mkopt(struct nmrp_msg *msg, char *p, uint16_t type, const void *val, size_t len)
{
	struct nmrp_opt* opt = (struct nmrp_opt*)p;

	len &= 0xffff;

	msg->len = ntohs(msg->len);

	if ((msg->len + len > sizeof(*msg))) {
		fprintf(stderr, "Error: invalid option - this is a bug\n");
		exit(1);
	}

	opt->type = htons(type);
	opt->len = NMRP_OPT_HDR_LEN + len;

	if (val) {
		memcpy(opt->val, val, len);
	}

	msg->len += opt->len;
	p += opt->len;

	msg->len = htons(msg->len);
	opt->len = htons(opt->len);

	return p;
}

static void msg_mkadvertise(struct nmrp_msg *msg, const char *magic)
{
	msg_init(msg, NMRP_C_ADVERTISE);
	msg_mkopt(msg, msg->opts, NMRP_O_MAGIC_NO, magic, strlen(magic));
}

static void msg_mkconfack(struct nmrp_msg *msg, uint32_t ipaddr, uint32_t ipmask, uint16_t region)
{
	char *p;
	struct {
		uint32_t addr;
		uint32_t mask;
	} PACKED ip = {
		.addr = ipaddr,
		.mask = ipmask
	};

	msg_init(msg, NMRP_C_CONF_ACK);
	p = msg_mkopt(msg, msg->opts, NMRP_O_DEV_IP, &ip, 8);
	p = msg_mkopt(msg, p, NMRP_O_FW_UP, NULL, 0);

#ifdef NMRPFLASH_SET_REGION
	if (region) {
		p = msg_mkopt(msg, p, NMRP_O_DEV_REGION, &region, 2);
	}
#endif
}

#ifdef NMRPFLASH_FUZZ
#define NMRP_INITIAL_TIMEOUT 0
#define ethsock_create(a, b) ((struct ethsock*)1)
#define ethsock_get_hwaddr(a) ethsock_get_hwaddr_fake(a)
#define ethsock_recv(sock, buf, len) read(STDIN_FILENO, buf, len)
#define ethsock_send(a, b, c) (0)
#define ethsock_set_timeout(a, b) (0)
#define ethsock_ip_add(a, b, c, d) (0)
#define ethsock_ip_del(a, b) (0)
#define ethsock_close(a) (0)
#define tftp_put(a) (0)

static uint8_t *ethsock_get_hwaddr_fake(struct ethsock* sock)
{
	static uint8_t hwaddr[6] = { 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa };
	return hwaddr;
}
#else
#define NMRP_INITIAL_TIMEOUT 60
#endif

static int pkt_send(struct ethsock *sock, struct nmrp_pkt *pkt)
{
	return ethsock_send(sock, pkt, sizeof(*pkt));
}

static int pkt_recv(struct ethsock *sock, struct nmrp_pkt *pkt)
{
	ssize_t bytes, len;

	memset(pkt, 0, sizeof(*pkt));
	bytes = ethsock_recv(sock, pkt, sizeof(*pkt));
	if (bytes < 0) {
		return 1;
	} else if (!bytes) {
		return 2;
	} else if (bytes < NMRP_MIN_PKT_LEN) {
		fprintf(stderr, "Short packet (%d bytes)\n", (int)bytes);
		return 1;
	}

	len = ntohs(pkt->msg.len) + sizeof(pkt->eh);

	if (bytes != len) {
		fprintf(stderr, "Unexpected packet length (expected %d, got %d).\n",
				(int)len, (int)bytes);
		return 1;
	}

	return 0;
}

static int mac_parse(const char *str, uint8_t *hwaddr)
{
	int i;
	unsigned data[6];

	sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x%n",
			data, data + 1, data + 2, data + 3, data + 4, data + 5, &i);

	if (i == strlen(str)) {
		for (i = 0; i != 6; ++i) {
			if (data[i] > 255) {
				break;
			}

			hwaddr[i] = data[i] & 0xff;
		}

		if (i == 6) {
			return 1;
		}
	}
	return 0;
}

struct is_valid_ip_arg
{
	struct in_addr *ipaddr;
	struct in_addr *ipmask;
	int result;
};

static int is_valid_ip_cb(struct ethsock_ip_callback_args *args)
{
#define SUBNET(x) ((x)->ipaddr->s_addr & (x)->ipmask->s_addr)
	struct is_valid_ip_arg *arg = args->arg;
	if (SUBNET(args) == SUBNET(arg)) {
		arg->result = args->ipaddr->s_addr != arg->ipaddr->s_addr;
		return 0;
	}

	return 1;
#undef SUBNET
}

static int is_valid_ip(struct ethsock *sock, struct in_addr *ipaddr,
		struct in_addr *ipmask)
{
	int status;
	struct is_valid_ip_arg arg = {
		.ipaddr = ipaddr,
		.ipmask = ipmask,
		.result = 0
	};

	status = ethsock_for_each_ip(sock, is_valid_ip_cb, &arg);
	return status < 0 ? status : arg.result;
}

static void sigh(int sig)
{
	g_interrupted = 1;
}

static const char *spinner = "\\|/-";

int nmrp_do(struct nmrpd_args *args)
{
	struct nmrp_pkt tx, rx;
	uint8_t *src, dest[6];
	uint16_t region;
	char *filename;
	time_t beg;
	int i, status, ulreqs, expect, upload_ok, autoip;
	struct ethsock *sock;
	struct ethsock_ip_undo *ip_undo = NULL;
	struct ethsock_arp_undo *arp_undo = NULL;
	uint32_t intf_addr;
	void (*sigh_orig)(int);
	struct {
		struct in_addr addr;
		struct in_addr mask;
	} PACKED ipconf;

	if (args->op != NMRP_UPLOAD_FW) {
		fprintf(stderr, "Operation not implemented.\n");
		return 1;
	}

	if (!mac_parse(args->mac, dest)) {
		fprintf(stderr, "Invalid MAC address '%s'.\n", args->mac);
		return 1;
	}

	ipconf.mask.s_addr = inet_addr(args->ipmask);
	if (ipconf.mask.s_addr == INADDR_NONE
			|| netmask(bitcount(ipconf.mask.s_addr)) != ipconf.mask.s_addr) {
		fprintf(stderr, "Invalid subnet mask '%s'.\n", args->ipmask);
		return 1;
	}

	if (!args->ipaddr) {
		autoip = true;
		/* The MAC of the device that was used to test this utility starts
		 * with a4:2b:8c, hence 164 (0xa4) and 183 (0x2b + 0x8c)
		 */
		args->ipaddr = "10.164.183.252";

		if (!args->ipaddr_intf) {
			args->ipaddr_intf = "10.164.183.253";
		}
	} else if (args->ipaddr_intf) {
		autoip = true;
	} else {
		autoip = false;
	}

	if ((ipconf.addr.s_addr = inet_addr(args->ipaddr)) == INADDR_NONE) {
		fprintf(stderr, "Invalid IP address '%s'.\n", args->ipaddr);
		return 1;
	}

	if (args->ipaddr_intf && (intf_addr = inet_addr(args->ipaddr_intf)) == INADDR_NONE) {
		fprintf(stderr, "Invalid IP address '%s'.\n", args->ipaddr_intf);
		return 1;
	}

	if (args->file_local && strcmp(args->file_local, "-") && access(args->file_local, R_OK) == -1) {
		fprintf(stderr, "Error accessing file '%s'.\n", args->file_local);
		return 1;
	}

	if (args->file_remote) {
		if (!tftp_is_valid_filename(args->file_remote)) {
			fprintf(stderr, "Invalid remote filename '%s'.\n",
					args->file_remote);
			return 1;
		}
	}

	if (args->region) {
		region = to_region_code(args->region);
		if (!region) {
			fprintf(stderr, "Invalid region code '%s'.\n", args->region);
			return 1;
		}
	} else {
		region = 0;
	}

	status = 1;

	sock = ethsock_create(args->intf, ETH_P_NMRP);
	if (!sock) {
		return 1;
	}

	sigh_orig = signal(SIGINT, sigh);

	if (!autoip) {
		status = is_valid_ip(sock, &ipconf.addr, &ipconf.mask);
		if (status <= 0) {
			if (!status) {
				fprintf(stderr, "Address %s/%s cannot be used on interface %s.\n",
						args->ipaddr, args->ipmask, args->intf);
			}
			goto out;
		}
	} else {
		if (verbosity) {
			printf("Adding %s to interface %s.\n", args->ipaddr_intf, args->intf);
		}

		if (ethsock_ip_add(sock, intf_addr, ipconf.mask.s_addr, &ip_undo) != 0) {
			goto out;
		}
	}

	if (ethsock_set_timeout(sock, args->rx_timeout)) {
		goto out;
	}

	src = ethsock_get_hwaddr(sock);
	if (!src) {
		goto out;
	}

	memcpy(tx.eh.ether_shost, src, 6);
	memcpy(tx.eh.ether_dhost, dest, 6);
	tx.eh.ether_type = htons(ETH_P_NMRP);

	msg_mkadvertise(&tx.msg, "NTGR");

	i = 0;
	upload_ok = 0;
	beg = time_monotonic();

	while (!g_interrupted) {
		printf("\rAdvertising NMRP server on %s ... %c",
				args->intf, spinner[i]);
		fflush(stdout);
		i = (i + 1) & 3;

		if (pkt_send(sock, &tx) < 0) {
			xperror("sendto");
			goto out;
		}

		status = pkt_recv(sock, &rx);
		if (status == 0 && memcmp(rx.eh.ether_dhost, src, 6) == 0) {
			break;
		} else if (status == 1) {
			goto out;
		} else {
			/* because we don't want nmrpflash's exit status to be zero */
			status = 1;
			if ((time_monotonic() - beg) >= NMRP_INITIAL_TIMEOUT) {
				printf("\nNo response after 60 seconds. Bailing out.\n");
				goto out;
			}
		}
	}

	printf("\n");

	expect = NMRP_C_CONF_REQ;
	ulreqs = 0;

	while (!g_interrupted) {
		if (expect != NMRP_C_NONE && rx.msg.code != expect) {
			fprintf(stderr, "Received %s while waiting for %s!\n",
					msg_code_str(rx.msg.code), msg_code_str(expect));
		}

		msg_init(&tx.msg, NMRP_C_NONE);

		status = 1;

		switch (rx.msg.code) {
			case NMRP_C_ADVERTISE:
				printf("Received NMRP advertisement from %s.\n",
						mac_to_str(rx.eh.ether_shost));
				status = 1;
				goto out;
			case NMRP_C_CONF_REQ:
				msg_mkconfack(&tx.msg, ipconf.addr.s_addr, ipconf.mask.s_addr, region);
				expect = NMRP_C_TFTP_UL_REQ;

				printf("Received configuration request from %s.\n",
						mac_to_str(rx.eh.ether_shost));

				memcpy(tx.eh.ether_dhost, rx.eh.ether_shost, 6);

				printf("Sending configuration: %s, netmask %s.\n",
						args->ipaddr, args->ipmask);

				if (ethsock_arp_add(sock, rx.eh.ether_shost, ipconf.addr.s_addr, &arp_undo) != 0) {
					goto out;
				}

				break;
			case NMRP_C_TFTP_UL_REQ:
				if (!upload_ok) {
					if (++ulreqs > 5) {
						printf("Bailing out after %d upload requests.\n",
								ulreqs);
						tx.msg.code = NMRP_C_CLOSE_REQ;
						break;
					}
				} else {
					if (verbosity) {
						printf("Ignoring extra upload request.\n");
					}
					ethsock_set_timeout(sock, args->ul_timeout);
					tx.msg.code = NMRP_C_KEEP_ALIVE_REQ;
					break;
				}

				filename = msg_filename(&rx.msg);
				if (filename) {
					if (!args->file_remote) {
						args->file_remote = filename;
					}
					printf("Received upload request: filename '%s'.\n", filename);
				} else if (!args->file_remote) {
					args->file_remote = args->file_local;
					printf("Received upload request with empty filename.\n");
				}

				status = 0;

				if (args->tftpcmd) {
					printf("Executing '%s' ... \n", args->tftpcmd);
					setenv("IP", inet_ntoa(ipconf.addr), 1);
					setenv("PORT", lltostr(args->port, 10), 1);
					setenv("MAC", mac_to_str(rx.eh.ether_shost), 1);
					setenv("NETMASK", inet_ntoa(ipconf.mask), 1);
					//setenv("FILENAME", args->file_remote ? args->file_remote : "", 1);
					status = system(args->tftpcmd);
				}

				if (!status && args->file_local) {
					if (!autoip) {
						status = is_valid_ip(sock, &ipconf.addr, &ipconf.mask);
						if (status < 0) {
							goto out;
						} else if (!status) {
							printf("IP address of %s has changed. Please assign a "
									"static ip to the interface.\n", args->intf);
							tx.msg.code = NMRP_C_CLOSE_REQ;
							break;
						}
					}

					if (verbosity) {
						printf("Using remote filename '%s'.\n",
								args->file_remote);
					}

					if (!strcmp(args->file_local, "-")) {
						printf("Uploading from stdin ... ");
					} else {
						printf("Uploading %s ... ", leafname(args->file_local));
					}
					fflush(stdout);
					if (!(status = tftp_put(args))) {
						printf("OK\n");
					}

				}

				if (!status) {
					printf("Waiting for remote to respond.\n");
					upload_ok = 1;
					ethsock_set_timeout(sock, args->ul_timeout);
					tx.msg.code = NMRP_C_KEEP_ALIVE_REQ;
					expect = NMRP_C_NONE;
				} else if (status == -2) {
					expect = NMRP_C_TFTP_UL_REQ;
				} else {
					goto out;
				}

				break;
			case NMRP_C_KEEP_ALIVE_REQ:
				tx.msg.code = NMRP_C_KEEP_ALIVE_ACK;
				ethsock_set_timeout(sock, args->ul_timeout);
				printf("Received keep-alive request.\n");
				break;
			case NMRP_C_CLOSE_REQ:
				tx.msg.code = NMRP_C_CLOSE_ACK;
				break;
			case NMRP_C_CLOSE_ACK:
				status = 0;
				goto out;
			default:
				fprintf(stderr, "Unknown message code 0x%02x!\n",
						rx.msg.code);
				msg_dump(&rx.msg);
		}

		if (tx.msg.code != NMRP_C_NONE) {
			if (pkt_send(sock, &tx) < 0) {
				xperror("sendto");
				goto out;
			}

			if (tx.msg.code == NMRP_C_CLOSE_REQ) {
				goto out;
			}
		}

		if (rx.msg.code == NMRP_C_CLOSE_REQ) {
			printf("Remote finished. Closing connection.\n");
			break;
		}

		status = pkt_recv(sock, &rx);
		if (status) {
			if (status == 2) {
				fprintf(stderr, "Timeout while waiting for %s.\n",
						msg_code_str(expect));
			}
			goto out;
		}

		ethsock_set_timeout(sock, args->rx_timeout);

	}

	if (!g_interrupted) {
		status = 0;
		if (ulreqs) {
			printf("Reboot your device now.\n");
		} else {
			printf("No upload request received.\n");
		}
	}

out:
	signal(SIGINT, sigh_orig);
	ethsock_arp_del(sock, &arp_undo);
	ethsock_ip_del(sock, &ip_undo);
	ethsock_close(sock);
	return status;
}
