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

#define NMRP_MAX_OPT_SIZE 12
#define NMRP_MAX_OPT_NUM 3

#define NMRP_OPT_NEXT(x) ((struct nmrp_opt*)(((char*)x) + x->len))

#define ETH_P_NMRP 0x0912
#define IP_LEN 4
#define MAX_LOOP_RECV 1024

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
	union {
		uint8_t magic[4];
		uint16_t region;
		struct {
			uint8_t addr[4];
			uint8_t mask[4];
		} ip;
	} val;
} PACKED;

struct nmrp_msg {
	uint16_t reserved;
	uint8_t code;
	uint8_t id;
	uint16_t len;
	/* only opts[0] is valid! think of this as a char* */
	struct nmrp_opt opts[NMRP_MAX_OPT_NUM];
	/* this is NOT part of the transmitted packet */
	uint32_t num_opts;
} PACKED;

struct nmrp_pkt {
	struct eth_hdr eh;
	struct nmrp_msg msg;
} PACKED;

static const char *msg_code_str(uint16_t code)
{
#define CASE_CODE(x) case NMRP_C_ ## x: return #x
	static char buf[16];

	switch (code) {
		CASE_CODE(ADVERTISE);
		CASE_CODE(CONF_REQ);
		CASE_CODE(CONF_ACK);
		CASE_CODE(CLOSE_REQ);
		CASE_CODE(CLOSE_ACK);
		CASE_CODE(KEEP_ALIVE_REQ);
		CASE_CODE(KEEP_ALIVE_ACK);
		CASE_CODE(TFTP_UL_REQ);
		default:
			snprintf(buf, sizeof(buf), "%04x", code);
			return buf;
	}
#undef CASE_CODE
}

static uint16_t to_region_code(const char *region)
{
#define REGION_CODE(r, c) if (!strcasecmp(region, r)) return c
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

static void msg_dump(struct nmrp_msg *msg, int dump_opts)
{
	struct nmrp_opt *opt;
	int remain_len, len, i;

	fprintf(stderr, "res=0x%04x, code=0x%02x, id=0x%02x, len=%u",
			msg->reserved, msg->code, msg->id, msg->len);

	remain_len = msg->len - NMRP_HDR_LEN;
	fprintf(stderr, "%s\n", remain_len ? "" : " (no opts)");

	if (dump_opts) {
		opt = msg->opts;

		while (remain_len > 0) {
			len = opt->len;
			fprintf(stderr, "  opt type=%u, len=%u", opt->type, len);
			if (len) {
				for (i = 0; i != len - NMRP_OPT_HDR_LEN; ++i) {
					if (!(i % 16)) {
						fprintf(stderr, "\n  ");
					}

					fprintf(stderr, "%02x ", ((char*)&opt->val)[i] & 0xff);
				}
				fprintf(stderr, "\n");
			}
			remain_len -= len;
			opt = NMRP_OPT_NEXT(opt);
		}
	}
}

static void msg_hton(struct nmrp_msg *msg)
{
	uint32_t i = 0;
	struct nmrp_opt *opt = msg->opts, *next;

	msg->reserved = htons(msg->reserved);
	msg->len = htons(msg->len);

	for (; i != msg->num_opts; ++i) {
		next = NMRP_OPT_NEXT(opt);
		opt->len = htons(opt->len);
		opt->type = htons(opt->type);
		opt = next;
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

	remaining = msg->len - NMRP_HDR_LEN;

	// FIXME maximum of two options supported, maximum option
	// size is 12
	if (remaining < NMRP_MAX_OPT_NUM * NMRP_MAX_OPT_SIZE) {
		while (remaining > 0) {
			if (remaining < NMRP_OPT_HDR_LEN) {
				break;
			}

			opt->type = ntohs(opt->type);
			opt->len = ntohs(opt->len);

			if (opt->len > NMRP_MAX_OPT_SIZE) {
				break;
			}

			remaining -= opt->len;
			opt = NMRP_OPT_NEXT(opt);
		}

		if (!remaining) {
			return 0;
		}
	}

	fprintf(stderr, "Unexpected message format.\n");
	msg_dump(msg, 0);
	return 1;
}

static void *msg_opt_data(struct nmrp_msg *msg, uint16_t type, uint16_t *len)
{
	static char buf[128];
	struct nmrp_opt *opt = msg->opts;
	int remaining = msg->len - NMRP_HDR_LEN;

	memset(buf, 0, sizeof(buf));

	while (remaining > 0) {
		if (opt->type == type) {
			if (opt->len == NMRP_OPT_HDR_LEN) {
				return NULL;
			}
			*len = opt->len - NMRP_OPT_HDR_LEN;
			memcpy(buf, &opt->val, MIN(*len, sizeof(buf)-1));
			return buf;
		}

		remaining -= opt->len;
		opt = NMRP_OPT_NEXT(opt);
	}

	return NULL;
}

static void msg_opt_add(struct nmrp_msg *msg, uint16_t type, void *data,
		uint16_t len)
{
	uint32_t i = 0;
	struct nmrp_opt *opt = msg->opts;

	if (len + NMRP_OPT_HDR_LEN > NMRP_MAX_OPT_SIZE
			|| msg->num_opts == NMRP_MAX_OPT_NUM) {
		fprintf(stderr, "Invalid option - this is a bug.\n");
	}

	for (; i <= msg->num_opts; ++i) {
		opt = NMRP_OPT_NEXT(opt);
	}

	opt->len = NMRP_OPT_HDR_LEN + len;
	opt->type = type;

	if (len) {
		memcpy(&opt->val, data, len);
	}

	msg->len += opt->len;
	++msg->num_opts;
}

static inline void msg_init(struct nmrp_msg *msg, uint16_t code)
{
	memset(msg, 0, sizeof(*msg));
	msg->len = NMRP_HDR_LEN;
	msg->code = code;
}

static int pkt_send(struct ethsock *sock, struct nmrp_pkt *pkt)
{
	size_t len = ntohs(pkt->msg.len) + sizeof(pkt->eh);
	return ethsock_send(sock, pkt, len);
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

	msg_hdr_ntoh(&pkt->msg);
	len = pkt->msg.len + sizeof(pkt->eh);

	if (bytes < len) {
		fprintf(stderr, "Short packet (expected %d, got %d).\n",
				(int)len, (int)bytes);
		return 1;
	}

	return msg_ntoh(&pkt->msg);
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

static struct ethsock *gsock = NULL;
static struct ethsock_ip_undo *gundo = NULL;
static int garp = 0;
static struct in_addr arpip = { 0 };
static uint8_t arpmac[6] = { 0 };

static void sigh(int sig)
{
	printf("\n");
	if (gsock) {
		if (garp) {
			ethsock_arp_del(gsock, arpmac, &arpip);
		}
		ethsock_ip_del(gsock, &gundo);
		ethsock_close(gsock);
		gsock = NULL;
	}

	exit(1);
}

static const char *spinner = "\\|/-";

int nmrp_do(struct nmrpd_args *args)
{
	struct nmrp_pkt tx, rx;
	uint8_t *src, dest[6];
	uint16_t len, region;
	char *filename;
	time_t beg;
	int i, status, ulreqs, expect, upload_ok, autoip;
	struct ethsock *sock;
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

	if ((ipconf.mask.s_addr = inet_addr(args->ipmask)) == INADDR_NONE) {
		fprintf(stderr, "Invalid subnet mask '%s'.\n", args->ipmask);
		return 1;
	}

	if (!args->ipaddr) {
		autoip = true;
		args->ipaddr = "10.11.12.252";

		if (!args->ipaddr_intf) {
			args->ipaddr_intf = "10.11.12.253";
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
		region = htons(to_region_code(args->region));
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

	gsock = sock;
	garp = 0;
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

		if (ethsock_ip_add(sock, intf_addr, ipconf.mask.s_addr, &gundo) != 0) {
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

	msg_init(&tx.msg, NMRP_C_ADVERTISE);
	msg_opt_add(&tx.msg, NMRP_O_MAGIC_NO, "NTGR", 4);
	msg_hton(&tx.msg);

	i = 0;
	upload_ok = 0;
	beg = time(NULL);

	while (1) {
		printf("\rAdvertising NMRP server on %s ... %c",
				args->intf, spinner[i]);
		fflush(stdout);
		i = (i + 1) & 3;

		if (pkt_send(sock, &tx) < 0) {
			perror("sendto");
			goto out;
		}

		status = pkt_recv(sock, &rx);
		if (status == 0 && memcmp(rx.eh.ether_dhost, src, 6) == 0) {
			break;
		} else if (status == 1) {
			goto out;
		} else {
			if ((time(NULL) - beg) >= 60) {
				printf("\nNo response after 60 seconds. Bailing out.\n");
				goto out;
			}
		}
	}

	printf("\n");

	expect = NMRP_C_CONF_REQ;
	ulreqs = 0;

	do {
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
				tx.msg.code = NMRP_C_CONF_ACK;

				msg_opt_add(&tx.msg, NMRP_O_DEV_IP, &ipconf, 8);
				msg_opt_add(&tx.msg, NMRP_O_FW_UP, NULL, 0);

#ifdef NMRPFLASH_SET_REGION
				if (region) {
					msg_opt_add(&tx.msg, NMRP_O_DEV_REGION, &region, 2);
				}
#endif

				expect = NMRP_C_TFTP_UL_REQ;

				printf("Received configuration request from %s.\n",
						mac_to_str(rx.eh.ether_shost));

				memcpy(tx.eh.ether_dhost, rx.eh.ether_shost, 6);

				printf("Sending configuration: ip %s, mask %s.\n",
						args->ipaddr, args->ipmask);

				memcpy(arpmac, rx.eh.ether_shost, 6);
				memcpy(&arpip, &ipconf.addr, sizeof(ipconf.addr));

				if (ethsock_arp_add(sock, arpmac, &arpip) != 0) {
					goto out;
				}

				garp = 1;

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

				len = 0;
				filename = msg_opt_data(&rx.msg, NMRP_O_FILE_NAME, &len);
				if (filename) {
					if (!args->file_remote) {
						args->file_remote = filename;
					}
					printf("Received upload request: filename '%.*s'.\n",
							len, filename);
				} else if (!args->file_remote) {
					args->file_remote = args->file_local;
					printf("Received upload request with empty filename.\n");
				}

				status = 0;

				if (args->tftpcmd) {
					printf("Executing '%s' ... \n", args->tftpcmd);
					setenv("IP", inet_ntoa(ipconf.addr), 1);
					setenv("MAC", mac_to_str(rx.eh.ether_shost), 1);
					setenv("NETMASK", inet_ntoa(ipconf.mask), 1);
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
					status = tftp_put(args);
				}

				if (!status) {
					printf("OK\nWaiting for remote to respond.\n");
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
				msg_dump(&rx.msg, 0);
		}

		if (tx.msg.code != NMRP_C_NONE) {
			msg_hton(&tx.msg);

			if (pkt_send(sock, &tx) < 0) {
				perror("sendto");
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

	} while (1);

	status = 0;

	if (ulreqs) {
		printf("Reboot your device now.\n");
	} else {
		printf("No upload request received.\n");
	}

out:
	signal(SIGINT, sigh_orig);
	gsock = NULL;
	ethsock_arp_del(sock, arpmac, &arpip);
	ethsock_ip_del(sock, &gundo);
	ethsock_close(sock);
	return status;
}
