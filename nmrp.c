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
#define NMRP_OPT_LEN 4
#define NMRP_MIN_PKT_LEN (sizeof(struct eth_hdr) +  NMRP_HDR_LEN)

#define NMRP_MAX_OPT_SIZE 12
#define NMRP_MAX_OPT_NUM 2

#define ETH_P_NMRP 0x0912
#define IP_LEN 4
#define MAX_LOOP_RECV 1024

#ifndef PACKED
#define PACKED __attribute__((__packed__))
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
	struct nmrp_opt opts[2];
	uint32_t num_opts;
} PACKED;

struct eth_hdr {
	uint8_t ether_dhost[6];
	uint8_t ether_shost[6];
	uint16_t ether_type;
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

static void msg_update_len(struct nmrp_msg *msg)
{
	uint32_t i = 0;
	msg->len = NMRP_HDR_LEN;
	for (; i != msg->num_opts; ++i) {
		msg->len += msg->opts[i].len;
	}
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
			for (i = 0; i != len - NMRP_OPT_LEN; ++i) {
				if (!(i % 16)) {
					fprintf(stderr, "\n  ");
				}

				fprintf(stderr, "%02x ", ((char*)&opt->val)[i] & 0xff);
			}
			fprintf(stderr, "\n");
			remain_len -= len;
			opt = (struct nmrp_opt*)(((char*)opt) + len);
		}
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

	remaining = msg->len - NMRP_HDR_LEN;

	// FIXME maximum of two options supported, maximum option
	// size is 12
	if (remaining < NMRP_MAX_OPT_NUM * NMRP_MAX_OPT_SIZE) {
		while (remaining > 0) {
			if (remaining < NMRP_OPT_LEN) {
				break;
			}

			opt->type = ntohs(opt->type);
			opt->len = ntohs(opt->len);

			if (opt->len > NMRP_MAX_OPT_SIZE) {
				break;
			}

			remaining -= opt->len;
			++opt;
		}

		if (!remaining) {
			return 0;
		}
	}

	fprintf(stderr, "Unexpected message format.\n");
	msg_dump(msg, 0);
	return 1;
}

static void *msg_opt_data(struct nmrp_msg *msg, int type, uint16_t *len)
{
	static char buf[128];
	struct nmrp_opt *opt = msg->opts;
	int remaining = msg->len - NMRP_HDR_LEN;

	memset(buf, 0, sizeof(buf));

	while (remaining > 0) {
		if (opt->type == type) {
			if (opt->len == NMRP_OPT_LEN) {
				return NULL;
			}
			*len = opt->len - NMRP_OPT_LEN;
			memcpy(buf, &opt->val, MIN(*len, sizeof(buf)-1));
			return buf;
		}

		remaining -= opt->len;
		opt = (struct nmrp_opt*)((char*)opt) + opt->len;
	}

	return NULL;
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

static void sigh(int sig)
{
	printf("\n");
	if (gsock) {
		ethsock_close(gsock);
	}

	exit(1);
}

static const char *spinner = "\\|/-";

int nmrp_do(struct nmrpd_args *args)
{
	struct nmrp_pkt tx, rx;
	uint8_t *src, dest[6];
	uint16_t len;
	char *filename;
	struct in_addr ipaddr, ipmask;
	time_t beg;
	int i, status, ulreqs, expect;
	struct ethsock *sock;
	void (*sigh_orig)(int);

	if (args->op != NMRP_UPLOAD_FW) {
		fprintf(stderr, "Operation not implemented.\n");
		return 1;
	}

	if (!mac_parse(args->mac, dest)) {
		fprintf(stderr, "Invalid MAC address '%s'.\n", args->mac);
		return 1;
	}

	if ((ipaddr.s_addr = inet_addr(args->ipaddr)) == INADDR_NONE) {
		fprintf(stderr, "Invalid IP address '%s'.\n", args->ipaddr);
		return 1;
	}

	if ((ipmask.s_addr = inet_addr(args->ipmask)) == INADDR_NONE) {
		fprintf(stderr, "Invalid subnet mask '%s'.\n", args->ipmask);
		return 1;
	}

	if (strcmp(args->file_local, "-") && access(args->file_local, R_OK) == -1) {
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

	status = 1;

	sock = ethsock_create(args->intf, ETH_P_NMRP);
	if (!sock) {
		return 1;
	}

	sigh_orig = signal(SIGINT, sigh);

	status = is_valid_ip(sock, &ipaddr, &ipmask);
	if (status <= 0) {
		if (!status) {
			fprintf(stderr, "Address %s/%s cannot be used on interface %s.\n",
					args->ipaddr, args->ipmask, args->intf);
		}
		goto out;
	}

	gsock = sock;

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
			printf("ERR\n");
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

		tx.msg.code = NMRP_C_NONE;
		tx.msg.reserved = 0;
		tx.msg.id = 0;
		tx.msg.num_opts = 0;
		tx.msg.len = 0;

		status = 1;

		switch (rx.msg.code) {
			case NMRP_C_ADVERTISE:
				printf("Received NMRP advertisement from %s.\n",
						mac_to_str(rx.eh.ether_shost));
				status = 1;
				goto out;
			case NMRP_C_CONF_REQ:
				tx.msg.code = NMRP_C_CONF_ACK;
				tx.msg.num_opts = 2;

				tx.msg.opts[0].type = NMRP_O_DEV_IP;
				tx.msg.opts[0].len = NMRP_OPT_LEN + 2 * 4;

				memcpy(tx.msg.opts[0].val.ip.addr, &ipaddr, 4);
				memcpy(tx.msg.opts[0].val.ip.mask, &ipmask, 4);

				tx.msg.opts[1].type = NMRP_O_FW_UP;
				tx.msg.opts[1].len = NMRP_OPT_LEN;

#ifdef NMRPFLASH_SET_REGION
				tx.msg.num_opts = 3;

				tx.msg.opts[2].type = NMRP_O_DEV_REGION;
				tx.msg.opts[2].len = NMRP_OPT_LEN + 2;
				tx.msg.opts[2].val.region = args->region;
#endif

				expect = NMRP_C_TFTP_UL_REQ;

				printf("Received configuration request from %s.\n",
						mac_to_str(rx.eh.ether_shost));

				memcpy(tx.eh.ether_dhost, rx.eh.ether_shost, 6);

				printf("Sending configuration: ip %s, mask %s.\n",
						args->ipaddr, args->ipmask);

				break;
			case NMRP_C_TFTP_UL_REQ:
				if (++ulreqs > 5) {
					fprintf(stderr, "Device re-requested file upload %d "
							"times; aborting.\n", ulreqs);
					tx.msg.code = NMRP_C_CLOSE_REQ;
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
					if (tftp_is_valid_filename(args->file_local)) {
						args->file_remote = args->file_local;
					} else {
						args->file_remote = "firmware";
					}
					printf("Received upload request with empty filename.");
				}

				status = 0;

				if (args->tftpcmd) {
					printf("Executing '%s' ... ", args->tftpcmd);
					fflush(stdout);
					status = system(args->tftpcmd);
					if (!status) {
						printf("OK\n");
					} else {
						printf("ERR\n");
					}
				}

				if (!status && args->file_local) {
					status = is_valid_ip(sock, &ipaddr, &ipmask);
					if (status < 0) {
						goto out;
					} else if (!status) {
						printf("IP address of %s has changed. Please assign a "
								"static ip to the interface.\n", args->intf);
						tx.msg.code = NMRP_C_CLOSE_REQ;
						break;
					}

					if (verbosity) {
						printf("Using remote filename '%s'.\n",
								args->file_remote);
					}

					if (!strcmp(args->file_local, "-")) {
						printf("Uploading from stdin ... ");
					} else {
						printf("Uploading %s ... ", args->file_local);
					}
					fflush(stdout);
					status = tftp_put(args);
				}

				if (!status) {
					printf("OK\nWaiting for remote to respond.\n");
					ethsock_set_timeout(sock, args->ul_timeout);
					expect = NMRP_C_NONE;
				} else if (status == -2) {
					expect = NMRP_C_TFTP_UL_REQ;
				} else {
					goto out;
				}

				break;
			case NMRP_C_KEEP_ALIVE_REQ:
				tx.msg.code = NMRP_C_KEEP_ALIVE_ACK;
				ethsock_set_timeout(sock, 15000);
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
			msg_update_len(&tx.msg);
			msg_hton(&tx.msg);

			if (pkt_send(sock, &tx) < 0) {
				perror("sendto");
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
	ethsock_close(sock);
	return status;
}
