/**
 * nmrp-flash - Netgear Unbrick Utility
 * Copyright (C) 2016 Joseph Lehner <joseph.c.lehner@gmail.com>
 *
 * nmrp-flash is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nmrp-flash is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with nmrp-flash.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef NMRPD_H
#define NMRPD_H
#include <stdint.h>
#include <stdbool.h>

#define NMRPD_VERSION "0.9"

enum nmrp_op {
	NMRP_UPLOAD_FW = 0,
	NMRP_UPLOAD_ST = 1,
	NMRP_SET_REGION = 2,
};

struct nmrpd_args {
	unsigned rx_timeout;
	unsigned ul_timeout;
	const char *tftpcmd;
	const char *filename;
	const char *ipaddr;
	const char *ipmask;
	const char *intf;
	const char *mac;
	enum nmrp_op op;
	uint16_t port;
	int force_root;
};

int sock_set_rx_timeout(int sock, unsigned msec);
int tftp_put(struct nmrpd_args *args);
int nmrp_do(struct nmrpd_args *args);


#endif