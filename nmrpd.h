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

#if defined(_WIN32) || defined(_WIN64)
#define NMRPFLASH_WINDOWS
#elif defined(__linux__)
#define NMRPFLASH_LINUX
#elif defined(__APPLE__) && defined(__MACH__)
#define NMRPFLASH_OSX
#elif defined(__unix__)
#define NMRPFLASH_UNIX
#warning "nmrp-flash is not fully supported on your operating system"
#endif

#ifndef NMRPFLASH_WINDOWS
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#else
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

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

int tftp_put(struct nmrpd_args *args);
int nmrp_do(struct nmrpd_args *args);

int select_fd(int fd, unsigned timeout);
const char *mac_to_str(uint8_t *mac);

#ifdef NMRPFLASH_WINDOWS
void win_perror2(const char *msg, DWORD err);
void sock_perror(const char *msg);
#else
#define sock_perror(x) perror(x)
#endif

extern int verbosity;

struct ethsock;

struct ethsock *ethsock_create(const char *intf, uint16_t protocol);
int ethsock_close(struct ethsock *sock);
int ethsock_send(struct ethsock *sock, void *buf, size_t len);
ssize_t ethsock_recv(struct ethsock *sock, void *buf, size_t len);
int ethsock_set_timeout(struct ethsock *sock, unsigned msec);
uint8_t *ethsock_get_hwaddr(struct ethsock *sock);
int ethsock_list_all(void);

#endif
