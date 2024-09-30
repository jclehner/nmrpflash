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

#ifndef NMRPD_H
#define NMRPD_H
#include <stdint.h>
#include <signal.h>
#include <stdbool.h>

#if defined(_WIN32) || defined(_WIN64)
#  define NMRPFLASH_WINDOWS
#elif defined(__APPLE__) && defined(__MACH__)
#  define NMRPFLASH_UNIX
#  define NMRPFLASH_OSX
#  define NMRPFLASH_BSD
#elif defined (__unix__)
#  define NMRPFLASH_UNIX
#  if defined(__linux__)
#    define NMRPFLASH_LINUX
#  elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__OpenBSD__)
#    define NMRPFLASH_BSD
#  else
#    warning "nmrpflash is not fully supported on this platform"
#  endif
#else
#	warning "nmrpflash is not supported on this platform"
#endif

#ifndef NMRPFLASH_WINDOWS
#  include <arpa/inet.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <net/if.h>
#  ifndef NMRPFLASH_LINUX
#    include <net/if_dl.h>
#  endif
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <conio.h>
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef PACKED
#define PACKED __attribute__((packed))
#endif

#define NMRPFLASH_SET_REGION

#define NMRP_DEFAULT_UL_TIMEOUT_S    (30 * 60)
#define NMRP_DEFAULT_RX_TIMEOUT_MS   (10000)
/*
 * These addresses should not cause collisions on most networks,
 * and if they do, the user is probably "poweruser" enough to
 * be able to use the -a and -A options.
 */
#define NMRP_DEFAULT_IP_LOCAL        "10.164.183.252"
#define NMRP_DEFAULT_IP_REMOTE       "10.164.183.253"
#define NMRP_DEFAULT_SUBNET          "255.255.255.0"
#define NMRP_DEFAULT_TFTP_PORT       69

struct eth_hdr {
	uint8_t ether_dhost[6];
	uint8_t ether_shost[6];
	uint16_t ether_type;
} PACKED;

enum nmrp_op {
	NMRP_UPLOAD_FW = 0,
	NMRP_UPLOAD_ST = 1,
	NMRP_SET_REGION = 2,
};

struct ethsock;

struct nmrpd_args {
	unsigned rx_timeout;
	unsigned ul_timeout;
	const char *tftpcmd;
	const char *file_local;
	const char *file_remote;
	const char *ipaddr_intf;
	const char *ipaddr;
	const char *ipmask;
	const char *intf;
	const char *mac;
	enum nmrp_op op;
	bool blind;
	uint16_t port;
	const char *region;
	off_t offset;

	struct ethsock *sock;
};

const char *leafname(const char *path);
ssize_t tftp_put(struct nmrpd_args *args);
bool tftp_is_valid_filename(const char *filename);

int nmrp_do(struct nmrpd_args *args);
bool nmrp_discard(struct ethsock *sock);

int select_fd(int fd, unsigned timeout);
const char *mac_to_str(uint8_t *mac);

#ifdef NMRPFLASH_WINDOWS
void win_perror2(const char *msg, DWORD err);
void sock_perror(const char *msg);
#else
#define sock_perror(x) xperror(x)
#endif

extern int verbosity;

struct ethsock_arp_undo;
struct ethsock_ip_undo;

struct ethsock *ethsock_create(const char *intf, uint16_t protocol);
bool ethsock_is_unplugged(struct ethsock *sock);
bool ethsock_is_wifi(struct ethsock *sock);
int ethsock_close(struct ethsock *sock);
int ethsock_send(struct ethsock *sock, void *buf, size_t len);
ssize_t ethsock_recv(struct ethsock *sock, void *buf, size_t len);
int ethsock_set_timeout(struct ethsock *sock, unsigned msec);
unsigned ethsock_get_timeout(struct ethsock *sock);
uint8_t *ethsock_get_hwaddr(struct ethsock *sock);
int ethsock_arp_add(struct ethsock *sock, uint8_t *hwaddr, uint32_t ipaddr, struct ethsock_arp_undo **undo);
int ethsock_arp_del(struct ethsock *sock, struct ethsock_arp_undo **undo);
int ethsock_list_all(void);

struct ethsock_ip_callback_args
{
	struct in_addr *ipaddr;
	struct in_addr *ipmask;
	void *arg;
};

typedef int (*ethsock_ip_callback_t)(struct ethsock_ip_callback_args *args);
int ethsock_for_each_ip(struct ethsock *sock, ethsock_ip_callback_t callback,
		void *arg);

int ethsock_ip_add(struct ethsock *sock, uint32_t ipaddr, uint32_t ipmask, struct ethsock_ip_undo **undo);
int ethsock_ip_del(struct ethsock *sock, struct ethsock_ip_undo **undo);

time_t time_monotonic();
long long millis();
char *lltostr(long long ll, int base);
uint32_t bitcount(uint32_t n);
uint32_t netmask(uint32_t count);
void xperror(const char *msg);

extern volatile sig_atomic_t g_interrupted;
#endif
