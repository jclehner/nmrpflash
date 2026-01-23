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

#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include "nmrpd.h"

#ifdef NMRPFLASH_MACOS
#include <mach/mach_time.h>
#endif

volatile sig_atomic_t g_interrupted = 0;
int verbosity = 0;

long long millis()
{
#ifndef NMRPFLASH_WINDOWS
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000 + ((ts.tv_nsec + 500000) / 1000000);
#else
	return GetTickCount();
#endif

}

time_t time_monotonic()
{
	return millis() / 1000;
}

char *xlltostr(long long ll, int base)
{
	static char buf[32];
	snprintf(buf, sizeof(buf) - 1, (base == 16 ? "%llx" : (base == 8 ? "%llo" : "%lld")), ll);
	return buf;
}

const char *mac_to_str(const uint8_t *mac)
{
	static char buf[18];
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return buf;
}

uint32_t bitcount(uint32_t n)
{
	uint32_t c;
	for (c = 0; n; ++c) {
		n &= n - 1;
	}
	return c;
}

uint32_t netmask(uint32_t count)
{
	return htonl(count <= 32 ? 0xffffffff << (32 - count) : 0);
}

int select_fd(int fd, unsigned timeout)
{
	struct timeval tv;
	int status;
	fd_set fds;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	tv.tv_sec = timeout / 1000;
	tv.tv_usec = 1000 * (timeout % 1000);

	status = select(fd + 1, &fds, NULL, NULL, &tv);
	if (status < 0) {
		sock_perror("select");
	}

	return status;
}

void xperror(const char *msg)
{
	if (errno != EINTR) {
		perror(msg);
	} else {
		printf("\n");
	}
}
