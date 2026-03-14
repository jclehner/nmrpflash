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
#include <stdlib.h>
#include <unistd.h>
#include "nmrpd.h"

#ifdef NMRPFLASH_MACOS
#include <mach/mach_time.h>
#endif

#ifndef NMRPFLASH_WINDOWS
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#else
#include <winsafer.h>
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

int select_readfd(int fd, unsigned timeout)
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

#ifdef NMRPFLASH_WINDOWS
bool console_window_is_ours()
{
	DWORD pid;
	HWND win = GetConsoleWindow();
	if (!win || !GetWindowThreadProcessId(win, &pid)) {
		return false;
	}

	return GetCurrentProcessId() == pid;
}
#endif

#ifndef NMRPFLASH_WINDOWS
int run_as_user(const char* cmd, uid_t user)
#else
int run_as_user(const char* cmd, bool user)
#endif
{
	if (!user) {
		return system(cmd);
	}

#ifdef NMRPFLASH_WINDOWS
	SAFER_LEVEL_HANDLE level;
	HANDLE token = NULL;

	if (!SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, &level, NULL)) {
		win_perror("SaferCreateLevel");
		return -1;
	}

	if (!SaferComputeTokenFromLevel(level, NULL, &token, 0, NULL)) {
		win_perror("SaferComputeTokenFromLevel");
		return -1;
	}

	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };

	size_t bufsize = strlen(cmd) + 32;
	char* buf = malloc(bufsize);
	snprintf(buf, bufsize, "cmd /c \"%s\"", cmd);

	DWORD ret = -1;

	if (CreateProcessAsUserA(token, NULL, buf, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		WaitForSingleObject(pi.hProcess, INFINITE);
		GetExitCodeProcess(pi.hProcess, &ret);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	} else {
		win_perror("CreateProcessAsUserA");
	}
	free(buf);

	return ret;
#else
	pid_t pid = fork();
	if (!pid) {
		struct passwd* pw = getpwuid(user);
		if (!pw) {
			perror("getpwuid");
			_exit(1);
		}

		if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
			perror("initgroups");
			_exit(1);
		}

		if (setgid(pw->pw_gid) != 0) {
			perror("setgid");
			_exit(1);
		}

		if (setuid(pw->pw_uid) != 0) {
			perror("setuid");
			_exit(1);
		}

		// we don't care about the extra fork() here
		_exit(system(cmd));
	} else if (pid > 0) {
		int ret = -1;
		if (waitpid(pid, &ret, 0) == -1) {
			perror("waitpid");
		}
		return ret;
	} else {
		perror("fork");
	}
	return -1;
#endif
}
