#include <stdio.h>
#include <time.h>
#include <math.h>
#include "nmrpd.h"

#ifdef NMRPFLASH_OSX
#include <mach/mach_time.h>
#endif

time_t time_monotonic()
{
#ifndef NMRPFLASH_WINDOWS
#ifndef NMRPFLASH_OSX
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
#else
	static double factor = 0.0;
	mach_timebase_info_data_t timebase;
	if (factor == 0.0) {
		mach_timebase_info(&timebase);
		factor = (double)timebase.numer / timebase.denom;
	}

	return round(mach_absolute_time() * factor / 1e9);
#endif
#else
	return round(GetTickCount() / 1000.0);
#endif
}

char *lltostr(long long ll, int base)
{
	static char buf[32];
	snprintf(buf, sizeof(buf) - 1, (base == 16 ? "%llx" : (base == 8 ? "%llo" : "%lld")), ll);
	return buf;
}
