#include <time.h>

#ifdef NMRPFLASH_OSX
#include <mach/mach_time.h>
#endif

time_t time_monotonic()
{
#ifndef NMRPFLASH_WINDOWS
#ifndef NMRPFLASH_OSX
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.ts_sec;
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

int main()
{
	time_t beg = time_monotonic();
	printf("now: %ld\n", beg);
	sleep(2);
	printf("+2s: %ld\n", time_monotonic());
	return 0;
}
