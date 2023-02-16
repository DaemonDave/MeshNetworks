//! \file timestamp.c
#ifndef TIMESTAMP_H
#include "timestamp.h"
#endif


uint32_t stampstart() 
{
	struct timeval  tv;
	struct timezone tz;
	struct tm      *tm;
	uint32_t         start;
 
	gettimeofday(&tv, &tz);
	tm = localtime(&tv.tv_sec);
 
	//printf("TIMESTAMP-START\t  %d:%02d:%02d:%d (~%d ms)\n", tm->tm_hour,
	//       tm->tm_min, tm->tm_sec, tv.tv_usec,
	//       tm->tm_hour * 3600 * 1000 + tm->tm_min * 60 * 1000 +
	//       tm->tm_sec * 1000 + tv.tv_usec / 1000);
 
	start = tm->tm_hour * 3600 * 1000 + tm->tm_min * 60 * 1000 +
		tm->tm_sec * 1000 + tv.tv_usec / 1000;
 
	return (start);
 
}
 
uint32_t stampstop(uint32_t start) 
{
	struct timeval  tv;
	struct timezone tz;
	struct tm      *tm;
	uint32_t         stop;
 
	gettimeofday(&tv, &tz);
	tm = localtime(&tv.tv_sec);
 
	stop = tm->tm_hour * 3600 * 1000 + tm->tm_min * 60 * 1000 +
		tm->tm_sec * 1000 + tv.tv_usec / 1000;
 
	//printf("TIMESTAMP-END\t  %d:%02d:%02d:%d (~%d ms) \n", tm->tm_hour,
	//       tm->tm_min, tm->tm_sec, tv.tv_usec,
	//       tm->tm_hour * 3600 * 1000 + tm->tm_min * 60 * 1000 +
	//       tm->tm_sec * 1000 + tv.tv_usec / 1000);
 
	//printf("ELAPSED\t  %d ms\n", stop - start);
 
	return (stop-start);
 
}

long long timespecDiff(struct timeval* start, struct timeval* end)
{
    long long t1, t2;
    t1 = start->tv_sec * 1000 + start->tv_usec;
    t2 = end->tv_sec * 1000 + end->tv_usec;
    return t1 - t2;
}
