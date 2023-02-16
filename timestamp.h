//! \file timestamp.h - header for 32 bit timestamp functions
#ifndef TIMESTAMP_H
#define TIMESTAMP_H




#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <stddef.h>
#include <sys/sysinfo.h>


uint32_t stampstart();
 
uint32_t stampstop(uint32_t start);

long long timespecDiff(struct timeval* start, struct timeval* end);

#endif
