/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_time.h
* @brief			a little time interface copied from include/linux;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/


#ifndef _US_TIME_H
#define _US_TIME_H

#include "types.h"

#include <sys/time.h>
#include <unistd.h>

#define 		HZ    (1000)	//us is better;	

#define MSEC_PER_SEC	1000L
#define USEC_PER_MSEC	1000L
#define NSEC_PER_USEC	1000L
#define NSEC_PER_MSEC	1000000L
#define USEC_PER_SEC	1000000L
#define NSEC_PER_SEC	1000000000L
#define FSEC_PER_SEC	1000000000000000LL

#define KTIME_MAX				((s64)~((u64)1 << 63))

#if (BITS_PER_LONG == 64)
# define KTIME_SEC_MAX			(KTIME_MAX / NSEC_PER_SEC)
#else
# define KTIME_SEC_MAX			LONG_MAX
#endif


extern 	struct 	 timespec	Ts;
/*
struct us_timespec {
	unsigned long		tv_sec;			// seconds 
	unsigned long		tv_nsec;		// nanoseconds
};

struct us_timeval {
	unsigned long			tv_sec;			// seconds 
	unsigned int			tv_usec;		// microseconds 
};

struct us_timezone {
	int			tz_minuteswest;	// minutes west of Greenwich 
	int			tz_dsttime;		// type of dst correction 
};*/

/*
 *	These inlines deal with timer wrapping correctly. You are 
 *	strongly encouraged to use them
 *	1. Because people otherwise forget
 *	2. Because if the timer wrap changes in future you won't have to
 *	   alter your driver code.
 *
 * time_after(a,b) returns true if the time a is after time b.
 *
 * Do this with "<0" and ">=0" to only test the sign of the result. A
 * good compiler would generate better code (and a really good compiler
 * wouldn't care). Gcc is currently neither.
 */
#define time_after(a,b)		\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(b) - (long)(a) < 0))
#define time_before(a,b)	time_after(b,a)

#define time_after_eq(a,b)	\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(a) - (long)(b) >= 0))
#define time_before_eq(a,b)	time_after_eq(b,a)

/*
 * Calculate whether a is in the range of [b, c].
 */
#define time_in_range(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before_eq(a,c))

/*
 * Calculate whether a is in the range of [b, c).
 */
#define time_in_range_open(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before(a,c))

/* Same as above, but does so with platform independent 64bit types.
 * These must be used when utilizing jiffies_64 (i.e. return value of
 * uil_get_jiffies_64() */
#define time_after64(a,b)	\
	(typecheck(__u64, a) &&	\
	 typecheck(__u64, b) && \
	 ((__s64)(b) - (__s64)(a) < 0))
#define time_before64(a,b)	time_after64(b,a)

#define time_after_eq64(a,b)	\
	(typecheck(__u64, a) && \
	 typecheck(__u64, b) && \
	 ((__s64)(a) - (__s64)(b) >= 0))
#define time_before_eq64(a,b)	time_after_eq64(b,a)


extern s32 time_init(void);
extern s32 time_update(void);
extern struct timeval ns_to_timeval(const s64 nsec);

static inline unsigned long 	us_get_seconds(void)
{
	//return timekeeper.xtime.tv_sec;
	//return 0;
	return Ts.tv_sec;
}

static inline unsigned long 	msecs_to_jiffies(const unsigned int m)
{
	return m * (HZ / MSEC_PER_SEC);   //smallboy:Fix it later if HZ!= 1000;
}

static inline unsigned int jiffies_to_usecs(const unsigned long j)  //smallboy:Fix it later if HZ!= 1000;
{
	return (USEC_PER_SEC / HZ) * j;
#if 0	
#if HZ <= USEC_PER_SEC && !(USEC_PER_SEC % HZ)
	return (USEC_PER_SEC / HZ) * j;
#elif HZ > USEC_PER_SEC && !(HZ % USEC_PER_SEC)
	return (j + (HZ / USEC_PER_SEC) - 1)/(HZ / USEC_PER_SEC);
#else
# if BITS_PER_LONG == 32
	return (HZ_TO_USEC_MUL32 * j) >> HZ_TO_USEC_SHR32;
# else
	return (j * HZ_TO_USEC_NUM) / HZ_TO_USEC_DEN;
# endif
#endif
#endif
}

static inline unsigned int jiffies_to_msecs(const unsigned long j)
{
	return (MSEC_PER_SEC / HZ) * j;
#if 0	
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	return (MSEC_PER_SEC / HZ) * j;
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	return (j + (HZ / MSEC_PER_SEC) - 1)/(HZ / MSEC_PER_SEC);
#else
# if BITS_PER_LONG == 32
	return (HZ_TO_MSEC_MUL32 * j) >> HZ_TO_MSEC_SHR32;
# else
	return (j * HZ_TO_MSEC_NUM) / HZ_TO_MSEC_DEN;
# endif
#endif
#endif
}









#endif

