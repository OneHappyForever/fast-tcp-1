/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			ktime.h
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/ 


#ifndef _US_KTIME_H
#define _US_KTIME_H

#include "types.h"
#include "us_time.h"

/*
 * ktime_t:
 *
 * On 64-bit CPUs a single 64-bit variable is used to store the hrtimers
 * internal representation of time values in scalar nanoseconds. The
 * design plays out best on 64-bit CPUs, where most conversions are
 * NOPs and most arithmetic ktime_t operations are plain arithmetic
 * operations.
 *
 * On 32-bit CPUs an optimized representation of the uil_timespec structure
 * is used to avoid expensive conversions from and to timespecs. The
 * endian-aware order of the tv struct members is chosen to allow
 * mathematical operations on the tv64 member of the union too, which
 * for certain operations produces better code.
 *
 * For architectures with efficient support for 64/32-bit conversions the
 * plain scalar nanosecond based representation can be selected by the
 * config switch CONFIG_KTIME_SCALAR.
 */
union ktime {
	s64	tv64;
};


typedef union ktime ktime_t;		/* Kill this */


static inline int ktime_equal(const ktime_t cmp1, const ktime_t cmp2)
{
	return cmp1.tv64 == cmp2.tv64;
}

/* Map the ktime_t to uil_timeval conversion to ns_to_timeval function */
#define ktime_to_timeval(kt)		ns_to_timeval((kt).tv64)
/* Convert ktime_t to nanoseconds - NOP in the scalar storage format: */
#define ktime_to_ns(kt)				((kt).tv64)


static inline s64 ktime_to_us(const ktime_t kt)
{
	struct timeval tv = ktime_to_timeval(kt);
	return (s64) tv.tv_sec * USEC_PER_SEC + tv.tv_usec;
}

static inline ktime_t ktime_set(const long secs, const unsigned long nsecs)
{
#if (BITS_PER_LONG == 64)
	if (unlikely(secs >= KTIME_SEC_MAX))
		return (ktime_t){ .tv64 = KTIME_MAX };
#endif
	return (ktime_t) { .tv64 = (s64)secs * NSEC_PER_SEC + (s64)nsecs };
}


static inline ktime_t timespec_to_ktime(struct timespec *ts)
{
	return ktime_set(ts->tv_sec, ts->tv_nsec);
}

static inline ktime_t ktime_get_real(void)
{
	//struct uil_timespec now;
	//getnstimeofday(&now);
	return timespec_to_ktime(&Ts);
}

/* Subtract two ktime_t variables. rem = lhs -rhs: */
#define ktime_sub(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 - (rhs).tv64 }; })

static inline s64 ktime_us_delta(const ktime_t later, const ktime_t earlier)
{
       return ktime_to_us(ktime_sub(later, earlier));
}


#endif

