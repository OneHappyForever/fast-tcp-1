/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_time.c
* @brief			a little time interface copied from include/linux;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/

#include "us_time.h"
#include "us_error.h"

u64						start_jiffies;
volatile u64			jiffies;  		//ms ---->HZ
volatile u64			cycles;	  		//rte_rdtsc() on the timer lcore;
struct 	 timespec	   	Ts;				//time clock;

static u64 last_1us_cycle ;
static u64 last_1ms_cycle ;
static u32 tv_usec = 0;

s32 time_init(void)
{
	s32 ret = US_RET_OK;
	Ts.tv_nsec = Ts.tv_sec = 0;
	
	struct timeval tv;
	
	if( (ret = gettimeofday((struct timeval*)&tv, NULL))< 0){
		return ret;
	}
	
	Ts.tv_sec = tv.tv_sec;
	Ts.tv_nsec = tv.tv_usec*1000;					//LF_late;

	jiffies = Ts.tv_sec*HZ + Ts.tv_nsec/1000000;

	start_jiffies = jiffies;

	last_1us_cycle = cycles;
	last_1ms_cycle = cycles;
	
	return 0;
}

s32 time_update(void)
{
#if 0
	//int ret = US_RET_OK;
	//int sec_delta = 0; 
	//struct timeval tv;

	//cycles = rte_get_hpet_cycles();
	cycles = rte_rdtsc();

	if( (ret = gettimeofday((struct timeval*)&tv, NULL))< 0){
		return ret;
	}	

	sec_delta = ((tv.tv_sec - Ts.tv_sec)*1000000 + (tv.tv_usec - Ts.tv_nsec/1000))/1000;

	if (sec_delta > 0 ){
		jiffies += sec_delta;
		
		Ts.tv_sec = tv.tv_sec;
		Ts.tv_nsec = tv.tv_usec*1000;	
	}

#else
	
	u64 sec_1_cnt ;
	u64 ms_1_cnt ;
	u64	us_1_cnt ;
	u64 t_delta;
	
	sec_1_cnt = rte_get_timer_hz();
	ms_1_cnt  = sec_1_cnt/1000;
	us_1_cnt  = ms_1_cnt/1000;
	
	cycles = rte_rdtsc();

	t_delta = cycles - last_1us_cycle;
	if(t_delta > us_1_cnt){
		tv_usec += t_delta/us_1_cnt;
		if(Ts.tv_nsec >1000000){
			Ts.tv_nsec = 0;
			Ts.tv_sec++;
		}else{
			Ts.tv_nsec = tv_usec*1000;
		}
		last_1us_cycle = cycles;
	}
	
	t_delta = cycles - last_1ms_cycle;
	if(t_delta > ms_1_cnt){
		jiffies += t_delta/ms_1_cnt ;
		last_1ms_cycle = cycles;
	}
	
	return US_RET_OK;
#endif	
}


/**
 * div_s64_rem - signed 64bit divide with 32bit divisor with remainder
 */
static inline s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}


struct timespec ns_to_timespec(const s64 nsec)
{
	struct timespec ts;
	s32 rem;

	if (!nsec)
		return (struct timespec) {0, 0};

	ts.tv_sec = div_s64_rem(nsec, NSEC_PER_SEC, &rem);
	if (unlikely(rem < 0)) {
		ts.tv_sec--;
		rem += NSEC_PER_SEC;
	}
	ts.tv_nsec = rem;

	return ts;
}


struct timeval ns_to_timeval(const s64 nsec)
{
	struct timespec ts = ns_to_timespec(nsec);
	struct timeval  tv;

	tv.tv_sec = ts.tv_sec;
	tv.tv_usec =  ts.tv_nsec / 1000;

	return tv;
}

