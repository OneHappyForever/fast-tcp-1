/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_timer.h
* @brief			the timer function which forked from BGW;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/

//@note : us_timer is not thread safe;

#ifndef _US_TIMER_H
#define _US_TIMER_H

#include "types.h"
#include "list.h"

#define TVN_BITS (7)
#define TVR_BITS (18)
#define TVN_SIZE (1 << TVN_BITS)
#define TVR_SIZE (1 << TVR_BITS)
#define TVN_MASK (TVN_SIZE - 1)
#define TVR_MASK (TVR_SIZE - 1)

#define TIMER_MAGIC	0x4b87ad6e

#define TIMER_INITIALIZER(_function,_expires,_data) {			\
		.function = (_function),								\
		.expires = (_expires),								\
		.data = (_data),										\
		.base_vec = NULL,									\
		.magic = TIMER_MAGIC,								\
	}

#define TIMER_TYPE_NONE		(0)
#define TIMER_TYPE_TW		(1)
#define TIMER_TYPE_SK		(2)
#define TIMER_TYPE_KEEP		(3)
#define TIMER_TYPE_DACK		(4)
#define TIMER_TYPE_REW		(5)
#define TIMER_TYPE_USER1	(6)
#define TIMER_TYPE_USER2	(7)
#define TIMER_TYPE_USER3	(8)
#define TIMER_TYPE_USER4	(9)


typedef struct __us_vec_head_t{
    struct us_list_head head;
}us_vec_head_t;

typedef struct us_tvec_s {
    us_vec_head_t vec[TVN_SIZE];
}us_tvec_t;

typedef struct us_tvec_root_s {
    us_vec_head_t vec[TVR_SIZE];
}us_tvec_root_t;

typedef struct us_tvec_t_base_s {
    u64						timer_jiffies;
    struct us_timer_list 	*running_timer;
    us_tvec_root_t tv1;
    us_tvec_t tv2;
    us_tvec_t tv3;
}us_tvec_base_t;

struct us_timer_list {
	struct us_list_head 	entry;
	unsigned  long 			expires;			//unsigned long long;
	struct __us_vec_head_t *base_vec;
	unsigned long			magic;
	void 					(*function)(unsigned long);
	unsigned long 			data;
	u32						period;
	u32						type;
};


extern int us_mod_timer(struct us_timer_list *timer, unsigned long long expires);
extern int us_del_timer(struct us_timer_list * timer);
extern void us_run_timers(void);
extern int us_timer_init(void) ;
extern void run_timer(us_tvec_base_t* base,int budget);
extern int __us_mod_timer(struct us_timer_list *timer, unsigned long long expires);


/***
 * us_init_timer - initialize a timer.
 * @timer: the timer to be initialized
 *
 * us_init_timer() must be done to a timer prior calling *any* of the
 * other timer functions.
 */
static inline void us_init_timer(struct us_timer_list * timer,u32 period,u32 type)
{
	timer->period   = period;
	timer->type		= type;
	timer->base_vec = NULL;
	timer->magic = TIMER_MAGIC;
}

/***
 * us_timer_pending - is a timer pending?
 * @timer: the timer in question
 *
 * us_timer_pending will tell whether a given timer is currently pending,
 * or not. Callers must ensure serialization wrt. other operations done
 * to this timer, eg. interrupt contexts, or other CPUs on SMP.
 *
 * return value: 1 if the timer is pending, 0 if not.
 */
static inline int us_timer_pending(const struct us_timer_list * timer)
{
	return timer->base_vec != NULL;
}

/***
 * us_add_timer - start a timer
 * @timer: the timer to be added
 *
 * The kernel will do a ->function(->data) callback from the
 * timer interrupt at the ->expired point in the future. The
 * current time is 'jiffies'.
 *
 * The timer's ->expired, ->function (and if the handler uses it, ->data)
 * fields must be set prior calling this function.
 *
 * Timers with an ->expired field in the past will be executed in the next
 * timer tick.
 */
static inline void us_add_timer(struct us_timer_list *timer)
{	
	__us_mod_timer(timer, timer->expires);
}

static inline void  us_init_tvec_t(us_tvec_t * tv)
{
    int j;
    for (j = 0; j < TVN_SIZE; j++) {
        US_INIT_LIST_HEAD( &tv->vec[j].head );
    }
    return;

}

static inline void  us_init_tvec_root_t(us_tvec_root_t * tv)
{
    int j;
    for (j = 0; j < TVR_SIZE; j++) {
        US_INIT_LIST_HEAD( &tv->vec[j].head );
    }
    return;

}

// you must make sure timer->base_vec==NULL  when you call attach_timer
// you must make sure that timer is not in any list when you call attach_timer
// you must make sure nobody else will change timer when attach_timer is running
static inline void us_attach_timer(struct us_timer_list * timer, us_vec_head_t * new_vec_head)
{
	if(timer->magic != TIMER_MAGIC){
		US_ERR("us_attach_timer faile!\n");
		while(1);
	}

	us_list_add_tail(&timer->entry, &new_vec_head->head);
	timer->base_vec = new_vec_head;
}

static inline int us_mod_check_timer(struct us_timer_list *timer)
{

    if(unlikely(timer->magic != TIMER_MAGIC))
        return -1;
    if(unlikely(timer->function==NULL))
        return -1;

    return 0;
}

typedef void (*timer_handler)	(unsigned long);

extern s32 us_timer_test(void );
extern int us_setup_timer(struct us_timer_list *timer, timer_handler th, void *arg,u32 timer_type);
extern int us_delay_timer(struct us_timer_list *timer,unsigned long mdelay);
#endif

