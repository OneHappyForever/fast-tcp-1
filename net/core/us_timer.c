/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_timer.c
* @brief			the timer function which forked from BGW;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/

//@note : us_timer is not thread safe; 

#include "types.h"
#include "us_timer.h"
#include "us_error.h"
#include "glb_var.h"

//For debug;
#include "socket.h"
#include "inet_connection_sock.h"
#include "us_entry.h"

#include <sys/time.h>

US_DEFINE_PER_LCORE(us_tvec_base_t,Tb);
US_DEFINE_PER_LCORE(struct us_timer_list,glb_ticks);
US_DEFINE_PER_LCORE(struct us_timer_list,glb_tickm);


extern void dmesg_all(const char *caller,int line);

static inline us_vec_head_t* get_new_vec_head(us_tvec_base_t *base, unsigned long long expires)
{
	unsigned long long idx = expires - base->timer_jiffies;
	us_vec_head_t *vec;

	if (idx < TVR_SIZE) {
		int i = expires & TVR_MASK;
		vec = base->tv1.vec + i;
	} else if (idx < 1 << (TVR_BITS + TVN_BITS)) {
		int i = (expires >> TVR_BITS) & TVN_MASK;
		vec = base->tv2.vec + i;
	} else if ((signed long long) idx < 0) {
		/*
		 * Can happen if you add a timer with expires == jiffies,
		 * or you set a timer to go off in the past
		 */
		vec = base->tv1.vec + ((base->timer_jiffies+1) & TVR_MASK) ;
	} else {
		int i;
		/* If the timeout is larger than 0xffffffff on 64-bit
		 * architectures then we use the maximum timeout:
		 */
		if (idx > 0xffffffffUL) {
			idx = 0xffffffffUL;
			expires = idx + base->timer_jiffies;
		}
		i = (expires >> (TVR_BITS + TVN_BITS)) & TVN_MASK;
		vec = base->tv3.vec + i;
	}
    return vec;
}


//@output, return -1 if failed
//@output, return 1 when success && take timer from other base to my base
//@output, return 0 when success && not move timer from one base to another
int __us_mod_timer(struct us_timer_list *timer, unsigned long long expires)
{
	int ret = 0;
    us_tvec_base_t *host_base ;
    us_vec_head_t * new_vec_head = NULL, * old_vec_head = NULL;

    if( us_mod_check_timer(timer) < 0 ) {
        return -1;
    }

	if (us_timer_pending(timer)){
		ret = 1;
	}

    timer->expires = expires;
    old_vec_head = timer->base_vec;
    //host_base = &Tb ;
    host_base = &US_PER_LCORE(Tb); 
    new_vec_head = get_new_vec_head(host_base, expires);
	if (new_vec_head == old_vec_head)
		return ret;
	
    if(old_vec_head){
	    us_list_del(&timer->entry);
    }

    us_attach_timer(timer, new_vec_head);
    return ret;
}

//@brief , init a us_timer system here;
int us_timer_init(void) 
{
	us_tvec_base_t *host_base = &US_PER_LCORE(Tb); 
    us_init_tvec_root_t( &host_base->tv1);
    us_init_tvec_t(  &host_base->tv2);
    us_init_tvec_t(  &host_base->tv3);
	host_base->timer_jiffies = jiffies;
	host_base->running_timer = NULL;

	return 0;
}

static inline int us_del_check_timer(struct us_timer_list *timer)
{
    if(unlikely(timer->magic != TIMER_MAGIC)){
		return -1;
    }
    return 0;
}

static inline int us_detach_timer(struct us_timer_list * timer)
{
	us_vec_head_t *base_vec;
 	base_vec = timer->base_vec;
	if (!base_vec){
		//US_ERR("us_detach_timer!\n");
		return 0;
	}

	us_list_del(&timer->entry);
	timer->base_vec = NULL;
		
    return 1;
}

//@brief , try to detach a timer struct from list; 
int us_del_timer(struct us_timer_list *timer)
{
	if( us_del_check_timer(timer) <0 ){
		//us_abort(US_GET_LCORE());
		return -1;
	}
    return us_detach_timer(timer);
}

/***
 * mod_timer - modify a timer's timeout
 * @timer: the timer to be modified
 *
 * mod_timer is a more efficient way to update the expire field of an
 * active timer (if the timer is inactive it will be activated)
 *
 * mod_timer(timer, expires) is equivalent to:
 *
 *     del_timer(timer); timer->expires = expires; add_timer(timer);
 *
 * Note that if there are multiple unserialized concurrent users of the
 * same timer, then mod_timer() is the only safe way to modify the timeout,
 * since add_timer() cannot modify an already running timer.
 *
 * The function returns whether it has modified a pending timer or not.
 * (ie. mod_timer() of an inactive timer returns 0, mod_timer() of an
 * active timer returns 1.)
 */
int us_mod_timer(struct us_timer_list *timer, unsigned long long expires)
{
	/*
	 * This is a common optimization triggered by the
	 * networking code - if the timer is re-modified
	 * to be the same thing then just return:
	 */
	if (timer->expires == expires && us_timer_pending(timer))
		return 1;

	return __us_mod_timer(timer, expires);
}

//@biref , try to delay a timer for mdelay here;
//@note  , the unit of measurement is the same with  HZ;
int us_delay_timer(struct us_timer_list *timer,unsigned long mdelay)
{
	return us_mod_timer(timer,jiffies + mdelay);	
}

//@biref , init a timer sturct here;
//@input , timer--> the pointer into the timer stuct;
//@input , th--> the callback function embedded in the timer struct;
//@input , arg--> the arg for the callback function above;
int us_setup_timer(struct us_timer_list *timer, timer_handler th, void *arg,u32 timer_type)
{
	if(us_timer_pending(timer)){
		return US_EALREADY;
	}
	
	us_init_timer(timer,0,timer_type);
	timer->data = (unsigned long)arg;
	timer->function = th;
	return US_RET_OK;
}

static int cascade(us_tvec_base_t *base, us_tvec_t *tv, int index)
{
	/* cascade all the timers from tv up one level */
	struct us_list_head *head, *curr;
    us_vec_head_t * new_vec_head, * old_vec_head;

	old_vec_head = tv->vec + index;
    head = &old_vec_head->head;
	curr = head->next;
	while (curr != head) {
		struct us_timer_list *tmp;

        tmp = us_list_entry(curr, struct us_timer_list, entry) ;
		curr = curr->next;
        new_vec_head = get_new_vec_head(base, tmp->expires );
        if(new_vec_head != old_vec_head) {
            __us_list_del(tmp->entry.prev, tmp->entry.next);
            us_attach_timer(tmp, new_vec_head);
        }
    }

	return index;
}


#define INDEX(N) (base->timer_jiffies >> (TVR_BITS + N * TVN_BITS)) & TVN_MASK
inline void run_timer(us_tvec_base_t* base,int budget){
    struct us_timer_list * timer=NULL;
 	int index;
    us_vec_head_t * vec_head = NULL;
    struct us_list_head* head = NULL;
	//int budget = g_per_cpu_dft_val_cp->timer_budget;
	//int budget = 10;

    while(budget > 0 && (jiffies >= base->timer_jiffies)){
 		index = base->timer_jiffies & TVR_MASK;
        vec_head = base->tv1.vec + index;
        head = &vec_head->head;
    	// Cascade timers:
    	if ((index==0)
    		&& ((cascade(base, &base->tv2, INDEX(0))) ==0 ) )
        {
    		cascade(base, &base->tv3, INDEX(1));
        }
		
		while(!us_list_empty(head) && (budget--)>0) {

			void (*fn)(unsigned long);
			unsigned long data;
			
			timer = us_list_entry(head->next,struct us_timer_list,entry);
 			fn = timer->function;
 			data = timer->data;	
			
			us_list_del(&timer->entry);

			timer->base_vec = NULL;			
			fn(data);
        }
		
		if(us_list_empty(head))
			base->timer_jiffies++;
	}

    return;
}

//@brief , for debug here;
void timer_test(unsigned long data)
{	
	//cyc_delta = cycles - cyc_base ;
	
	//US_ERR("TTTTTTTTTTTTTTTTTTTTTTTTTTT timer_min :%d  %d %d %d\n"
	//					,timer_cnt_del - timer_cnt_old
	//					,cyc1*100/cyc_delta
	//					,cyc2*100/cyc_delta
	//					,cyc3*100/cyc_delta);

	//disp_int_stats();
	
	//cyc_flush = 1;

	//cyc_base = cycles;
	
	///timer_cnt_old = timer_cnt_del;

	//dmesg_all(__FUNCTION__,__LINE__);
	memobj_dump_all();
	//us_debug_tcp_sock_info();
	//dmesg_snmp_all();
	
	//int ret = 0;
	//struct timeval tv;
	
	//if( (ret = gettimeofday((struct timeval*)&tv, NULL))>= 0){
//#ifdef US_DEBUG_TIMER		
	//	US_ERR("thread:%u  sec = %u ; usec = %lu jiffies = %lu \n"
	//				,US_GET_LCORE(),(u32)tv.tv_sec,tv.tv_usec,jiffies);
//#endif
//		glb_thread[US_GET_LCORE()].cyc_new = (jiffies);
//	}

	glb_thread[US_GET_LCORE()].cyc_new = (jiffies);
	us_mod_timer((struct us_timer_list *)data , jiffies + 1000);
	
	extern struct socket * debug_sk_p;

	if((US_GET_LCORE() == GLB_US_LCORE_LB) && (debug_sk_p != NULL)){
		fprintf(stderr,"TH:%u reqsk_queue_len:%d :%d queue_full:%u accept_full:%u sk_ack_backlog:%u/%u nf_trace:%u\n"
			,US_GET_LCORE(),inet_csk_reqsk_queue_len(debug_sk_p->sk)
			,inet_csk(debug_sk_p->sk)->icsk_accept_queue.listen_opt->max_qlen_log
			,inet_csk_reqsk_queue_is_full(debug_sk_p->sk)
			,sk_acceptq_is_full(debug_sk_p->sk)
			,debug_sk_p->sk->sk_ack_backlog
			,debug_sk_p->sk->sk_max_ack_backlog
			,glb_debug_trace);
		
		glb_debug_trace = 0;
	}//else{
	//	fprintf(stderr,"lcore:%u type:%u debug_sk_p:%p :%p \n"
	//			,US_GET_LCORE(),glb_thread[US_GET_LCORE()].th_type,debug_sk_p);
	//}
}

s32 us_timer_test(void )
{
	struct us_timer_list *ticks = &US_PER_LCORE(glb_ticks);
	struct us_timer_list *tickm	= &US_PER_LCORE(glb_tickm);;

	memset(ticks,0,sizeof(struct us_timer_list));
	memset(tickm,0,sizeof(struct us_timer_list));

	us_init_timer(ticks,0,TIMER_TYPE_NONE);
	us_init_timer(tickm,0,TIMER_TYPE_NONE);
	
	ticks->data = (unsigned long)ticks;
	ticks->expires = jiffies;
	ticks->function = timer_test;

	tickm->data = (unsigned long)tickm;
	tickm->expires = jiffies;

extern inline	void us_ip_send_flush(unsigned long data);
	
	tickm->function = us_ip_send_flush;

	us_add_timer(ticks);
	us_add_timer(tickm);

	return US_RET_OK;
}


