/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			tcp_metrics.c
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/


#include "net.h"
#include "tcp.h"
#include "us_mem.h"
#include "socket.h"
#include "us_error.h"
#include "tcp_metrics.h"
#include "us_util.h"

US_DECLARE_PER_LCORE(us_mempool*,tcp_metric_pool);


#define TCP_METRICS_RECLAIM_DEPTH	5
#define TCP_METRICS_TIMEOUT			(2*HZ)  //(60*60*HZ)
#define TCP_METRICS_RECLAIM_PTR		(struct tcp_metrics_block *) 0x1UL


static bool addr_same(const struct inetpeer_addr *a,const struct inetpeer_addr *b)
{
	//const struct in6_addr *a6, *b6;

	if (a->family != b->family)
		return false;
	if (a->family == AF_INET)
		return a->addr.a4 == b->addr.a4;

	return false;	
	//a6 = (const struct in6_addr *) &a->addr.a6[0];
	//b6 = (const struct in6_addr *) &b->addr.a6[0];

	//return ipv6_addr_equal(a6, b6);
}

#if 0
static struct tcp_metrics_block *tcp_get_encode(struct tcp_metrics_block *tm, int depth,int used)
{
	if (tm)
		return tm;
	if (depth > TCP_METRICS_RECLAIM_DEPTH && depth > used)
		return TCP_METRICS_RECLAIM_PTR;
	return NULL;
}
#endif

static struct tcp_metrics_block* us_tcp_metric_alloc(struct net*pnet)
{
	s32 ret;
	u32 tcpm_id ;
	struct tcp_metrics_block	*tm;
	us_mempool	*us_p = pnet->tcpm_pool;
	ret = us_slab_get(us_p,(void**)&tm);
	//ret = us_slab_get(US_PER_LCORE(tcp_metric_pool),(void**)&tm);
	if(ret < 0){
		return NULL;
	}else{
		tcpm_id = tm->tcpm_id;
		memset(tm, 0, sizeof(struct tcp_metrics_block));
		tm->tcpm_id = tcpm_id;
	}

	return tm;
}

void us_tcp_metric_free(struct tcp_metrics_block *tm)			//Not used;
{
	if (tm){
		us_slab_free(US_PER_LCORE(tcp_metric_pool),tm);
	}
}


static inline bool __tcpm_backup(struct tcp_metrics_block *tm)		//old but hashed;
{
	return (tm->tcpm_older.tcp_m != NULL);
}

static inline bool tcp_metric_unhashed(const struct tcp_metrics_block *tm)
{
	return us_hlist_unhashed(&tm->tcpm_node);
}

static inline bool tcp_metric_hashed(const struct tcp_metrics_block *tm)
{
	return !us_hlist_unhashed(&tm->tcpm_node);
}

static inline void __tcpm_unbackup(struct tcp_metrics_block *tm)		//old but hashed;
{
	us_list_del_init(&tm->tcpm_older.node);
	tm->tcpm_older.tcp_m = NULL;				//Not backuped;						
}

static inline void __tcpm_del_node( struct tcp_metrics_block *tm)
{	
	if(tcp_metric_hashed(tm)){
		__us_hlist_del(&tm->tcpm_node);
		if(__tcpm_backup(tm)){
			__tcpm_unbackup(tm); 
		}
	}
}

static inline void tcp_metric_add_node(struct tcp_metrics_block *tm, struct us_hlist_head *list)
{
	us_hlist_add_head(&tm->tcpm_node, list);
}

static inline void tcp_metric_hashdance(struct net *pnet,struct tcp_metrics_block *tm,u32 hash)
{
	struct us_hlist_head *pchain = &pnet->ipv4.tcp_metrics_hash[hash].chain;
	tcp_metric_add_node(tm,pchain);	
	tm->tcpm_older.tcp_m = NULL;
}

static inline s32 tcpm_check_stamp_old(struct tcp_metrics_block *tm)
{
	return __tcpm_backup(tm);
}

static inline s32 tcpm_check_stamp_timeout(struct tcp_metrics_block *tm)
{
	return time_after(jiffies, tm->tcpm_stamp + TCP_METRICS_TIMEOUT);
}

static inline s32 tcpm_check_stamp_passed(struct tcp_metrics_block *tm)
{
	return (tcpm_check_stamp_old(tm) && tcpm_check_stamp_timeout(tm));
}

static struct tcp_metrics_block *__tcp_get_metrics(const struct inetpeer_addr *addr,
						   struct net *pnet, unsigned int hash)  //smallboy:Fix it later;
{																	
	//int depth = 0;
	//int used = 0;
	struct tcp_metrics_block 	*tm = NULL;
	struct us_hlist_head		*pchain = &pnet->ipv4.tcp_metrics_hash[hash].chain;
#if 1	
	inet_tcpm_for_each(tm ,pchain){
		if(addr_same(&tm->tcpm_addr, addr))	{
			break;
		}
		
		if( tcpm_check_stamp_passed(tm)){
			__tcpm_del_node(tm);
			tcp_metric_push_older_head(pnet,tm);   // Not hashed ;
		}
	}

	return tm;
#else	
	for (tm = net->ipv4.tcp_metrics_hash[hash].chain; tm; tm = tm->tcpm_next) {
		if (addr_same(&tm->tcpm_addr, addr))
			break;
		used += tm->tcpm_ref_cnt ? 1: 0;	
		depth++;
	}
	return tcp_get_encode(tm, depth	,used);	
#endif	
}

//Added by smallboy;
static void inline tcpm_value_init(struct net*pnet,struct tcp_metrics_block *tm)
{
	int	val = 0;
	
	//val |= 1 << TCP_METRIC_RTT;
	//val |= 1 << TCP_METRIC_RTTVAR;
	//val |= 1 << TCP_METRIC_SSTHRESH;
	//val |= 1 << TCP_METRIC_CWND;
	//val |= 1 << TCP_METRIC_REORDERING;
	tm->tcpm_lock = val;

	
	tm->tcpm_vals[TCP_METRICS_ATTR_MTU] = pnet->n_cfg.sysctl_dev_mtu;
	tm->tcpm_vals[TCP_METRICS_ATTR_ADVMSS] = 0;		
	tm->tcpm_vals[TCP_METRICS_ATTR_INITRWND] = pnet->n_cfg.sysctl_tcp_init_cwnd;
	tm->tcpm_vals[TCP_METRICS_ATTR_WINDOW] = 0;


	tm->tcpm_vals[TCP_METRIC_RTT] = 0;
	tm->tcpm_vals[TCP_METRIC_RTTVAR] = 0;
	tm->tcpm_vals[TCP_METRIC_SSTHRESH] = 0;
	tm->tcpm_vals[TCP_METRIC_CWND] = pnet->n_cfg.sysctl_tcp_init_cwnd *1000;
	tm->tcpm_vals[TCP_METRIC_REORDERING] = pnet->n_cfg.sysctl_tcp_reordering;
	
	tm->tcpm_ts = 0;
	tm->tcpm_ts_stamp = 0;

	tm->tcpm_ref_cnt = 0;
	/*
	if (fastopen_clear) {
		tm->tcpm_fastopen.mss = 0;
		tm->tcpm_fastopen.syn_loss = 0;
		tm->tcpm_fastopen.cookie.len = 0;
	}*/
}

void tcp_metric_push_older(struct net*pnet,struct tcp_metrics_block	*tm)
{
	struct netns_ipv4	*ipv4 = &pnet->ipv4;

	tm->tcpm_older.tcp_m = tm;									//backuped here;
	us_list_add_tail(&tm->tcpm_older.node, &ipv4->tcpm_older);	//add into tail;
}

void tcp_metric_push_older_head(struct net*pnet,struct tcp_metrics_block	*tm)
{
	struct netns_ipv4	*ipv4 = &pnet->ipv4;

	tm->tcpm_older.tcp_m = NULL;								// unbackup;
	us_list_add(&tm->tcpm_older.node, &ipv4->tcpm_older);		// add into head;
	US_DEBUG("func:%s,%u tcpm_id:%u\n",__FUNCTION__,__LINE__,tm->tcpm_id);
}

void tcp_metric_push_through_older(struct net *pnet,struct tcp_metrics_block *tm)
{
	tm->tcpm_ref_cnt = 0;
	tcp_metric_push_older(pnet,tm);

	tm->tcpm_stamp = jiffies - TCP_METRICS_TIMEOUT - 1;  //force timeout;
	
	__tcpm_del_node(tm);
	tcp_metric_push_older_head(pnet,tm);
}

void tcp_metric_put(struct net*pnet,struct tcp_metrics_block* tm)
{
	tm->tcpm_ref_cnt = tm->tcpm_ref_cnt> 0 ? (tm->tcpm_ref_cnt-1) : 0;		//smallboy: overlook some bug here maybe ?
	if(tm->tcpm_ref_cnt == 0){
		tm->tcpm_stamp = jiffies ;	 
		//US_DEBUG("func:%s,%u tcpm_id:%u\n",__FUNCTION__,__LINE__,tm->tcpm_id);
		tcp_metric_push_older(pnet,tm);
	}
}

static struct tcp_metrics_block *tcpm_new(struct net *pnet,struct inetpeer_addr *addr,unsigned int hash)
{											//,bool reclaim
#if 1
#define 	US_TCPM_SEARCH_DEPTH	5

	s32 i = 0;
	s32 find_one = 0;
	struct tcp_metrics_block 	*tm = NULL;
	struct tcp_metrics_block 	*lm = NULL;
	struct us_list_head 		*p  = NULL;
	struct us_list_head 		*n  = NULL;
	struct tcp_metric_oblock	*tcpm_ob = NULL;
	struct us_list_head	 *tcpm_older_head = &pnet->ipv4.tcpm_older;

search_again:	
	if(us_list_empty(tcpm_older_head)){
		goto new_alloc;
	}else{	
		us_list_for_each_safe(p , n, tcpm_older_head){
			tcpm_ob = us_list_entry(p, struct tcp_metric_oblock, node);
			lm = container_of(tcpm_ob, struct tcp_metrics_block, tcpm_older);
			if(tcpm_ob->tcp_m == NULL){							//none used and time_out == dead;
				tm = lm ;
				find_one = 1;
				break;
			}
			
			if(tm == NULL || !time_after(lm->tcpm_stamp ,tm->tcpm_stamp))			//find the earlier one;
				tm = lm;
			if(i++ > US_TCPM_SEARCH_DEPTH )		
				break;								//when in older queue but not backuped,so deaded;
		}

		if(i <= US_TCPM_SEARCH_DEPTH){ 	
			if(find_one){							//OK find one;
				us_list_del_init(&tm->tcpm_older.node);
				tm->tcpm_addr = *addr;
				tcpm_value_init(pnet,tm);
				tcp_metric_hashdance(pnet,tm,hash);
				goto return_suc;
			}										//all, new_alloc ,because the older is too short;
		}

		i = 0;
	}

new_alloc:
	lm = us_tcp_metric_alloc(pnet);
	if(lm == NULL){
		if(tm == NULL){								//No useless here;
			return tm;		
		}
													 //useless one,force timeout here;
		tm->tcpm_stamp = tm->tcpm_stamp - TCP_METRICS_TIMEOUT - 1; 
		__tcpm_del_node(tm);
		tcp_metric_push_older_head(pnet,tm);
		//US_DEBUG("func:%s,%u tcpm_id:%u \n",__FUNCTION__,__LINE__,tm->tcpm_id);
		goto search_again;
	}else{
		tm = lm;
		tm->tcpm_addr = *addr;
		tcpm_value_init(pnet,tm);
		tcp_metric_hashdance(pnet,tm,hash);
	}

return_suc:
	return tm;	
#else
	int 	got_it = 0;
	struct tcp_metrics_block *tm;
	if (unlikely(reclaim)) {
		struct tcp_metrics_block *oldest;

		oldest = pnet->ipv4.tcp_metrics_hash[hash].chain;
		for (tm = oldest->tcpm_next; tm;tm = tm->tcpm_next) {
			if (time_before(tm->tcpm_stamp, oldest->tcpm_stamp) && tm->tcpm_ref_cnt == 0){
				oldest = tm;
				got_it = 1;
			}
		}
		tm = oldest;
	} 

	if (got_it == 0) {
		tm = (struct tcp_metrics_block*)us_tcp_metric_alloc();
		if (!tm)
			goto out_unlock;
	}

	tm->tcpm_addr = *addr;
	tcpm_value_init(pnet,tm);
	if (likely(!reclaim)) {
		tm->tcpm_next = pnet->ipv4.tcp_metrics_hash[hash].chain;
		pnet->ipv4.tcp_metrics_hash[hash].chain = tm;
	}

out_unlock:
	return tm;
#endif	
}

static void tcpm_check_stamp(struct net*pnet,struct tcp_metrics_block *tm)
{
	//if (tm && unlikely(time_after(jiffies, tm->tcpm_stamp + TCP_METRICS_TIMEOUT)))
	//	tcpm_value_init(pnet,tm);
	if(tm && tcpm_check_stamp_old(tm)){
		if(tcpm_check_stamp_timeout(tm)){
			//US_DEBUG("func:%s,%u tcpm_id:%u\n",__FUNCTION__,__LINE__,tm->tcpm_id);
			tcpm_value_init(pnet,tm);
		}

		__tcpm_unbackup(tm);  // Hashed;		
	}
}

u32 get_metric_advmss(struct tcp_metrics_block 	*sk_tcpm)
{
	u32 advmss = tcp_metric_get(sk_tcpm ,TCP_METRICS_ATTR_ADVMSS);

	if (!advmss){
		u32 mtu = tcp_metric_get(sk_tcpm ,TCP_METRICS_ATTR_MTU);
		advmss = mtu - 40;
	}
	
	return advmss;
}

struct tcp_metrics_block *tcp_get_metrics(struct sock *sk, bool create)
{	
	struct tcp_metrics_block *tm;
	struct inetpeer_addr addr;
	unsigned int hash;
	struct net *net;
	//bool reclaim;

	addr.family = sk->sk_family;
	switch (addr.family) {
	case AF_INET:
		addr.addr.a4 = inet_sk(sk)->inet_daddr;
		hash = (__force unsigned int) addr.addr.a4;
		break;
	//case AF_INET6:
	//	*(struct in6_addr *)addr.addr.a6 = inet6_sk(sk)->daddr;
	//	hash = ipv6_addr_hash(&inet6_sk(sk)->daddr);
	//	break;
	default:
		return NULL;
	}

	//net = dev_net(dst->dev);
	net = sock_net(sk);
	hash = hash_32(hash, net->ipv4.tcp_metrics_hash_log);
	tm = __tcp_get_metrics(&addr, net, hash);
	/*
	reclaim = false;
	if (tm == TCP_METRICS_RECLAIM_PTR) {
		reclaim = true;
		tm = NULL;
	}*/
	if (!tm && create){
		tm = tcpm_new(net, &addr,hash);  //, hash, reclaim
	}else{
		tcpm_check_stamp(net,tm);  // reinit or inherit the value before;
	}
	
	return tm;
}


/* VJ's idea. Save last timestamp seen from this destination and hold
 * it at least for normal timewait interval to use for duplicate
 * segment detection in subsequent connections, before they enter
 * synchronized state.
 */
bool tcp_remember_stamp(struct sock *sk)
{
	bool ret = false;
#if 1
	struct tcp_metrics_block *tm = sk->sk_tcpm;
	struct tcp_sock *tp = tcp_sk(sk);
	
	if ((s32)(tm->tcpm_ts - tp->rx_opt.ts_recent) <= 0 ||
			((u32)us_get_seconds() - tm->tcpm_ts_stamp > TCP_PAWS_MSL &&
					tm->tcpm_ts_stamp <= (u32)tp->rx_opt.ts_recent_stamp)) {
		tm->tcpm_ts_stamp = (u32)tp->rx_opt.ts_recent_stamp;
		tm->tcpm_ts = tp->rx_opt.ts_recent;
	}

	ret = true;

	return ret;
#else
	struct tcp_metrics_block *tm;	
	tm = tcp_get_metrics(sk, true);
	if (tm) {
		struct tcp_sock *tp = tcp_sk(sk);
		if ((s32)(tm->tcpm_ts - tp->rx_opt.ts_recent) <= 0 ||
		   		((u32)us_get_seconds() - tm->tcpm_ts_stamp > TCP_PAWS_MSL &&
		    		tm->tcpm_ts_stamp <= (u32)tp->rx_opt.ts_recent_stamp)) {
			tm->tcpm_ts_stamp = (u32)tp->rx_opt.ts_recent_stamp;
			tm->tcpm_ts = tp->rx_opt.ts_recent;
		}
		ret = true;
	}

	return ret;
#endif	
}


void tcp_fetch_timewait_stamp(struct sock *sk)
{
	u32 new_one = 0;
	struct tcp_metrics_block *tm;

	//rcu_read_lock();
	tm = sk->sk_tcpm;
	if(tm == NULL) {
		new_one = 1;
		tm = tcp_get_metrics(sk, true);
	}
	//tm = tcp_get_metrics(sk, true);
	if (tm) {
		struct tcp_sock *tp = tcp_sk(sk);

		if (((u32)us_get_seconds() - tm->tcpm_ts_stamp <= TCP_PAWS_MSL)
			&& (tm->tcpm_ts_stamp != 0)) {
			tp->rx_opt.ts_recent_stamp = tm->tcpm_ts_stamp;     //smallboy :Why ?????
			tp->rx_opt.ts_recent = tm->tcpm_ts;
		}
		if(new_one)
			sk_set_tcpm(sk,tm);	
	}
	//rcu_read_unlock();
}


static struct tcp_metrics_block *__tcp_get_metrics_tw(struct inet_timewait_sock *tw)
{
	//struct inet6_timewait_sock *tw6;
	struct tcp_metrics_block *tm;
	struct inetpeer_addr addr;
	unsigned int hash;
	struct net *pnet;

	addr.family = tw->tw_family;
	switch (addr.family) {
	case AF_INET:
		addr.addr.a4 = tw->tw_daddr;
		hash = (__force unsigned int) addr.addr.a4;
		break;
	//case AF_INET6:
	//	tw6 = inet6_twsk((struct sock *)tw);
	//	*(struct in6_addr *)addr.addr.a6 = tw6->tw_v6_daddr;
	//	hash = ipv6_addr_hash(&tw6->tw_v6_daddr);
	//	break;
	default:
		return NULL;
	}

	pnet = twsk_net(tw);
	hash = hash_32(hash, pnet->ipv4.tcp_metrics_hash_log);
	tm	= __tcp_get_metrics(&addr, pnet, hash);	
	return tm;
	
	//for (tm = rcu_dereference(net->ipv4.tcp_metrics_hash[hash].chain); tm;
	//    tm = rcu_dereference(tm->tcpm_next)) {
	//	if (addr_same(&tm->tcpm_addr, &addr))
	//		break;
	//}	

	//for (tm = (net->ipv4.tcp_metrics_hash[hash].chain); tm;
	//   tm = (tm->tcpm_next)) {
	//	if (addr_same(&tm->tcpm_addr, &addr))
	//		break;
	//}
	//return tm;
}


bool tcp_tw_remember_stamp(struct inet_timewait_sock *tw)
{
	struct tcp_metrics_block *tm;
	bool ret = false;

	//rcu_read_lock();
	tm = __tcp_get_metrics_tw(tw);
	if (tm) {	
		const struct tcp_timewait_sock *tcptw;
		struct sock *sk = (struct sock *) tw;

		tcptw = tcp_twsk(sk);
		if ((s32)(tm->tcpm_ts - tcptw->tw_ts_recent) <= 0 ||
		    ((u32)us_get_seconds() - tm->tcpm_ts_stamp > TCP_PAWS_MSL &&
		     tm->tcpm_ts_stamp <= (u32)tcptw->tw_ts_recent_stamp)) {
			tm->tcpm_ts_stamp = (u32)tcptw->tw_ts_recent_stamp;
			tm->tcpm_ts	   = tcptw->tw_ts_recent;
		}
		ret = true;
	}
	//rcu_read_unlock();

	return ret;
}



u32 tcp_metric_get(const struct tcp_metrics_block *tm,enum tcp_metric_index idx)
{
	return tm->tcpm_vals[idx];
}

s32 net_tcp_metrics_init(struct net* pnet,s32 delta)
{
	s32 ret = 0;
	//u32 lcore = US_GET_LCORE();
	//u32 socket = US_GET_SOCKET(lcore);
	
	ret = us_thash_init(pnet ,delta);
	US_INIT_LIST_HEAD(&pnet->ipv4.tcpm_older);
	
	return ret;
}

bool tcp_metric_locked(struct tcp_metrics_block *tm,  enum tcp_metric_index idx)
{
	return tm->tcpm_lock & (1 << idx);
}

u32 tcp_metric_get_jiffies(struct tcp_metrics_block *tm,enum tcp_metric_index idx)
{
	return msecs_to_jiffies(tm->tcpm_vals[idx]);
}


/* Initialize metrics on socket. */
void tcp_init_metrics(struct sock *sk)
{
	//struct dst_entry *dst = __sk_dst_get(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_metrics_block *tm;
	u32 val;
#if 1 
	tm = sk->sk_tcpm;							//tcp_finish_connect  //tcp_rcv_state_process
#else
	//if (dst == NULL)
	//	goto reset;

	//dst_confirm(dst);
	//rcu_read_lock();
	tm = tcp_get_metrics(sk, true);						
	if (!tm) {											
		//rcu_read_unlock();
		goto reset;
	}

	if(tm)
	US_DEBUG("func:%s,%u rtt:%u rttvar:%u SSTHRESH:%u CWND:%u REORDER:%u "
			 "tcpm->tcpm_ts_stamp:%u ts:%u	tcpm_id:%u\n"
			,__FUNCTION__,__LINE__
			,tcp_metric_get_jiffies(tm, TCP_METRIC_RTT)
			,tcp_metric_get_jiffies(tm, TCP_METRIC_RTTVAR)
			,tcp_metric_get(tm, TCP_METRIC_SSTHRESH)
			,tcp_metric_get(tm, TCP_METRIC_CWND)
			,tcp_metric_get(tm, TCP_METRIC_REORDERING)
			,tm->tcpm_ts_stamp
			,tm->tcpm_ts
			,tm->tcpm_id);
#endif	
	if (tcp_metric_locked(tm, TCP_METRIC_CWND))
		tp->snd_cwnd_clamp = tcp_metric_get(tm, TCP_METRIC_CWND);

	val = tcp_metric_get(tm, TCP_METRIC_SSTHRESH);
	if (val) {
		tp->snd_ssthresh = val;
		if (tp->snd_ssthresh > tp->snd_cwnd_clamp)
			tp->snd_ssthresh = tp->snd_cwnd_clamp;
	} else {
		/* ssthresh may have been reduced unnecessarily during.
		 * 3WHS. Restore it back to its initial default.
		 */
		tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	}
	
	val = tcp_metric_get(tm, TCP_METRIC_REORDERING);
	if (val && tp->reordering != val) {
		tcp_disable_fack(tp);
		tcp_disable_early_retrans(tp);
		tp->reordering = val;
	}

	val = tcp_metric_get(tm, TCP_METRIC_RTT);
	if (val == 0 || tp->srtt == 0) {
		//rcu_read_unlock();
		goto reset;
	}
	/* Initial rtt is determined from SYN,SYN-ACK.
	 * The segment is small and rtt may appear much
	 * less than real one. Use per-dst memory
	 * to make it more realistic.
	 *
	 * A bit of theory. RTT is time passed after "normal" sized packet
	 * is sent until it is ACKed. In normal circumstances sending small
	 * packets force peer to delay ACKs and calculation is correct too.
	 * The algorithm is adaptive and, provided we follow specs, it
	 * NEVER underestimate RTT. BUT! If peer tries to make some clever
	 * tricks sort of "quick acks" for time long enough to decrease RTT
	 * to low value, and then abruptly stops to do it and starts to delay
	 * ACKs, wait for troubles.
	 */
	val = msecs_to_jiffies(val);
	if (val > tp->srtt) {
		tp->srtt = val;
		tp->rtt_seq = tp->snd_nxt;
	}
	
	val = tcp_metric_get_jiffies(tm, TCP_METRIC_RTTVAR);
	if (val > tp->mdev) {
		tp->mdev = val;
		tp->mdev_max = tp->rttvar = max(tp->mdev, tcp_rto_min(sk));
	}
	//rcu_read_unlock();

	tcp_set_rto(sk);
reset:
	if (tp->srtt == 0) {
		/* RFC6298: 5.7 We've failed to get a valid RTT sample from
		 * 3WHS. This is most likely due to retransmission,
		 * including spurious one. Reset the RTO back to 3secs
		 * from the more aggressive 1sec to avoid more spurious
		 * retransmission.
		 */
		tp->mdev = tp->mdev_max = tp->rttvar = TCP_TIMEOUT_FALLBACK;
		inet_csk(sk)->icsk_rto = TCP_TIMEOUT_FALLBACK;
	}
	/* Cut cwnd down to 1 per RFC5681 if SYN or SYN-ACK has been
	 * retransmitted. In light of RFC6298 more aggressive 1sec
	 * initRTO, we only reset cwnd when more than 1 SYN/SYN-ACK
	 * retransmission has occurred.
	 */
	if (tp->total_retrans > 1)
		tp->snd_cwnd = 1;
	else
		tp->snd_cwnd = tcp_init_cwnd(tp, tm);  //dst;
	tp->snd_cwnd_stamp = tcp_time_stamp;	
}

struct tcp_metrics_block *__tcp_get_metrics_req(struct request_sock *req,struct net*pnet)
{	
	struct tcp_metrics_block *tm = NULL;
	struct inetpeer_addr addr;
	unsigned int hash;
	//struct net  *pnet; 

	addr.family = req->rsk_ops->family;
	switch (addr.family) {
	case AF_INET:
		addr.addr.a4 = inet_rsk(req)->rmt_addr;
		hash = ( unsigned int) addr.addr.a4;
		break;
	/*	
	case AF_INET6:
		*(struct in6_addr *)addr.addr.a6 = inet6_rsk(req)->rmt_addr;
		hash = ipv6_addr_hash(&inet6_rsk(req)->rmt_addr);
		break;*/
	default:
		return NULL;
	}

	//pnet  = US_PER_LCORE(init_net);
	//net  = (struct net *)req->sk;		//when there is no sk ,we use it as struct net *; 

	hash = hash_32(hash, pnet->ipv4.tcp_metrics_hash_log);
	tm = __tcp_get_metrics(&addr, pnet, hash);
	if(tm)
		tcpm_check_stamp(pnet,tm);
	
	return tm;
}

struct tcp_metrics_block *tcp_get_metrics_req(struct request_sock *req,struct net*pnet,int create)
{	
	struct tcp_metrics_block *tm = NULL;
	struct inetpeer_addr addr;
	unsigned int hash;
	//struct net  *pnet; 

	addr.family = req->rsk_ops->family;
	switch (addr.family) {
	case AF_INET:
		addr.addr.a4 = inet_rsk(req)->rmt_addr;
		hash = ( unsigned int) addr.addr.a4;
		break;
	/*	
	case AF_INET6:
		*(struct in6_addr *)addr.addr.a6 = inet6_rsk(req)->rmt_addr;
		hash = ipv6_addr_hash(&inet6_rsk(req)->rmt_addr);
		break;*/
	default:
		return NULL;
	}

	//pnet  = US_PER_LCORE(init_net);
	//net  = (struct net *)req->sk;		//when there is no sk ,we use it as struct net *; 

	hash = hash_32(hash, pnet->ipv4.tcp_metrics_hash_log);
	tm = __tcp_get_metrics(&addr, pnet, hash);
	if(!tm && create){
		tm = tcpm_new(pnet, &addr,hash);  //, hash, reclaim
	}else{
		tcpm_check_stamp(pnet,tm);  // reinit or inherit the value before;
	}
	
	return tm;
}


bool tcp_peer_is_proven(struct request_sock *req,struct tcp_metrics_block *tm, bool paws_check)
{	
	//struct tcp_metrics_block *tm;
	bool ret;

	//if (!dst)				//smallboy: Attention ???
	//	return false;

	//rcu_read_lock();
	//tm = __tcp_get_metrics_req(req, dst);
	if (paws_check) {
		if (tm &&
		    (u32)us_get_seconds() - tm->tcpm_ts_stamp < TCP_PAWS_MSL &&
		    (s32)(tm->tcpm_ts - req->ts_recent) > TCP_PAWS_WINDOW)
			ret = false;
		else
			ret = true;
	} else {
		if (tm && tcp_metric_get(tm, TCP_METRIC_RTT) && tm->tcpm_ts_stamp)
			ret = true;
		else
			ret = false;
	}
	//rcu_read_unlock();

	return ret;
}

static void tcp_metric_set(struct tcp_metrics_block *tm,
			   enum tcp_metric_index idx, u32 val)
{
	tm->tcpm_vals[idx] = val;
}

static void tcp_metric_set_msecs(struct tcp_metrics_block *tm,
				 enum tcp_metric_index idx,u32 val)
{
	tm->tcpm_vals[idx] = jiffies_to_msecs(val);
}

/* Save metrics learned by this TCP session.  This function is called
 * only, when TCP finishes successfully i.e. when it enters TIME-WAIT
 * or goes from LAST-ACK to CLOSE.
 */
void tcp_update_metrics(struct sock *sk)
{	
	const struct inet_connection_sock *icsk = inet_csk(sk);
	//struct dst_entry *dst = __sk_dst_get(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *pnet = sock_net(sk);
	struct tcp_metrics_block *tm = sk->sk_tcpm;
	unsigned long rtt;
	u32 val;
	int m;

	if (pnet->n_cfg.sysctl_tcp_nometrics_save || tm == NULL ){  //|| !dst
	US_DEBUG("func:%s,%u nometric:%u tm:%p \n",__FUNCTION__,__LINE__
						,pnet->n_cfg.sysctl_tcp_nometrics_save
						,tm);	
		return;											
	}
	//if (dst->flags & DST_HOST)
	//	dst_confirm(dst);

#if 1
	if (icsk->icsk_backoff || !tp->srtt) {
		if(!tcp_metric_locked(tm, TCP_METRIC_RTT)){
			tcp_metric_set(tm, TCP_METRIC_RTT, 0);
		}
		goto out_unlock;
	}
#else
	//rcu_read_lock();
	if (icsk->icsk_backoff || !tp->srtt) {
		/* This session failed to estimate rtt. Why?
		 * Probably, no packets returned in time.  Reset our
		 * results.
		 */
		tm = tcp_get_metrics(sk, false);  //sk, dst, false
		if (tm && !tcp_metric_locked(tm, TCP_METRIC_RTT))
			tcp_metric_set(tm, TCP_METRIC_RTT, 0);
		goto out_unlock;
	} else
		tm = tcp_get_metrics(sk, true);  //sk, dst, true

	if (!tm)
		goto out_unlock;
#endif	

	rtt = tcp_metric_get_jiffies(tm, TCP_METRIC_RTT);
	m = rtt - tp->srtt;

	/* If newly calculated rtt larger than stored one, store new
	 * one. Otherwise, use EWMA. Remember, rtt overestimation is
	 * always better than underestimation.
	 */
	if (!tcp_metric_locked(tm, TCP_METRIC_RTT)) {
		if (m <= 0)
			rtt = tp->srtt;
		else
			rtt -= (m >> 3);
		tcp_metric_set_msecs(tm, TCP_METRIC_RTT, rtt);
	}

	if (!tcp_metric_locked(tm, TCP_METRIC_RTTVAR)) {
		unsigned long var;

		if (m < 0)
			m = -m;

		/* Scale deviation to rttvar fixed point */
		m >>= 1;
		if (m < tp->mdev)
			m = tp->mdev;

		var = tcp_metric_get_jiffies(tm, TCP_METRIC_RTTVAR);
		if (m >= var)
			var = m;
		else
			var -= (var - m) >> 2;

		tcp_metric_set_msecs(tm, TCP_METRIC_RTTVAR, var);
	}

	if (tcp_in_initial_slowstart(tp)) {
		/* Slow start still did not finish. */
		if (!tcp_metric_locked(tm, TCP_METRIC_SSTHRESH)) {
			val = tcp_metric_get(tm, TCP_METRIC_SSTHRESH);
			if (val && (tp->snd_cwnd >> 1) > val){
				tcp_metric_set(tm, TCP_METRIC_SSTHRESH, tp->snd_cwnd >> 1);
			}
		}
		if (!tcp_metric_locked(tm, TCP_METRIC_CWND)) {
			val = tcp_metric_get(tm, TCP_METRIC_CWND);
			if (tp->snd_cwnd > val) {	
				tcp_metric_set(tm, TCP_METRIC_CWND, tp->snd_cwnd);
			}
		}
	} else if (tp->snd_cwnd > tp->snd_ssthresh 
			&& icsk->icsk_ca_state == TCP_CA_Open) {
		/* Cong. avoidance phase, cwnd is reliable. */
		if (!tcp_metric_locked(tm, TCP_METRIC_SSTHRESH)){
			tcp_metric_set(tm, TCP_METRIC_SSTHRESH, max(tp->snd_cwnd >> 1, tp->snd_ssthresh));
		}
		if (!tcp_metric_locked(tm, TCP_METRIC_CWND)) {
			val = tcp_metric_get(tm, TCP_METRIC_CWND);
			tcp_metric_set(tm, TCP_METRIC_CWND, (val + tp->snd_cwnd) >> 1);
		}
	} else {
		/* Else slow start did not finish, cwnd is non-sense,
		 * ssthresh may be also invalid.
		 */
		if (!tcp_metric_locked(tm, TCP_METRIC_CWND)) {
			val = tcp_metric_get(tm, TCP_METRIC_CWND);
			tcp_metric_set(tm, TCP_METRIC_CWND, (val + tp->snd_ssthresh) >> 1);
		}
		if (!tcp_metric_locked(tm, TCP_METRIC_SSTHRESH)) {
			val = tcp_metric_get(tm, TCP_METRIC_SSTHRESH);
			if (val && tp->snd_ssthresh > val){
				tcp_metric_set(tm, TCP_METRIC_SSTHRESH, tp->snd_ssthresh);
			}
		}
		if (!tcp_metric_locked(tm, TCP_METRIC_REORDERING)) {
			val = tcp_metric_get(tm, TCP_METRIC_REORDERING);
			if (val < tp->reordering && tp->reordering != pnet->n_cfg.sysctl_tcp_reordering){
				tcp_metric_set(tm, TCP_METRIC_REORDERING,tp->reordering);
			}
		}
	}
	
	tm->tcpm_stamp = jiffies;

/*	
	US_DEBUG("func:%s,%u rtt:%u rttvar:%u SSTHRESH:%u CWND:%u REORDER:%u tcpm_id:%u"
			 "tcpm_ts_stamp:%u ts:%u \n"	
				,__FUNCTION__,__LINE__
				,tcp_metric_get_jiffies(tm, TCP_METRIC_RTT)
				,tcp_metric_get_jiffies(tm, TCP_METRIC_RTTVAR)
				,tcp_metric_get(tm, TCP_METRIC_SSTHRESH)
				,tcp_metric_get(tm, TCP_METRIC_CWND)
				,tcp_metric_get(tm, TCP_METRIC_REORDERING)
				,tm->tcpm_id
				,tm->tcpm_ts_stamp
				,tm->tcpm_ts);
*/				
out_unlock:
	;//rcu_read_unlock();

}




