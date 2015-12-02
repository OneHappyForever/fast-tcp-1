/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			tcp_metrics.h
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/


#ifndef _US_TCP_METRICS_H
#define _US_TCP_METRICS_H

#include "types.h"

struct net;
struct sock;
struct request_sock;
struct inet_timewait_sock;


#if 0
enum tcp_metric_index {
	TCP_METRIC_RTT,
	TCP_METRIC_RTTVAR,
	TCP_METRIC_SSTHRESH,
	TCP_METRIC_CWND,
	TCP_METRIC_REORDERING,

	__TCP_METRIC_MAX,	//always last;
};

#define TCP_METRIC_MAX	(__TCP_METRIC_MAX - 1)


enum {
	TCP_METRICS_ATTR_UNSPEC,
	TCP_METRICS_ATTR_ADDR_IPV4,		// u32 */
	TCP_METRICS_ATTR_ADDR_IPV6,		/* binary */
	TCP_METRICS_ATTR_AGE,			/* msecs */
	TCP_METRICS_ATTR_TW_TSVAL,		/* u32, raw, rcv tsval */
	TCP_METRICS_ATTR_TW_TS_STAMP,		/* s32, sec age */
	TCP_METRICS_ATTR_VALS,			/* nested +1, u32 */
	TCP_METRICS_ATTR_FOPEN_MSS,		/* u16 */
	TCP_METRICS_ATTR_FOPEN_SYN_DROPS,	/* u16, count of drops */
	TCP_METRICS_ATTR_FOPEN_SYN_DROP_TS,	/* msecs age */
	TCP_METRICS_ATTR_FOPEN_COOKIE,		/* binary */

	__TCP_METRICS_ATTR_MAX,
};

#define TCP_METRICS_ATTR_MAX	(__TCP_METRICS_ATTR_MAX - 1)

#endif

//smallboy: some item is redundant;some item is new ;
enum tcp_metric_index {
	TCP_METRIC_RTT			= 0,
	TCP_METRIC_RTTVAR,
	TCP_METRIC_SSTHRESH,
	TCP_METRIC_CWND,
	TCP_METRIC_REORDERING,
	// From the TCP_METRICS_ATTR_
	TCP_METRICS_ATTR_UNSPEC,
	TCP_METRICS_ATTR_ADDR_IPV4,		// u32 
	TCP_METRICS_ATTR_ADDR_IPV6,		// binary 
	TCP_METRICS_ATTR_AGE,			// msecs 
	TCP_METRICS_ATTR_TW_TSVAL,		// u32, raw, rcv tsval 
	TCP_METRICS_ATTR_TW_TS_STAMP,	// s32, sec age 
	TCP_METRICS_ATTR_VALS,			// nested +1, u32 
	TCP_METRICS_ATTR_FOPEN_MSS,		// u16 
	TCP_METRICS_ATTR_FOPEN_SYN_DROPS,	// u16, count of drops 
	TCP_METRICS_ATTR_FOPEN_SYN_DROP_TS,	// msecs age 
	TCP_METRICS_ATTR_FOPEN_COOKIE,		// binary 
	// New item Added;
	TCP_METRICS_ATTR_ADVMSS,
	TCP_METRICS_ATTR_MTU,
	TCP_METRICS_ATTR_WINDOW,
	TCP_METRICS_ATTR_RTO_MIN,
	TCP_METRICS_ATTR_INITRWND,
	__TCP_METRICS_ATTR_MAX,
};

#define TCP_METRIC_MAX	(__TCP_METRICS_ATTR_MAX - 1)



#define TCP_FASTOPEN_COOKIE_MIN	4	/* Min Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_MAX	16	/* Max Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_SIZE 8	/* the size employed by this impl. */

// TCP Fast Open Cookie as stored in memory 
struct tcp_fastopen_cookie {
	s8	len;
	u8	val[TCP_FASTOPEN_COOKIE_MAX];
};

struct tcp_fastopen_metrics {
	u16	mss;
	u16	syn_loss:10;				/* Recurring Fast Open SYN losses */
	unsigned long	last_syn_loss;	/* Last Fast Open SYN loss */
	struct	tcp_fastopen_cookie	cookie;
};

struct inetpeer_addr_base {					//smallboy: No inet_peer anymore;
	union {
		__be32			a4;
		__be32			a6[4];
	};
};

struct inetpeer_addr {
	struct inetpeer_addr_base	addr;
	__u16						family;
};

struct tcp_metric_oblock{
	struct		us_list_head	node;
	struct tcp_metrics_block 	*tcp_m;
};

struct tcp_metrics_block {
	//struct tcp_metrics_block 	*tcpm_next;		//smallboy: we delete the rcu here;
	struct us_hlist_node		tcpm_node;
	struct tcp_metric_oblock	tcpm_older;
	struct inetpeer_addr		tcpm_addr;
	unsigned long				tcpm_stamp;		//time_stamp when tcpm is freed;
	u32							tcpm_ts;		//time_stamp we recv from remote;
	u32							tcpm_ts_stamp;  //time when we recv pkts;
	u32							tcpm_lock;
	u32							tcpm_ref_cnt;
	u32							tcpm_vals[TCP_METRIC_MAX + 1];
	struct tcp_fastopen_metrics	tcpm_fastopen;
	u32							tcpm_id;
	//struct rcu_head			rcu_head;
};

struct tcpm_hash_bucket {
	//struct tcp_metrics_block *chain;
	struct us_hlist_head	chain;
};

#define inet_tcpm_for_each(tcpm, head) \
	us_hlist_for_each_entry(tcpm, head, tcpm_node)


extern void tcp_init_metrics(struct sock *sk);
extern void tcp_update_metrics(struct sock *sk);
extern bool tcp_tw_remember_stamp(struct inet_timewait_sock *tw);
extern bool tcp_peer_is_proven(struct request_sock *req,struct tcp_metrics_block *tm, bool paws_check);

extern struct tcp_metrics_block *__tcp_get_metrics_req(struct request_sock *req,struct net *pnet);
extern struct tcp_metrics_block *tcp_get_metrics_req(struct request_sock *req,struct net*pnet,int create);
extern struct tcp_metrics_block *tcp_get_metrics(struct sock *sk, bool create);

extern u32 tcp_metric_get(const struct tcp_metrics_block *tm,enum tcp_metric_index idx);
extern s32 net_tcp_metrics_init(struct net* pnet,s32 delta);
extern u32 get_metric_advmss(struct tcp_metrics_block 	*sk_tcpm);
extern bool tcp_remember_stamp(struct sock *sk);
extern bool tcp_metric_locked(struct tcp_metrics_block *tm,  enum tcp_metric_index idx);
extern void tcp_fetch_timewait_stamp(struct sock *sk);
extern void tcp_metric_push_through_older(struct net *pnet,struct tcp_metrics_block *tm);
extern void tcp_metric_put(struct net*pnet,struct tcp_metrics_block* tm);
extern void tcp_metric_push_older_head(struct net*pnet,struct tcp_metrics_block	*tm);


#endif
