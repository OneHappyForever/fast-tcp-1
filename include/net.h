/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			net.h
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/  


#ifndef _US_NET_H
#define _US_NET_H

#include "snmp.h"
#include "list.h"
#include "atomic.h"
#include "us_memobj_slab.h"

struct sk_buff;
struct sock;
struct tcpm_hash_bucket;

#define NR_FILE  	8192	/* this can well be larger on a larger system */
#define SOMAXCONN	128

struct netns_ipv4 {
		struct sock 			  **icmp_sk;
		struct sock				   *tcp_sock;
		struct sk_buff			   *tcp_skb[US_MAX_PKT_BURST_OUT*2];
		int							tcp_skb_index;
		//struct inet_peer_base	   *peers;
		struct tcpm_hash_bucket    *tcp_metrics_hash;
		unsigned int				tcp_metrics_hash_log;
		int							tcp_metrics_num;
		struct us_list_head			tcpm_older;
		int				(*pre_route_in)(struct sk_buff*skb);
		int				(*aft_route_out)(struct sk_buff*skb);
		//atomic_t					memory_pressure;		//items below is located at the struct proto;
		//atomic_long_t				memory_allocated;		
		//atomic_long_t				orphan_count;
		//atomic_long_t				sockets_allocated;
		
		int sysctl_icmp_echo_ignore_all;
		int sysctl_icmp_echo_ignore_broadcasts;
		int sysctl_icmp_ignore_bogus_error_responses;
		int sysctl_icmp_ratelimit;
		int sysctl_icmp_ratemask;
		int sysctl_icmp_errors_use_inbound_ifaddr;		
		
};

struct netns_mib {
	DEFINE_SNMP_STAT(struct tcp_mib, tcp_statistics);
	DEFINE_SNMP_STAT(struct ipstats_mib, ip_statistics);
	DEFINE_SNMP_STAT(struct linux_mib, net_statistics);
	DEFINE_SNMP_STAT(struct udp_mib, udp_statistics);
	DEFINE_SNMP_STAT(struct udp_mib, udplite_statistics);
	DEFINE_SNMP_STAT(struct icmp_mib, icmp_statistics);
	DEFINE_SNMP_STAT_ATOMIC(struct icmpmsg_mib, icmpmsg_statistics);

#ifdef CONFIG_IPV6
	struct proc_dir_entry *proc_net_devsnmp6;
	DEFINE_SNMP_STAT(struct udp_mib, udp_stats_in6);
	DEFINE_SNMP_STAT(struct udp_mib, udplite_stats_in6);
	DEFINE_SNMP_STAT(struct ipstats_mib, ipv6_statistics);
	DEFINE_SNMP_STAT(struct icmpv6_mib, icmpv6_statistics);
	DEFINE_SNMP_STAT_ATOMIC(struct icmpv6msg_mib, icmpv6msg_statistics);
#endif
//#ifdef CONFIG_XFRM_STATISTICS
//	DEFINE_SNMP_STAT(struct linux_xfrm_mib, xfrm_statistics);
//#endif
};

typedef struct __tcp_ip_stack_config {
	int sysctl_tcp_timestamps;					// used;OK;
    int sysctl_tcp_window_scaling;				// used;OK;
    int sysctl_tcp_tw_reuse;					// used;OK;
    int sysctl_tw_recycle;						// used;OK;
	int sysctl_max_tw_buckets;					// used;OK;

	int sysctl_tcp_sack;						// used;
	int sysctl_tcp_fin_timeout;					// used;
	int sysctl_tcp_keepalive_time;				// used;
	int sysctl_tcp_keepalive_probes;			// used;	
	int sysctl_tcp_keepalive_intvl;				// used;
	
	int sysctl_tcp_syn_retries;					// used;
	int sysctl_tcp_synack_retries;				// used;	
	int sysctl_tcp_retries1;					// used;
	int sysctl_tcp_retries2;					// used;	
	int sysctl_tcp_orphan_retries;				// used;
	
	int sysctl_tcp_syncookies;					// used; Not ok;
	
	int sysctl_tcp_retrans_collapse;			// Not used;	
	int sysctl_tcp_stdurg;						// Not used;
		
	int sysctl_tcp_rfc1337;						// used; == 0;
	int sysctl_tcp_abort_on_overflow;			// used; == 0;  delete ?
	
	int sysctl_tcp_max_orphans;					// used;OK; 
	int sysctl_tcp_fack;						// used; == 1;
	
	int sysctl_tcp_reordering;					// used; == 3;
	int sysctl_tcp_ecn;							// used; Not ok;
	int sysctl_tcp_dsack;						// used; == 1;
	
	int sysctl_tcp_mem [3];						// Not used;
	int sysctl_tcp_wmem[3];						// used; OK; 
	int sysctl_tcp_rmem[3];						// used; OK;
	
	int sysctl_rmem_max ;						// used;
	int sysctl_wmem_max ;						// used;
	
	int sysctl_wmem_default;					// used;OK;__read_mostly = SK_WMEM_MAX
	int sysctl_rmem_default;					// used;OK;__read_mostly = SK_WMEM_MAX
	
	int sysctl_tcp_app_win;						// used; ??
	int sysctl_tcp_adv_win_scale;				// Not used;
	int sysctl_tcp_frto;						// used; OK;						
	int sysctl_tcp_frto_response;				// Not used; ????
	
	int sysctl_tcp_low_latency;					// Not used;
	int sysctl_tcp_dma_copybreak;				// Not used;
	
	int sysctl_tcp_nometrics_save;				// used; OK; == 1;
	int sysctl_tcp_moderate_rcvbuf;				// used; OK; == 0;
	
	int sysctl_tcp_tso_win_divisor;				// used; OK;	
	int sysctl_tcp_min_tso_segs ;				// used; OK; == 2;
	
	int sysctl_tcp_abc;							// Not used;
	int sysctl_tcp_mtu_probing;					// used; OK; == 0;
	int sysctl_tcp_base_mss;					// used; OK; 512;
	
	int sysctl_tcp_workaround_signed_windows;	// used; OK; == 0;
	int sysctl_tcp_slow_start_after_idle;		// used; OK; == 1;
	int sysctl_tcp_max_ssthresh;				// used; OK; == 0;
	
	int sysctl_tcp_cookie_size;					// Not used; 
	int sysctl_tcp_thin_linear_timeouts;		// used; OK ; == 0;	
	int sysctl_tcp_thin_dupack;					// Not used; Not OK;
	unsigned int sysctl_max_syn_backlog;		// used; OK;
	int sysctl_somaxconn;						// used; OK;
	int sysctl_tcp_early_retrans;				// used; OK;
	int sysctl_tcp_fastopen;					// used; NOt ok; == 0;

	int sysctl_tcp_challenge_ack_limit;			// Used; OK;
	long tcp_memory_allocated;					// Not used;
	int tcp_sockets_allocated;					// Not used;
	int tcp_memory_pressure;					// Not used;
	//////////////////SMALLBOY////////////////
	unsigned short sysctl_skb_limit_rcv;		// used; OK;
	unsigned short sysctl_skb_limit_snd;		// used; OK;
	int sysclt_no_pmtu_disc;					// used; Not ok; == 0 ;	
	int sysctl_tcp_init_cwnd;					// used; OK;
	int sysctl_base_mtu;						// Not used;		
	int sysctl_dev_mtu;							// Used; 1500;
	int sysctl_ip_default_ttl;					// used;OK;
	int sysctl_ip_nonlocal_bind;				// used;partial;
	int sysctl_nr_file;							// not used;
	unsigned long	max_schedule_timeout;		// used; OK;MAX_SCHEDULE_TIMEOUT;
	struct tcp_congestion_ops 	*sysctl_tcp_ca; // used; OK;
	unsigned short 	sysctl_portrange_low;		// used; OK;
	unsigned short  sysctl_portrange_high;		// used; OK;	
	unsigned long 	sysctl_local_reserved_ports[65536/8];  //used; Not OK;
}tcp_ip_stack_config;


#define  TCP_MAX_STATES_DEF		(11)		//The same with TCP_MAX_STATES - 1;
typedef struct __us_session_stat{
	u32		sessions[TCP_MAX_STATES_DEF + 1];  //smallboy:ugly here;
}us_session_stat;


struct __us_nic_port;

struct net {
	short				port_id;
	short				send_queue_id;
	struct __us_nic_port *port;
	int 				count;
	int					use_count;		// To track references we  destroy on demand
	unsigned int		inet_ehash_secret;
	struct netns_mib	mib;
	struct netns_ipv4	ipv4;
	tcp_ip_stack_config n_cfg;
	us_session_stat		session_info;

	struct us_netio_evb	*evb_p;
	
	us_mempool			*sock_pool;
	us_mempool			*socket_pool;
	us_mempool			*sk_tw_pool;
	us_mempool			*sk_req_pool;
	us_mempool			*tcpm_pool;
	us_mempool			*mbuf_s_pool;
	
	us_objslab			*req_slab;
	us_objslab			*tw_slab;
	us_objslab			*socket_slab;
	struct rte_mbuf		*mmbuf[US_MAX_PKT_BURST_OUT];
};

/*
 * Transmit return codes: transmit return codes originate from three different
 * namespaces:
 *
 * - qdisc return codes
 * - driver transmit return codes
 * - errno values
 *
 * Drivers are allowed to return any one of those in their hard_start_xmit()
 * function. Real network devices commonly used with qdiscs should only return
 * the driver transmit return codes though - when qdiscs are used, the actual
 * transmission happens asynchronously, so the value is not propagated to
 * higher layers. Virtual network devices transmit synchronously, in this case
 * the driver transmit return codes are consumed by dev_queue_xmit(), all
 * others are propagated to higher layers.
 */

/* qdisc ->enqueue() return codes. */
#define NET_XMIT_SUCCESS	0x00
#define NET_XMIT_DROP		0x01	/* skb dropped			*/
#define NET_XMIT_CN			0x02	/* congestion notification	*/
#define NET_XMIT_POLICED	0x03	/* skb is shot by police	*/
#define NET_XMIT_MASK		0x0f	/* qdisc flags in net/sch_generic.h */

/* NET_XMIT_CN is special. It does not guarantee that this packet is lost. It
 * indicates that the device will soon be dropping packets, or already drops
 * some packets of the same priority; prompting us to send less aggressively. */
#define net_xmit_eval(e)	((e) == NET_XMIT_CN ? 0 : (e))
#define net_xmit_errno(e)	((e) != NET_XMIT_CN ? -ENOBUFS : 0)



extern s32 net_init(s32 delta);
extern __u32 secure_tcp_sequence_number(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport);
extern u32 net_random(void);
extern void md5_transform(__u32 *hash, __u32 const *in);
extern u32 secure_ipv4_port_ephemeral(__be32 saddr, __be32 daddr, __be16 dport);
extern inline struct sk_buff *net_get_format_skb(struct net *pnet);

static inline struct net *get_net(struct net *pnet)
{
	atomic_inc(&pnet->count);
	return pnet;
}

static inline void put_net(struct net *net)
{
	atomic_dec_and_test(&net->count);
	//if (atomic_dec_and_test(&net->count))
	//	__put_net(net);
}

static inline void release_net(struct net *pnet)
{
	if (pnet)
		atomic_dec(&pnet->use_count);
}



static inline int net_eq(const struct net *net1, const struct net *net2)
{
	return net1 == net2;
}

static inline unsigned int net_hash_mix(struct net *net)
{
	return 0;									//smallboy:Fix it later;
/*	
#ifdef CONFIG_NET_NS	
	// shift this right to eliminate bits, that are always zeroed
	return (unsigned)(((unsigned long)net) >> L1_CACHE_SHIFT);
#else
	return 0;
#endif
*/
}

#endif
