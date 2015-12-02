/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			net.c
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/  


#include "net.h"
#include "ip.h"
#include "tcp.h"
#include "ktime.h"
#include "tcp_metrics.h"
#include "us_error.h"
#include "us_entry.h"

#include <stdlib.h>

#define NET_SECRET_SIZE (MD5_MESSAGE_BYTES / 4)


US_DEFINE_PER_LCORE(struct net* ,init_net);

US_DEFINE_PER_LCORE(struct tcp_mib ,tcp_statistics);
US_DEFINE_PER_LCORE(struct ipstats_mib ,  ip_statistics);
US_DEFINE_PER_LCORE(struct linux_mib  ,  net_statistics);
US_DEFINE_PER_LCORE(struct udp_mib	,	udp_statistics);
//US_DEFINE_PER_LCORE(struct udp_mib	,udplite_statistics);
US_DEFINE_PER_LCORE(struct icmp_mib	,icmp_statistics);
//US_DEFINE_PER_LCORE(struct icmpmsg_mib ,icmpmsg_statistics);

static u32 	net_secret[NET_SECRET_SIZE];

us_th_info	glb_thread[US_LCORE_MAX] = {{0,0,0,0,0,0}};
us_cpu_idle glb_thcpu[US_LCORE_MAX] ;
us_nic_port	 us_nic_ports[APP_MAX_NIC_PORTS] ;



void net_mib_init(struct net* pnet)
{
	pnet->mib.tcp_statistics[0] = &US_PER_LCORE(tcp_statistics);
	memset(&US_PER_LCORE(tcp_statistics),0,sizeof(struct tcp_mib));
	pnet->mib.ip_statistics[0] = &US_PER_LCORE(ip_statistics); //&ip_statistics;
	memset(&US_PER_LCORE(tcp_statistics),0,sizeof(struct ipstats_mib));
	pnet->mib.net_statistics[0] = &US_PER_LCORE(net_statistics); //&net_statistics;
	memset(&US_PER_LCORE(tcp_statistics),0,sizeof(struct linux_mib));
	
	pnet->mib.udp_statistics[0] = &US_PER_LCORE(udp_statistics); //&udp_statistics;
	memset(&US_PER_LCORE(tcp_statistics),0,sizeof(struct udp_mib));
	//pnet->mib.udplite_statistics[0] = &US_PER_LCORE(udplite_statistics); //&udplite_statistics;
	pnet->mib.icmp_statistics[0] = &US_PER_LCORE(icmp_statistics); //&icmp_statistics;
	memset(&US_PER_LCORE(tcp_statistics),0,sizeof(struct icmp_mib));
	//pnet->mib.icmpmsg_statistics[0] =&US_PER_LCORE(icmpmsg_statistics);  //&icmpmsg_statistics;
}

static void net_secret_init(void)
{
	//u32 tmp;
	int i;

	if (likely(net_secret[0]))
		return;

	srand((u32)(jiffies>>16));

	for (i = NET_SECRET_SIZE; i > 0;) {
		//do {
		//	get_random_bytes(&tmp, sizeof(tmp));
		//} while (!tmp);
		//cmpxchg(&net_secret[--i], 0, tmp);
		net_secret[--i] = rand();
	}
}

u32 secure_ipv4_port_ephemeral(__be32 saddr, __be32 daddr, __be16 dport)
{
	u32 hash[MD5_DIGEST_WORDS];

	net_secret_init();
	hash[0] = (__force u32)saddr;
	hash[1] = (__force u32)daddr;
	hash[2] = (__force u32)dport ^ net_secret[14];
	hash[3] = net_secret[15];

	md5_transform(hash, net_secret);

	return hash[0];
}

static u32 seq_scale(u32 seq)
{
	/*
	 *	As close as possible to RFC 793, which
	 *	suggests using a 250 kHz clock.
	 *	Further reading shows this assumes 2 Mb/s networks.
	 *	For 10 Mb/s Ethernet, a 1 MHz clock is appropriate.
	 *	For 10 Gb/s Ethernet, a 1 GHz clock should be ok, but
	 *	we also need to limit the resolution so that the u32 seq
	 *	overlaps less than one time per MSL (2 minutes).
	 *	Choosing a clock of 64 ns period is OK. (period of 274 s)
	 */
	return seq + (ktime_to_ns(ktime_get_real()) >> 6);
}


__u32 secure_tcp_sequence_number(__be32 saddr, __be32 daddr,
				 __be16 sport, __be16 dport)
{
	u32 hash[MD5_DIGEST_WORDS];

	//net_secret_init();				// within net_init(s32 delta)
	hash[0] = (__force u32)saddr;
	hash[1] = (__force u32)daddr;
	hash[2] = ((__force u16)sport << 16) + (__force u16)dport;
	hash[3] = net_secret[15];

	md5_transform(hash, net_secret);

	return seq_scale(hash[0]);
}

u32 net_random(void)		//Fix it later maybe ;
{
	srand((u32)(jiffies>>16));
	return rand();
}

void net_tcp_sysclt_init(struct net* pnet)
{
	tcp_ip_stack_config	*n_cfgp = &pnet->n_cfg;
	memset(n_cfgp,0,sizeof(tcp_ip_stack_config));
													//smallboy: there must be difference between 3.10; 
	n_cfgp->sysctl_tcp_mtu_probing 		= 0;
	n_cfgp->sysctl_tcp_ecn				= 0;		// 0 maybe;	
	
	n_cfgp->sysctl_tcp_syn_retries 		= TCP_SYN_RETRIES;
	n_cfgp->sysctl_tcp_retries1			= TCP_RETR1;
	n_cfgp->sysctl_tcp_retries2			= TCP_RETR2;
	n_cfgp->sysctl_tcp_synack_retries	= TCP_SYNACK_RETRIES;
	
	n_cfgp->sysctl_tcp_orphan_retries	= 0;
	n_cfgp->sysctl_tcp_reordering		= TCP_FASTRETRANS_THRESH;
	n_cfgp->sysctl_tcp_thin_linear_timeouts	= 0;
	n_cfgp->sysctl_tcp_frto				= 2;	
	n_cfgp->sysctl_tcp_keepalive_intvl	= TCP_KEEPALIVE_INTVL;
	n_cfgp->sysctl_tcp_keepalive_time	= TCP_KEEPALIVE_TIME;
	n_cfgp->sysctl_tcp_keepalive_probes	= TCP_KEEPALIVE_PROBES;
	n_cfgp->sysctl_tcp_fin_timeout		= TCP_FIN_TIMEOUT;
	n_cfgp->sysctl_nr_file 				= NR_FILE;
	n_cfgp->sysctl_tcp_max_orphans 		= NR_FILE;
	
	n_cfgp->sysctl_tcp_nometrics_save	= 0;
	n_cfgp->sysctl_tcp_moderate_rcvbuf	= 0;
	
	n_cfgp->sysctl_ip_default_ttl		= 128;
	n_cfgp->sysctl_tcp_early_retrans	= 4;   //default is 3, open;

	n_cfgp->sysctl_tcp_cookie_size 		= 0;
	n_cfgp->sysctl_tcp_abc 				= 0;
	n_cfgp->sysctl_tcp_slow_start_after_idle = 1;

	n_cfgp->sysctl_tcp_syncookies 		= 0;
	n_cfgp->sysctl_max_syn_backlog 		= SOMAXCONN*128;//256;

	n_cfgp->sysctl_tcp_base_mss 		= TCP_BASE_MSS;
	n_cfgp->sysctl_tcp_window_scaling  	= 1;			//0;

	n_cfgp->sysctl_tcp_dsack			= 1;
	n_cfgp->sysctl_tcp_sack  			= 1;
	n_cfgp->sysctl_tcp_fack 			= 1;
	
	n_cfgp->sysctl_tw_recycle			= 0;
	n_cfgp->sysctl_tcp_tw_reuse 		= 0;
	n_cfgp->sysctl_tcp_timestamps 		= 0;
	
	n_cfgp->sysctl_base_mtu				= 512;					// ??
	n_cfgp->sysctl_dev_mtu 				= 1500;

	n_cfgp->sysctl_tcp_frto_response 	= 1;
	n_cfgp->sysctl_tcp_max_ssthresh 	= 0;
	n_cfgp->sysctl_tcp_tso_win_divisor 	= 1;   //default :3
	n_cfgp->sysctl_tcp_init_cwnd		= TCP_INIT_CWND;
	n_cfgp->sysctl_tcp_fastopen			= 0;

	n_cfgp->sysctl_portrange_low		= 1024;
	n_cfgp->sysctl_portrange_high 		= 60000;
	n_cfgp->sysctl_somaxconn			= SOMAXCONN*64;			//SOMAXCONN;
	n_cfgp->sysctl_max_tw_buckets		= NR_FILE * 2;
	n_cfgp->sysctl_tcp_rfc1337 			= 0;
	n_cfgp->sysctl_tcp_challenge_ack_limit = 100;
	n_cfgp->sysctl_wmem_default 		= 65535;
	n_cfgp->sysctl_rmem_default 		= 65535;
	
	n_cfgp->sysctl_tcp_ca				= &cubictcp  ; //&tcp_reno; cubictcp;
	n_cfgp->sysctl_ip_nonlocal_bind		= 0;
	n_cfgp->sysctl_tcp_min_tso_segs 	= 2;
	
	n_cfgp->sysctl_skb_limit_rcv		= 2000;
	n_cfgp->sysctl_skb_limit_snd 		= 2000;	
	
	n_cfgp->sysctl_rmem_max				= 4096*1024;
	n_cfgp->sysctl_wmem_max				= 4096*1024;
	n_cfgp->sysctl_tcp_app_win			= 31;
	n_cfgp->sysctl_tcp_workaround_signed_windows	= 0;
	n_cfgp->max_schedule_timeout		= 60*60;
}


s32 net_burst_buf_init(struct net *pnet)
{
	int i = 0;
	struct rte_mbuf	*mbuf	 = NULL;
	struct rte_mbuf	**mmbuf  = &pnet->mmbuf[0];
	us_mempool		*mbuf_s  = US_PER_LCORE(mbuf_pool_s);

	for(i = 0; i< US_MAX_PKT_BURST_OUT; i++){
		mbuf = rte_pktmbuf_alloc_noreset(mbuf_s);
		if(mbuf == NULL)
			return US_ENOMEM;
		rte_pktmbuf_reset(mbuf);			
		mmbuf[i] = mbuf;
	}

	return US_RET_OK;
}


int tcp_drop_local(struct sk_buff *skb)
{	/*
	static u32 rand_num = 0;
	static u32 proton = 331;   
	static u32 again = 0; 
	
	struct iphdr 	*iph = (struct iphdr*)skb->network_header;
	struct tcphdr	*th  = (struct tcphdr*)skb->transport_header;
	u32	data_len = ntohs(iph->tot_len) - (th->doff*4) - (iph->ihl*4);
		*/
	/*
	struct tcp_sock *tp = tcp_sk(skb->sk);
	
	if(skb->nf_trace){
		
	fprintf(stderr,"RE--SEND--sec:%u--sk->snd_wnd:%u cwnd:%u prior_cwnd:%u lost_out:%u skb_id:%u seq:%u end_seq:%u ack:%u SYN:%u PSH:%u RST:%u FIN:%u ACK:%u window:%u \n"
			,us_get_seconds(),tp->snd_wnd,tp->snd_cwnd,tp->prior_cwnd,tp->lost_out,skb->skb_id,ntohl(th->seq),ntohl(th->seq) + ntohs(iph->tot_len) - th->doff*4 - iph->ihl*4
			,TCP_SKB_CB(skb)->ack_seq,th->syn,th->psh,th->rst,th->fin,th->ack,ntohs(th->window));
	}else{

	fprintf(stderr,"SEND-sec:%u--skb_id:%u seq:%u end_seq:%u ack:%u SYN:%u PSH:%u RST:%u FIN:%u ACK:%u window:%u \n"
			,us_get_seconds(),skb->skb_id,ntohl(th->seq),ntohl(th->seq) + ntohs(iph->tot_len) - th->doff*4 - iph->ihl*4 
			,TCP_SKB_CB(skb)->ack_seq,th->syn,th->psh,th->rst,th->fin,th->ack,ntohs(th->window));		

	}*/
	//US_DEBUG("data_len:%u :%u :%u \n",data_len, rand_num, proton);
/*
	rand_num++ ;
	if(skb->nf_trace){
		if(skb->used < 2) {
			th->check = 0;
		}
	}else{
		if(data_len > 0 && (rand_num % proton == 3)){
			th->check = 0;
		}
	}
	*/
	//if(skb->nf_trace){
	//	glb_debug_trace++;
		
		//fprintf(stderr,"TH:%u,nf_trace_ skb->id:%u,skb->len:%u,skb->mac_len:%u,skb->delta_csum_len:%u \n"
		//		,US_GET_LCORE(),skb->skb_id,skb->len,skb->mac_len,skb->delta_csum_len);
		//fprintf(stderr,"TH:%u,nf_trace_ src:%s,dst:%s, source:%u, dest:%u,seq:%-12u,end_seq:%u,ack:%-12u,ipid:%-12u,len:%-12u,SYN:%u;PSH:%u;ACK:%u;FIN:%u;RST:%u; resend\n"
		//		,US_GET_LCORE(),trans_ip(iph->saddr),trans_ip(iph->daddr)
		//		,ntohs(th->source),ntohs(th->dest)
		//		,ntohl(th->seq),ntohl(th->seq) + skb->len -sizeof(struct tcphdr) - sizeof(struct iphdr) ,ntohl(th->ack_seq)
		//		,iph->id,skb->len,th->syn,th->psh,th->ack,th->fin,th->rst);
	//}//else
	/*
	if(skb->nohdr == 1)
	{
		fprintf(stderr,"TH:%u,skb_id:%u ,src:%s,dst:%s,sport:%u,dport:%u,seq:%-12u,ack:%-12u,ipid:%-12u,len:%-12u,SYN:%u;PSH:%u;ACK:%u;FIN:%u;RST:%u; send\n"
			,US_GET_LCORE(),skb->skb_id,trans_ip(iph->saddr),trans_ip(iph->daddr)
			,ntohs(th->source),ntohs(th->dest)
			,ntohl(th->seq),ntohl(th->ack_seq)
			,iph->id,skb->len,th->syn,th->psh,th->ack,th->fin,th->rst);		
	}*/
	
	return 0;
}

void net_nf_hook_init(struct net *pnet)
{	
	//pnet->ipv4.aft_route_out = tcp_drop_local;
	//tcp_drop_local(skb,iph,th);  move to aft_route_out;

}

s32 net_init(s32 delta)
{
	s32 ret;
	u32 if_id = 1;
	
	struct net *pnet = (struct net *)us_zmalloc(NULL,sizeof(struct net),SMP_CACHE_BYTES);
	US_PER_LCORE(init_net) = pnet;

	pnet->port_id = if_id ;						//smallboy ; So ugly, fix it later;
	pnet->send_queue_id = glb_thread[US_GET_LCORE()].queue_send_id;
	pnet->port = &us_nic_ports[if_id];
	
	pnet->inet_ehash_secret = (u32)(jiffies>>24);
	if((ret = net_tcp_metrics_init(pnet,delta)) != 0){
		return ret;
	}

	net_secret_init();

	if(	(ret = net_burst_buf_init(pnet)) < 0){
		return ret;
	}

	net_nf_hook_init(pnet);
	
	net_tcp_sysclt_init(pnet);
	net_mib_init(pnet);

#if 1
	pnet->sock_pool 	= US_PER_LCORE(sock_pool);
	pnet->socket_pool 	= US_PER_LCORE(socket_pool);
	pnet->sk_tw_pool	= US_PER_LCORE(sk_tw_pool);
	pnet->sk_req_pool	= US_PER_LCORE(sk_req_pool);
	pnet->tcpm_pool		= US_PER_LCORE(tcp_metric_pool);
	pnet->mbuf_s_pool	= US_PER_LCORE(mbuf_pool_s);
#else	
	pnet->req_slab		= US_PER_LCORE(sk_req_slab);
	pnet->tw_slab		= US_PER_LCORE(sk_tw_slab);
	pnet->socket_slab	= US_PER_LCORE(socket_slab);

#endif

	dmesg_snmp_all();

	return US_RET_OK;
}

inline struct sk_buff *net_get_format_skb(struct net *pnet)
{
	struct sk_buff *skb = pnet->ipv4.tcp_skb[(pnet->ipv4.tcp_skb_index++)%(US_MAX_PKT_BURST_OUT*2)];
	skb_mbuf_format_recover((struct rte_mbuf*)skb->head,skb->mac_len);
	skb->mac_len = 0;

	return skb;
}


