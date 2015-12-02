/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) output module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 *	See ip_input.c for original log
 *
 *	Fixes:
 *		Alan Cox	:	Missing nonblock feature in ip_build_xmit.
 *		Mike Kilburn	:	htons() missing in ip_build_xmit.
 *		Bradford Johnson:	Fix faulty handling of some frames when
 *					no route is found.
 *		Alexander Demenshin:	Missing sk/skb free in ip_queue_xmit
 *					(in case if packet not accepted by
 *					output firewall rules)
 *		Mike McLagan	:	Routing by source
 *		Alexey Kuznetsov:	use new route cache
 *		Andi Kleen:		Fix broken PMTU recovery and remove
 *					some redundant tests.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Andi Kleen	: 	Replace ip_reply with ip_send_reply.
 *		Andi Kleen	:	Split fast and slow ip_build_xmit path
 *					for decreased register pressure on x86
 *					and more readibility.
 *		Marc Boucher	:	When call_out_firewall returns FW_QUEUE,
 *					silently drop skb instead of failing with -EPERM.
 *		Detlev Wengorz	:	Copy protocol for fragments.
 *		Hirokazu Takahashi:	HW checksumming for outgoing UDP
 *					datagrams.
 *		Hirokazu Takahashi:	sendfile() on UDP works now.
 */

/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			ip_output.c
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/ 



#include "skbuff.h"
#include "sock.h"
#include "tcp.h"
#include "tcp_metrics.h"
#include "socket.h"
#include "us_error.h"
#include "us_util.h"

struct sock;
struct net;

US_DECLARE_PER_LCORE(struct net*, init_net);
US_DECLARE_PER_LCORE(struct proto*, tcp_prot);

US_DECLARE_PER_LCORE(u32,mmbuf_flush) ;
US_DECLARE_PER_LCORE(u32,mmbuf_num) ;


u32 glb_debug_trace = 0;


s32 ip_init(void)
{
	s32	i = 0;
	s32 skc_id ;
	struct sk_buff 	*skb = NULL;
	struct sock		*sk = NULL;
	struct net		*pnet = US_PER_LCORE(init_net);
	
	sk = us_sock_alloc(pnet);
	skc_id = sk->sk_id;
	memset(sk, 0, sizeof(struct sock));
	sk->sk_id = skc_id;

	US_DEBUG("TH:%u,ip_init sk_id:%u\n",US_GET_LCORE(),sk->sk_id);
	if (!sk){
		US_ERR("TH:%d,fatal error! No ipv4->tcp_sock!",US_GET_LCORE());
		return US_ENOMEM;
	}

	sk->sk_wmem_alloc = 1;

	sk->sk_prot = US_PER_LCORE(tcp_prot);
	sk->sk_prot_creator = sk->sk_prot;
	sk->sk_family = AF_INET;
	sk->sk_net = pnet;
	
	sk->sk_reuse = 0;
	
	//sock_init_data(sk,sk);
	sk->sk_protocol		= IPPROTO_TCP;
	sk->sk_userlocks 	= (SOCK_SNDBUF_LOCK|SOCK_RCVBUF_LOCK);

	pnet->ipv4.tcp_sock = sk;

	US_PER_LCORE(mmbuf_flush) = 0;
	US_PER_LCORE(mmbuf_num) = 0;

	memset(pnet->ipv4.tcp_skb,0,sizeof(void *)*US_MAX_PKT_BURST_OUT*2);
	for(i = 0; i< US_MAX_PKT_BURST_OUT*2 ; i++){
		skb = alloc_skb(sk,MAX_TCP_HEADER,US_SKB_CLONE);
		if(skb == NULL){
			US_ERR("TH:%d,fatal error! No skb alloced for ipv4->tcp_sock!",US_GET_LCORE());
			return US_ENOMEM;
		}

		skb->len = 0;		//Do not put here;
		skb_build_ip_head(skb,pnet);
		pnet->ipv4.tcp_skb[i] = skb;
	}

	pnet->ipv4.tcp_skb_index = 0;
	//if(rte_pktmbuf_trim((struct rte_mbuf*)skb->head,MAX_TCP_HEADER) < 0){
	//	US_ERR("TH:%d,fatal error! No skb reserved for ipv4->tcp_sock!",US_GET_LCORE);	
	//	return US_ENOBUFS;
	//}
	
	return US_RET_OK;
}


static inline int ip_select_ttl(struct sock *sk)
{
	//int ttl = inet->uc_ttl;

	//if (ttl < 0)
	//	ttl = ip4_dst_hoplimit(dst);
	//return ttl;
	return sock_net(sk)->n_cfg.sysctl_ip_default_ttl;
}

//smallboy: We change the whole func here;
int ip_local_out(struct sk_buff *skb)
{
	//us_nic_port	*port = NULL;
	//port = get_local_out_port(skb);
	//if (port == NULL  ){
	//	IP_INC_STATS_BH(skb->pnet, IPSTATS_MIB_OUTNOROUTES);
	//	return US_ENETUNREACH;
	//}

	s32 ret = US_RET_OK;
	u32 n ;
	struct rte_mbuf *mbuf = (struct rte_mbuf*)(skb->head);
	struct net		*pnet = skb->pnet;

	if(skb->nohdr ){
		if( skb->nf_trace || skb->used > 0 ){
			rte_pktmbuf_prepend(mbuf, skb->mac_len);
		}

		mbuf_rebuild(skb , pnet->port);	
		//ret = ip_send_out(pnet,mbuf,skb);				//smallboy:  unkown error here; ip traunked; ???
		
		recv_pkt_dump(&mbuf, 1);

		n = rte_eth_tx_burst(pnet->port_id, pnet->send_queue_id , &mbuf, 1);	
		if(n < 1){
			US_ERR("TH:%u ,tx_burst failed on skb_id:%u sk_id:%u \n"
					,US_GET_LCORE(),skb->skb_id,skb->sk->sk_id);
			IP_ADD_STATS(skb->pnet,IPSTATS_MIB_OUTDISCARDS , 1); 
			ret = US_ENETDOWN;  
		}else{
			ret = US_RET_OK;
			IP_ADD_STATS(skb->pnet,IPSTATS_MIB_OUTPKTS , 1);  //skb->gso_segs == 1;
		}

		if(skb->users == 1){		//smallboy: More attention about the users,clone,used and nf_trace;
			__kfree_skb(skb,US_MBUF_FREE_BY_OTHER);		//users == 1; not cloned;  or errors here;
		}else{
			if(ret == US_RET_OK)	//smallboy: data send failed; No recover the users too;	
				skb->users--;
			skb->used++;
			skb_reset_data_header(skb);
		}
	}else{
		if(skb_can_gso(skb)){
			ret = ip_send_out_batch(skb,pnet);
		}
		
		if(skb->users == 1){		//smallboy: More attention about the users,clone,used and nf_trace;
			__kfree_skb(skb,US_MBUF_FREE_BY_STACK);		//users == 1; not cloned;  or errors here;
		}else{
			if(ret == US_RET_OK)
				skb->users--;
			skb->used++;
			skb_reset_data_header(skb);
		}		
	}

	return ret;
}

int ip_queue_xmit(struct sk_buff *skb)
{	
	//smallboy:    We delete all the route here;
	//smallboy:    ROUTE ROUTE  ROUTE  ROUTE !!!!!
	
	struct sock 		*sk 	= skb->sk;
	struct inet_sock 	*inet 	= inet_sk(sk);
	struct tcphdr 	 	*th		= tcp_hdr(skb);
	struct net 			*pnet 	= sock_net(sk);
	struct netns_ipv4	*n_ipv4 = &pnet->ipv4;

	struct iphdr *iph;
	u32 ihl;
	s32 ret = 0;

	//ihl = sizeof(struct iphdr) + (inet_opt ? inet_opt->optlen : 0);
	ihl = sizeof(struct iphdr);
	skb_push(skb, ihl);
	
	skb_reset_network_header(skb);
	
	iph = ip_hdr(skb);
	
	iph->version = 4;					//smallboy: Attention for ipv6;
	iph->ihl 	 = ihl>>2;

	iph->tos	 = inet->tos;
	iph->tot_len = htons(skb->len);
	
	iph->frag_off = htons(IP_DF);
	iph->ttl	  = ip_select_ttl(sk);
	iph->protocol = sk->sk_protocol;
	
	iph->daddr	= inet->inet_daddr;			//
	iph->saddr	= inet->inet_rcv_saddr; 	//smallboy:Attention here;

	ip_select_ident_more(iph, sk, (skb->gso_segs ?: 1) - 1);
	
	th->check	= 0;
	//th->check	= get_ipv4_udptcp_checksum(iph , th);
	
	iph->check	= 0;

	th->check = get_ipv4_psd_sum(iph);
	//iph->check  = ip_fast_csum(iph, iph->ihl);

	if(n_ipv4->aft_route_out){
		ret = n_ipv4->aft_route_out(skb);
		if(ret < 0){
			skb_reset_data_header(skb);	
			return ret;
		}
	}

	ret = ip_local_out(skb);

	return ret;
}

/*
 *		Add an ip header to a skbuff and send it out.
 *
 */
int ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,__be32 saddr, __be32 daddr)
{
	int ret = 0;
	struct inet_sock 	*inet 	= inet_sk(sk);
	struct tcphdr 		*th 	= tcp_hdr(skb);
	struct net 			*pnet 	= sock_net(sk);
	struct netns_ipv4	*n_ipv4 = &pnet->ipv4;
	struct iphdr *iph;

	// Build the IP header. 
	skb_push(skb, sizeof(struct iphdr));  ////+ (opt ? opt->opt.optlen : 0)
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	
	iph->version  = 4;
	iph->ihl      = 5;		
	//iph->tos      = 0;//inet->tos;
	iph->tos      = inet->tos;
	iph->tot_len  = htons(skb->len);
	iph->frag_off = htons(IP_DF);		//smallboy :must before ip_select_ident;
	
	ip_select_ident(skb, sk);
	iph->ttl      = ip_select_ttl(sk);
	iph->protocol = sk->sk_protocol;
	iph->daddr    = daddr;
	iph->saddr    = saddr;
	
	iph->check	  = 0;
	//iph->check    = ip_fast_csum(iph, iph->ihl);

	th->check = 0;
	//th->check = get_ipv4_udptcp_checksum(iph , th);
	th->check = get_ipv4_psd_sum(iph);
	
	//skb->mark = sk->sk_mark;

	//fprintf(stderr,"TH:%u,src:%s,dst:%s,sport:%u,dport:%u,seq:%-12u,ack:%-12u,ipid:%-12u,len:%-12u,SYN:%u;PSH:%u;ACK:%u;FIN:%u;RST:%u; send!!!\n"
	//		,US_GET_LCORE(),trans_ip(iph->saddr),trans_ip(iph->daddr)
	//		,ntohs(th->source),ntohs(th->dest)
	//		,ntohl(th->seq),ntohl(th->ack_seq)
	//		,iph->id,skb->len,th->syn,th->psh,th->ack,th->fin,th->rst);	

	if(n_ipv4->aft_route_out){
		ret = n_ipv4->aft_route_out(skb);
		if(ret < 0)
			return US_ENETUNREACH;
	}

	// Send it out. 
	return ip_local_out(skb);		
}

int ip_format_and_send_pkt(struct sk_buff *skb,struct sock*sk,__be32 saddr, __be32 daddr,u16 tcp_len)
{
	int ret	= 0;
	struct net 			*pnet 	= sock_net(sk);
	struct netns_ipv4	*n_ipv4 = &pnet->ipv4;
	struct inet_sock 	*inet 	= inet_sk(sk);
	struct tcphdr 		*th 	= tcp_hdr(skb);
	struct iphdr 		*iph	= ip_hdr(skb);

	iph->tos 		= inet->tos;
	iph->tot_len 	= htons(sizeof(struct iphdr) + tcp_len);
	iph->frag_off 	= htons(IP_DF);
	ip_select_ident(skb, sk);
	iph->ttl      	= ip_select_ttl(sk);
	iph->protocol 	= sk->sk_protocol;
	iph->daddr    	= daddr;
	iph->saddr    	= saddr;
	iph->check	  	= 0; 
	th->check 		= 0;	
	th->check 		= get_ipv4_psd_sum(iph);

	if(n_ipv4->aft_route_out){
		ret = n_ipv4->aft_route_out(skb);
		if(ret < 0)
			return US_ENETUNREACH;
	}

	return mbuf_format_and_send(skb, tcp_len);
}
