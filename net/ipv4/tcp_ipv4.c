/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 *		IPv4 specific functions
 *
 *
 *		code split from:
 *		linux/ipv4/tcp.c
 *		linux/ipv4/tcp_input.c
 *		linux/ipv4/tcp_output.c
 *
 *		See tcp.c for author information
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

/*
 * Changes:
 *		David S. Miller	:	New socket lookup architecture.
 *					This code is dedicated to John Dyson.
 *		David S. Miller :	Change semantics of established hash,
 *					half is devoted to TIME_WAIT sockets
 *					and the rest go in the other half.
 *		Andi Kleen :		Add support for syncookies and fixed
 *					some bugs: ip options weren't passed to
 *					the TCP layer, missed a check for an
 *					ACK bit.
 *		Andi Kleen :		Implemented fast path mtu discovery.
 *	     				Fixed many serious bugs in the
 *					request_sock handling and moved
 *					most of it into the af independent code.
 *					Added tail drop and some other bugfixes.
 *					Added new listen semantics.
 *		Mike McLagan	:	Routing by source
 *	Juan Jose Ciarlante:		ip_dynaddr bits
 *		Andi Kleen:		various fixes.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year
 *					coma.
 *	Andi Kleen		:	Fix new listen.
 *	Andi Kleen		:	Fix accept error reporting.
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 */

/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			tcp_ipv4.c
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/


#include "types.h"
#include "ip.h"
#include "tcp.h"
#include "net.h"
#include "socket.h"
#include "skbuff.h"
#include "inet_sock.h"
#include "tcp_metrics.h"
#include "inet_hashtables.h"
#include "inet_timewait_sock.h"
#include "inet_connection_sock.h"
#include "us_error.h"
#include "us_util.h"

//struct inet_hashinfo tcp_hashinfo;
US_DEFINE_PER_LCORE(struct inet_hashinfo *, tcp_hashinfo);

US_DECLARE_PER_LCORE(struct inet_timewait_death_row*,tcp_death_row);

struct request_sock_ops tcp_request_sock_ops;

extern const struct inet_connection_sock_af_ops ipv4_specific;
extern u32 get_local_out_ip(u32 lcore);

int ip_getsockopt(struct sock *sk, int level,
		  int optname, char __user *optval, int __user *optlen)
{
	int err = US_ENOPROTOOPT;

	//err = do_ip_getsockopt(sk, level, optname, optval, optlen, 0);
#ifdef CONFIG_NETFILTER
	/* we need to exclude all possible ENOPROTOOPTs except default case */
	if (err == -ENOPROTOOPT && optname != IP_PKTOPTIONS &&
			!ip_mroute_opt(optname)) {
		int len;

		if (get_user(len, optlen))
			return -EFAULT;

		lock_sock(sk);
		err = nf_getsockopt(sk, PF_INET, optname, optval,
				&len);
		release_sock(sk);
		if (err >= 0)
			err = put_user(len, optlen);
		return err;
	}
#endif
	return err;
}


int ip_setsockopt(struct sock *sk, int level,
		int optname, char __user *optval, unsigned int optlen)
{
	int err = US_ENOPROTOOPT;

	if (level != SOL_IP)
		return -ENOPROTOOPT;

	//err = do_ip_setsockopt(sk, level, optname, optval, optlen);
#ifdef CONFIG_NETFILTER
	/* we need to exclude all possible ENOPROTOOPTs except default case */
	if (err == -ENOPROTOOPT && optname != IP_HDRINCL &&
			optname != IP_IPSEC_POLICY &&
			optname != IP_XFRM_POLICY &&
			!ip_mroute_opt(optname)) {
		lock_sock(sk);
		err = nf_setsockopt(sk, PF_INET, optname, optval, optlen);
		release_sock(sk);
	}
#endif
	return err;
}



/*
 *	IPv4 request_sock destructor.
 */
static void tcp_v4_reqsk_destructor(struct request_sock *req)
{
	//smallboy: NO ip option;
	//kfree(inet_rsk(req)->opt);
}


static void tcp_v4_reqsk_send_ack(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req)
{
	/* sk->sk_state == TCP_LISTEN -> for regular TCP_SYN_RECV
	 * sk->sk_state == TCP_SYN_RECV -> for Fast Open.
	 */
	tcp_v4_send_ack(skb, (sk->sk_state == TCP_LISTEN) ?
			tcp_rsk(req)->snt_isn + 1 : tcp_sk(sk)->snd_nxt,
			tcp_rsk(req)->rcv_nxt, req->rcv_wnd,
			tcp_time_stamp,
			req->ts_recent,
			0,
			inet_rsk(req)->no_srccheck ? IP_REPLY_ARG_NOSRCCHECK : 0,
			ip_hdr(skb)->tos);
}

#if 0	
static void __tcp_v4_send_check(struct sk_buff *skb,__be32 saddr, __be32 daddr)
{

	struct tcphdr *th = tcp_hdr(skb);

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		th->check = ~tcp_v4_check(skb->len, saddr, daddr, 0);
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		th->check = tcp_v4_check(skb->len, saddr, daddr,
						csum_partial(th, th->doff << 2,skb->csum));
	}	
}
#endif

/*
 *	Send a SYN-ACK after having received a SYN.
 *	This still operates on a request_sock only, not on a big
 *	socket.
 */
static int tcp_v4_send_synack(struct sock *sk, struct request_sock *req
								,u16 queue_mapping, bool nocache)
{	
	const struct inet_request_sock *ireq = inet_rsk(req);
	//struct flowi4 fl4;
	int err = -1;
	u16 append = 0;
	struct sk_buff * skb;
	struct net *pnet = sock_net(sk);

	/* First, grab a route. */
	//if (!dst && (dst = inet_csk_route_req(sk, &fl4, req)) == NULL)
	//	return -1;
#if 1
	//skb = pnet->ipv4.tcp_skb;
	skb 	= net_get_format_skb(pnet);	
	append 	= tcp_make_synack(sk, req, NULL,skb);

	err = ip_format_and_send_pkt(skb, sk, ireq->loc_addr,ireq->rmt_addr, append);
	err = net_xmit_eval(err);
	if (!tcp_rsk(req)->snt_synack && !err)
		tcp_rsk(req)->snt_synack = tcp_time_stamp;
	return err;

#else

	skb = tcp_make_synack(sk, req, NULL); // dst,

	if (skb) {
		//__tcp_v4_send_check(skb, ireq->loc_addr, ireq->rmt_addr);

		//skb_set_queue_mapping(skb, queue_mapping);
		err = ip_build_and_send_pkt(skb, sk, ireq->loc_addr,ireq->rmt_addr); //,ireq->opt
		err = net_xmit_eval(err);
		if (!tcp_rsk(req)->snt_synack && !err)
			tcp_rsk(req)->snt_synack = tcp_time_stamp;
	}

	return err;
#endif

}


static int tcp_v4_rtx_synack(struct sock *sk, struct request_sock *req)
{
	int res = tcp_v4_send_synack(sk,  req, 0, false);

	if (!res)
		TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_RETRANSSEGS);
	return res;
}


/*
 *	This routine will send an RST to the other tcp.
 *
 *	Someone asks: why I NEVER use socket parameters (TOS, TTL etc.)
 *		      for reset.
 *	Answer: if a packet caused RST, it is not for a socket
 *		existing in our system, if it is matched to a socket,
 *		it is just duplicate segment or bug in other side's TCP.
 *		So that we build reply only basing on parameters
 *		arrived with segment.
 *	Exception: precedence violation. We do not implement it in any case.
 */

static void tcp_v4_send_reset(struct sock *sk, struct sk_buff *skb)
{	
	const struct iphdr 	*iph = ip_hdr(skb);
	const struct tcphdr *th  = tcp_hdr(skb);
	struct tcphdr *th_new = NULL;
	struct sk_buff *new_skb = NULL;
		
	//struct {
	//	struct tcphdr th;
	//} rep;

	//struct ip_reply_arg arg;
	struct net *pnet = (sk == NULL) ? (US_PER_LCORE(init_net)) : sock_net(sk);	
	struct sock *r_sk = (sk == NULL)? pnet->ipv4.tcp_sock:sk;
	struct inet_sock *inet = inet_sk(r_sk);
	// Never send a reset in response to a reset. 
	if (th->rst)
		return;

	//if (skb_rtable(skb)->rt_type != RTN_LOCAL)
	//	return;

	/* Swap the send and the receive. */
	//memset(&rep, 0, sizeof(rep));
	//rep.th.dest   = th->source;
	//rep.th.source = th->dest;
	//rep.th.doff   = sizeof(struct tcphdr) / 4;
	//rep.th.rst    = 1;

	//if (th->ack) {
	//	rep.th.seq = th->ack_seq;
	//} else {
	//	rep.th.ack = 1;
	//	rep.th.ack_seq = htonl(ntohl(th->seq) + th->syn + th->fin +
	//			       skb->len - (th->doff << 2));
	//}

#if 1
	new_skb = net_get_format_skb(pnet); 
	th_new 	= tcp_hdr(new_skb);; 
	th_new->source = th->dest;
	th_new->dest = th->source;
	th_new->doff = sizeof(struct tcphdr) / 4;
	th_new->rst  = 1;

	if(th->ack) {
		th_new->seq = th->ack_seq;		//smallboy: ack == 0;
	}else{
		th_new->ack = 1;
		th_new->ack_seq = htonl(ntohl(th->seq) + th->syn + th->fin +
					   skb->len - (th->doff << 2));
	}

	th_new->check = 0;
	th_new->window = th->window;
	inet->tos = ip_hdr(skb)->tos;
	
	ip_format_and_send_pkt(new_skb, r_sk, iph->daddr ,iph->saddr, sizeof(struct tcphdr));

	TCP_INC_STATS_BH(pnet, TCP_MIB_OUTSEGS);
	TCP_INC_STATS_BH(pnet, TCP_MIB_OUTRSTS);
#else
	new_skb = alloc_skb(r_sk,MAX_TCP_HEADER,0);
	if (new_skb == NULL){
		return ;
	}

	skb_reserve(new_skb, MAX_TCP_HEADER);
	
	skb_push(new_skb, sizeof(struct tcphdr));
	skb_reset_transport_header(new_skb);
		
	//skb_set_owner_w(skb, sk); 	//LF_W ?
	// Build TCP header and checksum it. 
	th_new	= tcp_hdr(new_skb);
	th_new->source = th->dest;
	th_new->dest = th->source;
	th_new->doff = sizeof(struct tcphdr) / 4;;
	th_new->rst  = 1;
	
	if(th->ack) {
		th_new->seq = th->ack_seq;		//smallboy: ack == 0;
	}else{
		th_new->ack = 1;
		th_new->ack_seq = htonl(ntohl(th->seq) + th->syn + th->fin +
				       skb->len - (th->doff << 2));
	}

	th_new->check = 0;
	th_new->window = th->window;
	
	//memcpy(th,&rep,sizeof(rep));
		
	inet->tos = ip_hdr(skb)->tos;

	//memset(&arg, 0, sizeof(arg));
	//arg.iov[0].iov_base = (unsigned char *)&rep;
	//arg.iov[0].iov_len  = sizeof(rep.th);

	//arg.csum = csum_tcpudp_nofold(ip_hdr(skb)->daddr,
	//			      ip_hdr(skb)->saddr, /* XXX */
	//			      arg.iov[0].iov_len, IPPROTO_TCP, 0);
	//arg.csumoffset = offsetof(struct tcphdr, check) / 2;
	//arg.flags = (sk && inet_sk(sk)->transparent) ? IP_REPLY_ARG_NOSRCCHECK : 0;
	/* When socket is gone, all binding information is lost.
	 * routing might fail in this case. No choice here, if we choose to force
	 * input interface, we will misroute in case of asymmetric route.
	 */
	//if (sk)
	//	arg.bound_dev_if = sk->sk_bound_dev_if;

	//net = dev_net(skb_dst(skb)->dev);
	//net = sock_net(sk);
	//arg.tos = ip_hdr(skb)->tos;
	//ip_send_unicast_reply(net, skb, ip_hdr(skb)->saddr,
	//		      ip_hdr(skb)->daddr, &arg, arg.iov[0].iov_len);

	ip_build_and_send_pkt(new_skb,pnet->ipv4.tcp_sock,
					ip_hdr(skb)->daddr,ip_hdr(skb)->saddr);

	TCP_INC_STATS_BH(pnet, TCP_MIB_OUTSEGS);
	TCP_INC_STATS_BH(pnet, TCP_MIB_OUTRSTS);
#endif
}

static struct sock *tcp_v4_hnd_req(struct sock *sk, struct sk_buff *skb)
{
	//struct sock *nsk;
	struct tcphdr *th = tcp_hdr(skb);
	const struct iphdr *iph = ip_hdr(skb);
	//struct inet_hashinfo *hash_info_p = &US_PER_LCORE(tcp_hashinfo);
	//struct proto	*proto_p	= sk->sk_prot_creator;
	//struct inet_hashinfo *hash_info_p = proto_p->h.hashinfo;
	struct request_sock **prev;		/* Find possible connection requests. */
	struct request_sock *req = inet_csk_search_req(sk, &prev, th->source,
						       iph->saddr, iph->daddr);
	if (req){
		return tcp_check_req(sk, skb, req, prev, false);
	}

	/*  When single process, the lookup here is useless i think , by smallboy ;
	
	nsk = inet_lookup_established(sock_net(sk), hash_info_p, iph->saddr,
			th->source, iph->daddr, th->dest, inet_iif(skb));
	if (nsk) {
		if (nsk->sk_state != TCP_TIME_WAIT) {
			//bh_lock_sock(nsk);	
			return nsk;
		}
		inet_twsk_put(inet_twsk(nsk));
		return NULL;
	} */

//#ifdef CONFIG_SYN_COOKIES			//smallboy:Fix it later;
	if (!th->syn)
		sk = cookie_v4_check(sk, skb, NULL);  //&(IPCB(skb)->opt)
//#endif
	return sk;
}



/* The socket must have it's spinlock held when we get
 * here.
 *
 * We have a potential double-lock case here, so even when
 * doing backlog processing we use the BH locking scheme.
 * This is because we cannot sleep with the original spinlock
 * held.
 */
int tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{	
	struct sock *rsk;
	
	if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */
		//struct dst_entry *dst = sk->sk_rx_dst;
		//sock_rps_save_rxhash(sk, skb);
		//if (dst) {
		//	if (inet_sk(sk)->rx_dst_ifindex != skb->skb_iif ||
		//	    dst->ops->check(dst, 0) == NULL) {
		//		dst_release(dst);
		//		sk->sk_rx_dst = NULL;
		//	}
		//}
			
		if (tcp_rcv_established(sk, skb, tcp_hdr(skb), skb->len)) {
			rsk = sk;			

			goto reset;
		}
		
		return 0;
	}

	//if (skb->len < tcp_hdrlen(skb) || tcp_checksum_complete(skb))
	if (skb->len < tcp_hdrlen(skb) )			//smallboy: Both csumed by hw before;
		goto csum_err;

	if (sk->sk_state == TCP_LISTEN) {
		struct sock *nsk = tcp_v4_hnd_req(sk, skb);
		if (!nsk){	
			goto discard;
		}
		
		if (nsk != sk) {
			//sock_rps_save_rxhash(nsk, skb);
			if (tcp_child_process(sk, nsk, skb)) {
				rsk = nsk;	

				goto reset;
			}
			return 0;
		}
	} //else
	//	sock_rps_save_rxhash(sk, skb);

	if (tcp_rcv_state_process(sk, skb, tcp_hdr(skb), skb->len)) {
		rsk = sk;

		goto reset;
	}

	return 0;

reset:
	tcp_v4_send_reset(rsk, skb);
discard:
	//kfree_skb(skb);		//smallboy:Attention here;
	kfree_skb(skb , US_MBUF_FREE_BY_STACK);
	/* Be careful here. If this function gets more complicated and
	 * gcc suffers from register pressure on the x86, sk (in %ebx)
	 * might be destroyed here. This current version compiles correctly,
	 * but you have been warned.
	 */
	return 0;

csum_err:
	TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_CSUMERRORS);
	TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_INERRS);
	goto discard;
}

static void tcp_v4_timewait_ack(struct sock *sk, struct sk_buff *skb)
{	
	struct inet_timewait_sock *tw = inet_twsk(sk);
	struct tcp_timewait_sock *tcptw = tcp_twsk(sk);

	tcp_v4_send_ack(skb, tcptw->tw_snd_nxt, tcptw->tw_rcv_nxt,
			tcptw->tw_rcv_wnd >> tw->tw_rcv_wscale,
			tcp_time_stamp + tcptw->tw_ts_offset,
			tcptw->tw_ts_recent,
			tw->tw_bound_dev_if,					//	tcp_twsk_md5_key(tcptw),
			tw->tw_transparent ? IP_REPLY_ARG_NOSRCCHECK : 0,
			tw->tw_tos
			);

	inet_twsk_put(tw);
}


int tcp_v4_rcv(struct sk_buff *skb)
{
	const struct iphdr *iph;
	const struct tcphdr *th;
	struct sock *sk;
	int ret;
	struct net *pnet = skb->pnet;
	struct inet_hashinfo *hash_info_p = US_PER_LCORE(tcp_hashinfo);

	/* Count it even if it's bad */
	TCP_INC_STATS_BH(pnet, TCP_MIB_INSEGS);

	if (!is_ipv4_csum_correct_offload((struct rte_mbuf*)(skb->head))){
		IP_INC_STATS_BH(pnet, TCP_MIB_CSUMERRORS);
		ret = US_EFAULT;
		goto discard_it;
	}

	if (!pskb_may_pull(skb, sizeof(struct tcphdr)) || skb->data == NULL)
		goto discard_it;

	th = tcp_hdr(skb);

	if (th->doff < sizeof(struct tcphdr) / 4)
		goto bad_packet;
	
	if (!pskb_may_pull(skb, th->doff * 4))
		goto discard_it;

	/* An explanation is required here, I think.
	 * Packet length and doff are validated by header prediction,
	 * provided case of th->doff==0 is eliminated.
	 * So, we defer the checks. */
	//if (!skb_csum_unnecessary(skb) && tcp_v4_checksum_init(skb))
	//	goto csum_error;								//smallboy: csumed  by hw only;

	th = tcp_hdr(skb);
	iph = ip_hdr(skb);
	if(ip_is_fragment(iph)){
		IP_INC_STATS_BH(pnet, IPSTATS_MIB_REASMREQDS);
		IP_INC_STATS_BH(pnet, IPSTATS_MIB_REASMFAILS);
		goto discard_it;
	}
	
	TCP_SKB_CB(skb)->seq = ntohl(th->seq);
	TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + th->syn + th->fin +
				    skb->len - th->doff * 4);
	TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
	TCP_SKB_CB(skb)->when	 = 0;
	TCP_SKB_CB(skb)->ip_dsfield = ipv4_get_dsfield(iph);
	TCP_SKB_CB(skb)->sacked	 = 0;

	/*
	fprintf(stderr,"TH:%u,skb_id:%u ,src:%s,dst:%s,sport:%u,dport:%u,seq:%-12u,ack:%-12u,"
				   "ipid:%-12u,len:%-12u,SYN:%u;PSH:%u;FIN:%u;RST:%u; window:%u\n"
			,US_GET_LCORE(),skb->skb_id,trans_ip(iph->saddr),trans_ip(iph->daddr)
			,ntohs(th->source),ntohs(th->dest)
			,TCP_SKB_CB(skb)->seq,TCP_SKB_CB(skb)->ack_seq
		   	,iph->id,skb->len,th->syn,th->psh,th->fin,th->rst,ntohs(th->window));
	*/
	
//scard_it:
//d_packet:
//eturn US_RET_OK;

	sk = __inet_lookup_skb(hash_info_p, skb, th->source, th->dest);
	if (!sk){
		goto no_tcp_socket;
	}

	//fprintf(stderr,"RECV__sec:%u__skb_id:%u seq:%u send_seq:%u ack:%u SYN:%u PSH:%u RST:%u FIN:%u ACK:%u window:%u \n"
	//		,us_get_seconds(),skb->skb_id,TCP_SKB_CB(skb)->seq,TCP_SKB_CB(skb)->end_seq,TCP_SKB_CB(skb)->ack_seq
	//		,th->syn,th->psh,th->rst,th->fin,th->ack,ntohs(th->window));
	
process:
	if (sk->sk_state == TCP_TIME_WAIT)
		goto do_time_wait;

	if (unlikely(iph->ttl < inet_sk(sk)->min_ttl)) {
		NET_INC_STATS_BH(pnet, LINUX_MIB_TCPMINTTLDROP);
		goto discard_and_relse;
	}

	//if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
	//	goto discard_and_relse;
	//nf_reset(skb);

	//if (sk_filter(sk, skb))
	//	goto discard_and_relse;

	//skb->dev = NULL;

	//bh_lock_sock_nested(sk);

/*
	ret = 0;
	if (!sock_owned_by_user(sk)) {
#ifdef CONFIG_NET_DMA
		struct tcp_sock *tp = tcp_sk(sk);
		if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
			tp->ucopy.dma_chan = net_dma_find_channel();
		if (tp->ucopy.dma_chan)
			ret = tcp_v4_do_rcv(sk, skb);
		else
#endif
		{
			if (!tcp_prequeue(sk, skb))
				ret = tcp_v4_do_rcv(sk, skb);
		}
	} else if (unlikely(sk_add_backlog(sk, skb,
					   sk->sk_rcvbuf + sk->sk_sndbuf))) {
		bh_unlock_sock(sk);
		NET_INC_STATS_BH(net, LINUX_MIB_TCPBACKLOGDROP);
		goto discard_and_relse;
	}
	bh_unlock_sock(sk);
*/

	ret = tcp_v4_do_rcv(sk, skb);
	sock_put(sk);

	return ret;

no_tcp_socket:
	//if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
	//	goto discard_it;
	
	//if (skb->len < (th->doff << 2) || tcp_checksum_complete(skb)) {
	if (skb->len < (th->doff << 2)) {
//csum_error:
//		TCP_INC_STATS_BH(net, TCP_MIB_CSUMERRORS);
bad_packet:
		TCP_INC_STATS_BH(pnet, TCP_MIB_INERRS);
	} else {
		// if syncookies is open, no reset here ! smallboy: fix it later;
		tcp_v4_send_reset(NULL, skb);
	}

discard_it:
	// Discard frame. 
	//kfree_skb(skb);		//smallboy:Attention here;
	kfree_skb(skb , US_MBUF_FREE_BY_STACK);
	return 0;

discard_and_relse:
	sock_put(sk);
	goto discard_it;

do_time_wait:
	//if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
	//	inet_twsk_put(inet_twsk(sk));
	//	goto discard_it;
	//}

	if (skb->len < (th->doff << 2)) {
		inet_twsk_put(inet_twsk(sk));
		goto bad_packet;
	}

	//if (tcp_checksum_complete(skb)) {
	//	inet_twsk_put(inet_twsk(sk));
	//	goto csum_error;
	//}
	
	switch (tcp_timewait_state_process(inet_twsk(sk), skb, th)) {
	case TCP_TW_SYN: {
		struct sock *sk2 = inet_lookup_listener(skb->pnet,		//dev_net(skb->dev)
							hash_info_p,						//&tcp_hashinfo
							iph->saddr, th->source,
							iph->daddr, th->dest,
							inet_iif(skb));
		if (sk2) {
			inet_twsk_deschedule(inet_twsk(sk),US_PER_LCORE(tcp_death_row));  //inet_twsk_deschedule(inet_twsk(sk), &tcp_death_row);
			inet_twsk_put(inet_twsk(sk));
			sk = sk2;
			goto process;
		}
		// Fall through to ACK 
	}
	case TCP_TW_ACK:
		tcp_v4_timewait_ack(sk, skb);
		break;
	case TCP_TW_RST:
		goto no_tcp_socket;
	case TCP_TW_SUCCESS:;
	}
	goto discard_it;
	
}



/*
 * The three way handshake has completed - we got a valid synack -
 * now create the new socket.
 */
struct sock *tcp_v4_syn_recv_sock(struct sock *sk, struct sk_buff *skb,struct request_sock *req
									,struct tcp_metrics_block *tcpm)
{	
	struct inet_request_sock *ireq;
	struct inet_sock *newinet;
	struct tcp_sock *newtp;
	struct sock *newsk;

	//ip_options_rcu *inet_opt;

	if (sk_acceptq_is_full(sk)){	
		goto exit_overflow;
	}
	
	newsk = tcp_create_openreq_child(sk, req, skb);
	if (!newsk){	
		goto exit_nonewsk;
	}
	
	newsk->sk_gso_type = SKB_GSO_TCPV4;
	//inet_sk_rx_dst_set(newsk, skb);

	newtp		      = tcp_sk(newsk);
	newinet		      = inet_sk(newsk);
	ireq		      = inet_rsk(req);
	newinet->inet_daddr   		= ireq->rmt_addr;
	newinet->inet_rcv_saddr 	= ireq->loc_addr;
	newinet->inet_saddr	      	= ireq->loc_addr;
	//inet_opt	      = ireq->opt;
	//rcu_assign_pointer(newinet->inet_opt, inet_opt);
	//ireq->opt	      = NULL;
	newinet->mc_index     = inet_iif(skb);				//smallboy:Why Multicast here ??
	newinet->mc_ttl	      = ip_hdr(skb)->ttl;
	newinet->rcv_tos      = ip_hdr(skb)->tos;
	inet_csk(newsk)->icsk_ext_hdr_len = 0;
	//if (inet_opt)
	//	inet_csk(newsk)->icsk_ext_hdr_len = inet_opt->opt.optlen;
	newinet->inet_id = newtp->write_seq ^ jiffies;

	//if (!dst) {
	//	dst = inet_csk_route_child_sock(sk, newsk, req);
	//	if (!dst)
	//		goto put_and_exit;
	//} else {
	//	/* syncookie case : see end of cookie_v4_check() */
	//}
	sk_setup_caps(newsk); //, dst

	/*
	if(tcpm == NULL){
		newsk->sk_tcpm = tcp_get_metrics(sk , true);
		if (NULL == newsk->sk_tcpm) {
			goto exit_overflow;
		}
	}else{
		newsk->sk_tcpm = tcpm;
	}*/

	if(tcpm == NULL){
		tcpm = 	tcp_get_metrics(newsk , true);
		if(NULL == tcpm){
			goto exit_overflow;
		}
	}

	sk_set_tcpm(newsk,tcpm);						//smallboy: attention put_and_exit here;
	
	tcp_mtup_init(newsk);
	tcp_sync_mss(newsk, tcp_metric_get(newsk->sk_tcpm ,TCP_METRICS_ATTR_MTU)); //dst_mtu(dst)
	//newtp->advmss = dst_metric_advmss(dst);
	newtp->advmss = get_metric_advmss(newsk->sk_tcpm);
	if (tcp_sk(sk)->rx_opt.user_mss &&
	    tcp_sk(sk)->rx_opt.user_mss < newtp->advmss)
		newtp->advmss = tcp_sk(sk)->rx_opt.user_mss;

	tcp_initialize_rcv_mss(newsk);
	tcp_synack_rtt_meas(newsk, req);
	newtp->total_retrans = req->num_retrans;

	if (__inet_inherit_port(sk, newsk) < 0){
		goto put_and_exit;
	}
	__inet_hash_nolisten(newsk, NULL);

	return newsk;

exit_overflow:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
exit_nonewsk:
	//dst_release(dst);
exit:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENDROPS);
	return NULL;
put_and_exit:
	inet_csk_prepare_forced_close(newsk);
	tcp_done(newsk);
	goto exit;

}

/*
 * Return true if a syncookie should be sent
 */
bool tcp_syn_flood_action(struct sock *sk, const struct sk_buff *skb,
			 const char *proto)
{
	const char *msg = "Dropping request";
	bool want_cookie = false;
	struct listen_sock *lopt;
	struct net *pnet = sock_net(sk);

//#ifdef CONFIG_SYN_COOKIES
	if (pnet->n_cfg.sysctl_tcp_syncookies) {
		msg = "Sending cookies";
		want_cookie = true;
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPREQQFULLDOCOOKIES);
	} else
//#endif
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPREQQFULLDROP);

	lopt = inet_csk(sk)->icsk_accept_queue.listen_opt;
	if (!lopt->synflood_warned) {
		lopt->synflood_warned = 1;
		US_LOG("%s: Possible SYN flooding on port %d. %s.  Check SNMP counters.\n",
			proto, ntohs(tcp_hdr(skb)->dest), msg);
	}
	return want_cookie;
}

#if 0
/*
 * Save and compile IPv4 options into the request_sock if needed.
 */
static struct ip_options_rcu *tcp_v4_save_options(struct sk_buff *skb)
{	
	const struct ip_options *opt = &(IPCB(skb)->opt);
	struct ip_options_rcu *dopt = NULL;

	if (opt && opt->optlen) {
		int opt_size = sizeof(*dopt) + opt->optlen;

		dopt = kmalloc(opt_size, GFP_ATOMIC);
		if (dopt) {
			if (ip_options_echo(&dopt->opt, skb)) {
				kfree(dopt);
				dopt = NULL;
			}
		}
	}
	return dopt;
}
#endif


static inline __u32 tcp_v4_init_sequence(const struct sk_buff *skb)
{
	return secure_tcp_sequence_number(ip_hdr(skb)->daddr, ip_hdr(skb)->saddr,
					  tcp_hdr(skb)->dest,  tcp_hdr(skb)->source);
}

static bool tcp_fastopen_check(struct sock *sk, struct sk_buff *skb, struct request_sock *req,
			       struct tcp_fastopen_cookie *foc, struct tcp_fastopen_cookie *valid_foc)
{
#if 0	
	bool skip_cookie = false;
	struct fastopen_queue *fastopenq;

	if (likely(!fastopen_cookie_present(foc))) {
		/* See include/net/tcp.h for the meaning of these knobs */
		if ((sysctl_tcp_fastopen & TFO_SERVER_ALWAYS) ||
		    ((sysctl_tcp_fastopen & TFO_SERVER_COOKIE_NOT_REQD) &&
		    (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq + 1)))
			skip_cookie = true; /* no cookie to validate */
		else
			return false;
	}
	fastopenq = inet_csk(sk)->icsk_accept_queue.fastopenq;
	/* A FO option is present; bump the counter. */
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPFASTOPENPASSIVE);

	/* Make sure the listener has enabled fastopen, and we don't
	 * exceed the max # of pending TFO requests allowed before trying
	 * to validating the cookie in order to avoid burning CPU cycles
	 * unnecessarily.
	 *
	 * XXX (TFO) - The implication of checking the max_qlen before
	 * processing a cookie request is that clients can't differentiate
	 * between qlen overflow causing Fast Open to be disabled
	 * temporarily vs a server not supporting Fast Open at all.
	 */
	if ((sysctl_tcp_fastopen & TFO_SERVER_ENABLE) == 0 ||
	    fastopenq == NULL || fastopenq->max_qlen == 0)
		return false;

	if (fastopenq->qlen >= fastopenq->max_qlen) {
		struct request_sock *req1;
		spin_lock(&fastopenq->lock);
		req1 = fastopenq->rskq_rst_head;
		if ((req1 == NULL) || time_after(req1->expires, jiffies)) {
			spin_unlock(&fastopenq->lock);
			NET_INC_STATS_BH(sock_net(sk),
			    LINUX_MIB_TCPFASTOPENLISTENOVERFLOW);
			/* Avoid bumping LINUX_MIB_TCPFASTOPENPASSIVEFAIL*/
			foc->len = -1;
			return false;
		}
		fastopenq->rskq_rst_head = req1->dl_next;
		fastopenq->qlen--;
		spin_unlock(&fastopenq->lock);
		reqsk_free(req1);
	}
	if (skip_cookie) {
		tcp_rsk(req)->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		return true;
	}
	if (foc->len == TCP_FASTOPEN_COOKIE_SIZE) {
		if ((sysctl_tcp_fastopen & TFO_SERVER_COOKIE_NOT_CHKED) == 0) {
			tcp_fastopen_cookie_gen(ip_hdr(skb)->saddr, valid_foc);
			if ((valid_foc->len != TCP_FASTOPEN_COOKIE_SIZE) ||
			    memcmp(&foc->val[0], &valid_foc->val[0],
			    TCP_FASTOPEN_COOKIE_SIZE) != 0)
				return false;
			valid_foc->len = -1;
		}
		/* Acknowledge the data received from the peer. */
		tcp_rsk(req)->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		return true;
	} else if (foc->len == 0) { /* Client requesting a cookie */
		tcp_fastopen_cookie_gen(ip_hdr(skb)->saddr, valid_foc);
		NET_INC_STATS_BH(sock_net(sk),
		    LINUX_MIB_TCPFASTOPENCOOKIEREQD);
	} else {
		/* Client sent a cookie with wrong size. Treat it
		 * the same as invalid and return a valid one.
		 */
		tcp_fastopen_cookie_gen(ip_hdr(skb)->saddr, valid_foc);
	}
	return false;
#endif
	return false;
}

static int tcp_v4_conn_req_fastopen(struct sock *sk,struct sk_buff *skb,
				    struct sk_buff *skb_synack,struct request_sock *req)
{
	US_ERR("TH:%u,should not be there!%s\n",US_GET_LCORE(),__FUNCTION__);
#if 0	
	struct tcp_sock *tp = tcp_sk(sk);
	struct request_sock_queue *queue = &inet_csk(sk)->icsk_accept_queue;
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct sock *child;
	int err;

	req->num_retrans = 0;
	req->num_timeout = 0;
	req->sk = NULL;

	child = inet_csk(sk)->icsk_af_ops->syn_recv_sock(sk, skb, req, NULL);
	if (child == NULL) {
		NET_INC_STATS_BH(sock_net(sk),
				 LINUX_MIB_TCPFASTOPENPASSIVEFAIL);
		kfree_skb(skb_synack);
		return -1;
	}
	err = ip_build_and_send_pkt(skb_synack, sk, ireq->loc_addr,
				    ireq->rmt_addr, ireq->opt);
	err = net_xmit_eval(err);
	if (!err)
		tcp_rsk(req)->snt_synack = tcp_time_stamp;
	/* XXX (TFO) - is it ok to ignore error and continue? */

	spin_lock(&queue->fastopenq->lock);
	queue->fastopenq->qlen++;
	spin_unlock(&queue->fastopenq->lock);

	/* Initialize the child socket. Have to fix some values to take
	 * into account the child is a Fast Open socket and is created
	 * only out of the bits carried in the SYN packet.
	 */
	tp = tcp_sk(child);

	tp->fastopen_rsk = req;
	/* Do a hold on the listner sk so that if the listener is being
	 * closed, the child that has been accepted can live on and still
	 * access listen_lock.
	 */
	sock_hold(sk);
	tcp_rsk(req)->listener = sk;

	/* RFC1323: The window in SYN & SYN/ACK segments is never
	 * scaled. So correct it appropriately.
	 */
	tp->snd_wnd = ntohs(tcp_hdr(skb)->window);

	/* Activate the retrans timer so that SYNACK can be retransmitted.
	 * The request socket is not added to the SYN table of the parent
	 * because it's been added to the accept queue directly.
	 */
	inet_csk_reset_xmit_timer(child, ICSK_TIME_RETRANS,
	    TCP_TIMEOUT_INIT, TCP_RTO_MAX);

	/* Add the child socket directly into the accept queue */
	inet_csk_reqsk_queue_add(sk, req, child);

	/* Now finish processing the fastopen child socket. */
	inet_csk(child)->icsk_af_ops->rebuild_header(child);
	tcp_init_congestion_control(child);
	tcp_mtup_init(child);
	tcp_init_buffer_space(child);
	tcp_init_metrics(child);

	/* Queue the data carried in the SYN packet. We need to first
	 * bump skb's refcnt because the caller will attempt to free it.
	 *
	 * XXX (TFO) - we honor a zero-payload TFO request for now.
	 * (Any reason not to?)
	 */
	if (TCP_SKB_CB(skb)->end_seq == TCP_SKB_CB(skb)->seq + 1) {
		/* Don't queue the skb if there is no payload in SYN.
		 * XXX (TFO) - How about SYN+FIN?
		 */
		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
	} else {
		skb = skb_get(skb);
		skb_dst_drop(skb);
		__skb_pull(skb, tcp_hdr(skb)->doff * 4);
		skb_set_owner_r(skb, child);
		__skb_queue_tail(&child->sk_receive_queue, skb);
		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		tp->syn_data_acked = 1;
	}
	sk->sk_data_ready(sk, 0);
	bh_unlock_sock(child);
	sock_put(child);
	WARN_ON(req->sk == NULL);
	return 0;
#endif
	return 1;
}


int tcp_v4_conn_request(struct sock *sk, struct sk_buff *skb)
{	
	struct tcp_options_received tmp_opt;
	struct request_sock *req;
	struct inet_request_sock *ireq;
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *pnet = sk->sk_net;
	struct tcp_metrics_block *tcpm = NULL;
	tcp_ip_stack_config	*n_cfg	= &pnet->n_cfg;
	//struct dst_entry *dst = NULL;
	__be32 saddr = ip_hdr(skb)->saddr;
	__be32 daddr = ip_hdr(skb)->daddr;
	__u32 isn = TCP_SKB_CB(skb)->when;
	bool want_cookie = false;
	//struct flowi4 fl4;
	struct tcp_fastopen_cookie foc = { .len = -1 };
	struct tcp_fastopen_cookie valid_foc = { .len = -1 };
	struct sk_buff *skb_synack;
	int do_fastopen;
	int tcp_append;

	/* Never answer to SYNs send to broadcast or multicast */
	//if (skb_rtable(skb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
	//	goto drop;

	/* TW buckets are converted to open requests without
	 * limitations, they conserve resources and peer is
	 * evidently real one.
	 */
	if (inet_csk_reqsk_queue_is_full(sk) && !isn) {
		want_cookie = tcp_syn_flood_action(sk, skb, "TCP");
		if (!want_cookie){		
			goto drop;
		}
	}

	/* Accept backlog is full. If we have already queued enough
	 * of warm entries in syn queue, drop request. It is better than
	 * clogging syn queue with openreqs with exponentially increasing
	 * timeout.
	 */
	if (sk_acceptq_is_full(sk) && inet_csk_reqsk_queue_young(sk) > 1) {  // smallboy £» qlen-qyoung == syn/ack retransmit;
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);	
		goto drop;
	}

	req = inet_reqsk_alloc(&tcp_request_sock_ops,pnet);
	if (!req){
		goto drop;
	}
	
	tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = TCP_MSS_DEFAULT;
	tmp_opt.user_mss  = tp->rx_opt.user_mss;
	tcp_parse_options(skb, &tmp_opt, 0, want_cookie ? NULL : &foc);

	if (want_cookie && !tmp_opt.saw_tstamp)
		tcp_clear_options(&tmp_opt);

	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;
	tcp_openreq_init(req, &tmp_opt, skb);

	ireq = inet_rsk(req);
	ireq->loc_addr = daddr;
	ireq->rmt_addr = saddr;
	ireq->no_srccheck = inet_sk(sk)->transparent;
	//ireq->opt = tcp_v4_save_options(skb);

	//if (security_inet_conn_request(sk, skb, req))
	//	goto drop_and_free;

	if (!want_cookie || tmp_opt.tstamp_ok)
		TCP_ECN_create_request(req, skb, sock_net(sk));

	if (want_cookie) {
		isn = cookie_v4_init_sequence(sk, skb, &req->mss);
		req->cookie_ts = tmp_opt.tstamp_ok;
	} else if (!isn) {
		/* VJ's idea. We save last timestamp seen
		 * from the destination in peer table, when entering
		 * state TIME-WAIT, and check against it before
		 * accepting new connection request.
		 *
		 * If "isn" is not zero, this request hit alive
		 * timewait bucket, so that all the necessary checks
		 * are made in the function processing timewait state.
		 */

		tcpm = __tcp_get_metrics_req(req,pnet);  // No create here;smallboy;	
		
		if (tmp_opt.saw_tstamp &&
		    n_cfg->sysctl_tw_recycle && tcpm)  {   //(dst = inet_csk_route_req(sk, &fl4, req)) != NULL && fl4.daddr == saddr
 			if (!tcp_peer_is_proven(req,tcpm ,true)) {
				NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PAWSPASSIVEREJECTED);
				goto drop_and_release;
			}
		}
		/* Kill the following clause, if you dislike this way. */
		else if (!n_cfg->sysctl_tcp_syncookies 
					&& ((n_cfg->sysctl_max_syn_backlog - inet_csk_reqsk_queue_len(sk))
							< (n_cfg->sysctl_max_syn_backlog >> 2))
						&& !tcp_peer_is_proven(req, tcpm, false)) {     //smallboy: terrible here i think;
			/* Without syncookies last quarter of
			 * backlog is filled with destinations,
			 * proven to be alive.
			 * It means that we continue to communicate
			 * to destinations, already remembered
			 * to the moment of synflood.
			 */
			US_ERR("drop open request from %pI4/%u tcpm:%p,:%u :%u :%u\n"
						,&saddr, ntohs(tcp_hdr(skb)->source),tcpm
						,(n_cfg->sysctl_max_syn_backlog)
						,inet_csk_reqsk_queue_len(sk)
						,!tcp_peer_is_proven(req, tcpm, false));
			goto drop_and_release;
		}

		isn = tcp_v4_init_sequence(skb);
	}
	
	tcp_rsk(req)->snt_isn = isn;
	//if (dst == NULL) {					
	//	dst = inet_csk_route_req(sk, &fl4, req);		
	//	if (dst == NULL)									//smallboy:Fix it later;
	//		goto drop_and_free;
	//}
	
	do_fastopen = tcp_fastopen_check(sk, skb, req, &foc, &valid_foc);

	/* We don't call tcp_v4_send_synack() directly because we need
	 * to make sure a child socket can be created successfully before
	 * sending back synack!
	 *
	 * XXX (TFO) - Ideally one would simply call tcp_v4_send_synack()
	 * (or better yet, call tcp_send_synack() in the child context
	 * directly, but will have to fix bunch of other code first)
	 * after syn_recv_sock() except one will need to first fix the
	 * latter to remove its dependency on the current implementation
	 * of tcp_v4_send_synack()->tcp_select_initial_window().
	 */

	/*
	skb_synack = tcp_make_synack(sk, req,
	    fastopen_cookie_present(&valid_foc) ? &valid_foc : NULL);

	//if (skb_synack) {
	//	__tcp_v4_send_check(skb_synack, ireq->loc_addr, ireq->rmt_addr);
		//skb_set_queue_mapping(skb_synack, skb_get_queue_mapping(skb));
	//} else
	//	goto drop_and_free;
	if(!skb_synack){
	fprintf(stderr,"func:%s,%u \n",__FUNCTION__,__LINE__);		
	US_DEBUG("TH:%u, FUNC:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);	
		goto drop_and_free;
	}*/
	//skb_synack = pnet->ipv4.tcp_skb;

#if 1
	skb_synack = net_get_format_skb(pnet);
	tcp_append = tcp_make_synack(sk ,req 
								,fastopen_cookie_present(&valid_foc) ? &valid_foc : NULL
								,skb_synack);

	if (likely(!do_fastopen)) {
		int err;
		err = ip_format_and_send_pkt(skb_synack, sk, ireq->loc_addr,ireq->rmt_addr, tcp_append);
		//err = ip_build_and_send_pkt(skb_synack, sk, ireq->loc_addr,ireq->rmt_addr);
		//err = net_xmit_eval(err);
		if (err || want_cookie){
		US_DEBUG(" syncookies func:%s,%u \n",__FUNCTION__,__LINE__);
			
			goto drop_and_free;
		}
		tcp_rsk(req)->snt_synack = tcp_time_stamp;
		tcp_rsk(req)->listener = NULL;
		// Add the request_sock to the SYN table 
		inet_csk_reqsk_queue_hash_add(sk, req, TCP_TIMEOUT_INIT);  //TCP_TIMEOUT_INIT FOR debug here ;smallboy;
		
		if (fastopen_cookie_present(&foc) && foc.len != 0)
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPFASTOPENPASSIVEFAIL);
	} else if (tcp_v4_conn_req_fastopen(sk, skb, skb_synack, req))
		goto drop_and_free; 

#else
	skb_synack = tcp_make_synack(sk ,req 
								,fastopen_cookie_present(&valid_foc) ? &valid_foc : NULL );

	if (likely(!do_fastopen)) {
		int err;
		err = ip_build_and_send_pkt(skb_synack, sk, ireq->loc_addr,ireq->rmt_addr);
		err = net_xmit_eval(err);
		if (err || want_cookie){
		US_DEBUG(" syncookies func:%s,%u \n",__FUNCTION__,__LINE__);
			
			goto drop_and_free;
		}
		tcp_rsk(req)->snt_synack = tcp_time_stamp;
		tcp_rsk(req)->listener = NULL;
		// Add the request_sock to the SYN table 
		inet_csk_reqsk_queue_hash_add(sk, req, TCP_TIMEOUT_INIT);  //TCP_TIMEOUT_INIT FOR debug here ;smallboy;
		
		if (fastopen_cookie_present(&foc) && foc.len != 0)
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPFASTOPENPASSIVEFAIL);
	} else if (tcp_v4_conn_req_fastopen(sk, skb, skb_synack, req))
		goto drop_and_free;
#endif

	return 0;

drop_and_release:
	//dst_release(dst);
drop_and_free:
	reqsk_free(req);
drop:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENDROPS);
	return 0;
}


/* This will initiate an outgoing connection. */
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{	
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_timewait_death_row	*tdr = US_PER_LCORE(tcp_death_row);
	__be32 daddr;
	//__be16 orig_sport, orig_dport;
	//__be32 daddr, nexthop;
	//struct flowi4 *fl4;
	//struct rtable *rt;
	int err;
	//struct ip_options_rcu *inet_opt;

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	//nexthop = daddr = usin->sin_addr.s_addr;

	//inet_opt = rcu_dereference_protected(inet->inet_opt,sock_owned_by_user(sk));
	//if (inet_opt && inet_opt->opt.srr) {
	//	if (!daddr)
	//		return -EINVAL;
	//	nexthop = inet_opt->opt.faddr;
	//}

	//orig_sport = inet->inet_sport;
	//orig_dport = usin->sin_port;
	//fl4 = &inet->cork.fl.u.ip4;
	//rt = ip_route_connect(fl4, nexthop, inet->inet_saddr,
	//		      RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
	//		      IPPROTO_TCP,
	//		      orig_sport, orig_dport, sk, true);
	//if (IS_ERR(rt)) {
	//	err = PTR_ERR(rt);
	//	if (err == -ENETUNREACH)
	//		IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
	//	return err;
	//}

	//if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
	//	ip_rt_put(rt);
	//	return -ENETUNREACH;
	//}

	//if (!inet_opt || !inet_opt->opt.srr)
	//	daddr = fl4->daddr;

	//if (!inet->inet_saddr)
	//	inet->inet_saddr = fl4->saddr;

	if(!inet->inet_saddr)
		inet->inet_saddr = get_local_out_ip(US_GET_LCORE());
	
	inet->inet_rcv_saddr = inet->inet_saddr;

	daddr = usin->sin_addr.s_addr;
	
	inet->inet_daddr = daddr;
	inet->inet_dport = usin->sin_port;

	if (tp->rx_opt.ts_recent_stamp && inet->inet_daddr != daddr) {
		/* Reset inherited state */
		tp->rx_opt.ts_recent	   = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		if (likely(!tp->repair))
			tp->write_seq = 0;
	}


	if (sock_net(sk)->n_cfg.sysctl_tw_recycle &&
	    !tp->rx_opt.ts_recent_stamp )   //&& fl4->daddr == daddr
		tcp_fetch_timewait_stamp(sk);  //, &rt->dst				//why ?????

	inet->inet_dport = usin->sin_port;
	inet->inet_daddr = daddr;

	inet_csk(sk)->icsk_ext_hdr_len = 0;
	//if (inet_opt)
	//	inet_csk(sk)->icsk_ext_hdr_len = inet_opt->opt.optlen;

	tp->rx_opt.mss_clamp = TCP_MSS_DEFAULT;

	/* Socket identity is still unknown (sport may be zero).
	 * However we set state to SYN-SENT and not releasing socket
	 * lock select source port, enter ourselves into the hash tables and
	 * complete initialization after this.
	 */
	tcp_set_state(sk, TCP_SYN_SENT);
	err = inet_hash_connect(tdr, sk);   //&tcp_death_row
	if (err)
		goto failure;

	//rt = ip_route_newports(fl4, rt, orig_sport, orig_dport,
	//		       inet->inet_sport, inet->inet_dport, sk);
	//if (IS_ERR(rt)) {
	//	err = PTR_ERR(rt);
	//	rt = NULL;
	//	goto failure;
	//}
	
	/* OK, now commit destination to socket.  */
	sk->sk_gso_type = SKB_GSO_TCPV4;
	sk_setup_caps(sk); //, &rt->dst

	if (!tp->write_seq && likely(!tp->repair))
		tp->write_seq = secure_tcp_sequence_number(inet->inet_saddr,
							   inet->inet_daddr,
							   inet->inet_sport,
							   usin->sin_port);

	inet->inet_id = tp->write_seq ^ jiffies;

	err = tcp_connect(sk);

	//rt = NULL;
	if (err)
		goto failure;

	return 0;

failure:
	/*
	 * This unhashes the socket and releases the local port,
	 * if necessary.
	 */
	tcp_set_state(sk, TCP_CLOSE);
	//ip_rt_put(rt);
	//sk->sk_route_caps = 0;
	inet->inet_dport = 0;
	return err;
}


/* NOTE: A lot of things set to zero explicitly by call to
 *       sk_alloc() so need not be done here.
 */
int tcp_v4_init_sock(struct sock *sk)
{	
	struct inet_connection_sock *icsk = inet_csk(sk);

	tcp_init_sock(sk);

	icsk->icsk_af_ops = &ipv4_specific;

	return 0;
}

void tcp_v4_destroy_sock(struct sock *sk)
{	
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_clear_xmit_timers(sk);

	//tcp_cleanup_congestion_control(sk);

	/* Cleanup up the write buffer. */
	tcp_write_queue_purge(sk);

	/* Cleans up our, hopefully empty, out_of_order_queue. */
	__skb_queue_purge(&tp->out_of_order_queue);

	/* Clean prequeue, it must be empty really */
	//__skb_queue_purge(&tp->ucopy.prequeue);

	/* Clean up a referenced TCP bind bucket. */
	if (inet_csk(sk)->icsk_bind_hash)
		inet_put_port(sk);

	//BUG_ON(tp->fastopen_rsk != NULL);

	/* If socket is aborted during connect operation */
	tcp_free_fastopen_req(tp);

	sk_sockets_allocated_dec(sk);
	//sock_release_memcg(sk);	
}

int tcp_twsk_unique(struct sock *sk, struct sock *sktw, void *twp)
{	
	const struct tcp_timewait_sock *tcptw = tcp_twsk(sktw);
	struct tcp_sock *tp = tcp_sk(sk);

	/* With PAWS, it is safe from the viewpoint
	   of data integrity. Even without PAWS it is safe provided sequence
	   spaces do not overlap i.e. at data rates <= 80Mbit/sec.

	   Actually, the idea is close to VJ's one, only timestamp cache is
	   held not per host, but per port pair and TW bucket is used as state
	   holder.

	   If TW bucket has been already destroyed we fall back to VJ's scheme
	   and use initial timestamp retrieved from peer table.
	 */
	if (tcptw->tw_ts_recent_stamp &&
	    (twp == NULL || (sock_net(sk)->n_cfg.sysctl_tcp_tw_reuse &&
			     us_get_seconds() - tcptw->tw_ts_recent_stamp > 1))) {
		tp->write_seq = tcptw->tw_snd_nxt + 65535 + 2;
		if (tp->write_seq == 0)
			tp->write_seq = 1;
		tp->rx_opt.ts_recent	   = tcptw->tw_ts_recent;
		tp->rx_opt.ts_recent_stamp = tcptw->tw_ts_recent_stamp;
		sock_hold(sktw);
		return 1;
	}

	return 0;
}

void tcp_twsk_destructor(struct sock *sk)
{
//#ifdef CONFIG_TCP_MD5SIG
//	struct tcp_timewait_sock *twsk = tcp_twsk(sk);
//
//	if (twsk->tw_md5_key) {
//		tcp_free_md5sig_pool();
//		kfree_rcu(twsk->tw_md5_key, rcu);
//	}
//#endif
}

US_DEFINE_PER_LCORE(struct proto*,tcp_prot);
//smallboy: proto inited later;

/*
struct proto tcp_prot = {
	.name			= "TCP",
	//.owner			= THIS_MODULE,
	.close			= tcp_close,
	.connect		= tcp_v4_connect,
	.disconnect		= tcp_disconnect,
	.accept			= inet_csk_accept,
	//.ioctl			= tcp_ioctl,
	.init			= tcp_v4_init_sock,
	.destroy		= tcp_v4_destroy_sock,
	.shutdown		= tcp_shutdown,
	.setsockopt		= tcp_setsockopt,
	.getsockopt		= tcp_getsockopt,
	.recvmsg		= tcp_recvmsg,
	.sendmsg		= tcp_sendmsg,
	//.sendpage		= tcp_sendpage,
	//.backlog_rcv		= tcp_v4_do_rcv,
	//.release_cb		= tcp_release_cb,
	//.mtu_reduced		= tcp_v4_mtu_reduced,
	.hash			= inet_hash,
	.unhash			= inet_unhash,
	.get_port		= inet_csk_get_port,
	//.enter_memory_pressure	= tcp_enter_memory_pressure,			//smallboy:later;
	.sockets_allocated	= &tcp_sockets_allocated,
	.orphan_count		= &tcp_orphan_count,
	.memory_allocated	= &tcp_memory_allocated,
	.memory_pressure	= &tcp_memory_pressure,
	.sysctl_wmem		= sysctl_tcp_wmem,
	.sysctl_rmem		= sysctl_tcp_rmem,
	.max_header			= MAX_TCP_HEADER,
	//.obj_size			= sizeof(struct tcp_sock),
	//.slab_flags		= SLAB_DESTROY_BY_RCU,
	.twsk_prot			= &tcp_timewait_sock_ops,
	.rsk_prot			= &tcp_request_sock_ops,
	.h.hashinfo			= &tcp_hashinfo,
	.no_autobind		= true,
};*/

struct request_sock_ops tcp_request_sock_ops  = {
	.family		=	PF_INET,
	.obj_size	=	sizeof(struct tcp_request_sock),
	.rtx_syn_ack	=	tcp_v4_rtx_synack,
	.send_ack	=	tcp_v4_reqsk_send_ack,
	.destructor	=	tcp_v4_reqsk_destructor,
	.send_reset	=	tcp_v4_send_reset,
	.syn_ack_timeout = 	tcp_syn_ack_timeout,
};

const struct inet_connection_sock_af_ops ipv4_specific = {
	.queue_xmit	   	   = ip_queue_xmit,
	//.send_check	   = tcp_v4_send_check,				//smallboy: always be check_sumed by hw;
	//.rebuild_header  = inet_sk_rebuild_header,
	//.sk_rx_dst_set   = inet_sk_rx_dst_set,
	.conn_request	   = tcp_v4_conn_request,
	.syn_recv_sock	   = tcp_v4_syn_recv_sock,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   	   = ip_setsockopt,
	.getsockopt	       = ip_getsockopt,
	.addr2sockaddr	   = inet_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in),
	.bind_conflict	   = inet_csk_bind_conflict,
//#ifdef CONFIG_COMPAT
//	.compat_setsockopt = compat_ip_setsockopt,
//	.compat_getsockopt = compat_ip_getsockopt,
//#endif
};

struct timewait_sock_ops tcp_timewait_sock_ops = {
	//.twsk_obj_size	= sizeof(struct tcp_timewait_sock),
	.twsk_unique	= tcp_twsk_unique,
	.twsk_destructor= tcp_twsk_destructor,
};


