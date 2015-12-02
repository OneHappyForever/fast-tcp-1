/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for inet_sock
 *
 * Authors:	Many, reorganised here by
 * 		Arnaldo Carvalho de Melo <acme@mandriva.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			inet_sock.h
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/


#ifndef _US_INET_SOCK_H
#define _US_INET_SOCK_H

#include "types.h"
#include "sock.h"
#include "net.h"
#include "ipv6.h"
#include "request_sock.h"

enum {
	INET_ECN_NOT_ECT = 0,
	INET_ECN_ECT_1 = 1,
	INET_ECN_ECT_0 = 2,
	INET_ECN_CE = 3,
	INET_ECN_MASK = 3,
};

#define INET_PROTOSW_REUSE 			0x01	     /* Are ports automatically reusable? */
#define INET_PROTOSW_PERMANENT 		0x02  /* Permanent protocols are unremovable. */
#define INET_PROTOSW_ICSK      		0x04  /* Is this an inet_connection_sock? */


struct inet_request_sock {
	struct request_sock	req;
#ifdef CONFIG_IPV6
	u16			inet6_rsk_offset;
#endif
	__be16			loc_port;
	__be32			loc_addr;
	__be32			rmt_addr;
	__be16			rmt_port;
//	kmemcheck_bitfield_begin(flags);
	u16			snd_wscale : 4,
				rcv_wscale : 4,
				tstamp_ok  : 1,
				sack_ok	   : 1,
				wscale_ok  : 1,
				ecn_ok	   : 1,
				acked	   : 1,
				no_srccheck: 1;
//	kmemcheck_bitfield_end(flags);
//	struct ip_options_rcu	*opt;		//smallboy: no ip_opt now;
};

//struct ip_options_rcu {
	//struct rcu_head rcu;
//	struct ip_options opt;
//};

/** struct ip_options - IP Options
 *
 * @faddr - Saved first hop address
 * @nexthop - Saved nexthop address in LSRR and SSRR
 * @is_data - Options in __data, rather than skb
 * @is_strictroute - Strict source route
 * @srr_is_hit - Packet destination addr was our one
 * @is_changed - IP checksum more not valid
 * @rr_needaddr - Need to record addr of outgoing dev
 * @ts_needtime - Need to record timestamp
 * @ts_needaddr - Need to record addr of outgoing dev
 */
struct ip_options {
	__be32		faddr;
	__be32		nexthop;
	unsigned char	optlen;
	unsigned char	srr;
	unsigned char	rr;
	unsigned char	ts;
	unsigned char	is_strictroute:1,
			srr_is_hit:1,
			is_changed:1,
			rr_needaddr:1,
			ts_needtime:1,
			ts_needaddr:1;
	unsigned char	router_alert;
	unsigned char	cipso;
	unsigned char	__pad2;
	unsigned char	__data[0];
};

/** struct inet_sock - representation of INET sockets
 *
 * @sk - ancestor class
 * @pinet6 - pointer to IPv6 control block
 * @inet_daddr - Foreign IPv4 addr
 * @inet_rcv_saddr - Bound local IPv4 addr
 * @inet_dport - Destination port
 * @inet_num - Local port
 * @inet_saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @inet_sport - Source port
 * @inet_id - ID counter for DF pkts
 * @tos - TOS
 * @mc_ttl - Multicasting TTL
 * @is_icsk - is this an inet_connection_sock?
 * @uc_index - Unicast outgoing device index
 * @mc_index - Multicast device index
 * @mc_list - Group array
 * @cork - info to build ip hdr on each ip frag while socket is corked
 */
struct inet_sock {  //sk and pinet6 has to be the first two members of inet_sock
	struct sock			sk;
//#ifdef CONFIG_IPV6
	//struct ipv6_pinfo	*pinet6;
//#endif  //Socket demultiplex comparisons on incoming packets.
#define inet_daddr		sk.__sk_common.skc_daddr			//YES		rmt_addr;
#define inet_rcv_saddr	sk.__sk_common.skc_rcv_saddr		//YES		loc_addr;
#define inet_addrpair	sk.__sk_common.skc_addrpair
#define inet_dport		sk.__sk_common.skc_dport			// remote dest port(Big);
#define inet_num		sk.__sk_common.skc_num				// local src port(Host)
#define inet_portpair	sk.__sk_common.skc_portpair

	__be32			inet_saddr;
	__s16			uc_ttl;
	__u16			cmsg_flags;
	__be16			inet_sport;
	__u16			inet_id;

	//struct ip_options_rcu __rcu	*inet_opt;
	struct ip_options	*inet_opt;		//smallboy:Not used;
	int				rx_dst_ifindex;
	__u8			tos;
	__u8			min_ttl;
	__u8			mc_ttl;
	__u8			pmtudisc;
	__u8			recverr:1,
					is_icsk:1,
					freebind:1,
					hdrincl:1,
					mc_loop:1,
					transparent:1,
					mc_all:1,
					nodefrag:1;
	__u8			rcv_tos;
	int				uc_index;
	int				mc_index;
	__be32			mc_addr;
	//struct ip_mc_socklist __rcu	*mc_list;	//smallboy:No multicast for ip anymore;
	//struct inet_cork_full	cork;				//smallboy:Not used;
};

extern void inet_sock_destruct(struct sock *sk);


static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static inline unsigned int inet_ehashfn(struct net *pnet, const __be32 laddr, const __u16 lport,
					const __be32 faddr, const __be16 fport)
{
	return us_jhash_3words((__force __u32) laddr
							,(__force __u32) faddr
							,((__u32) lport) << 16 | (__force __u32)fport
							,pnet->inet_ehash_secret + net_hash_mix(pnet));
}

static inline struct inet_request_sock *inet_rsk(const struct request_sock *sk)
{
	return (struct inet_request_sock *)sk;
}

static inline struct request_sock *inet_reqsk_alloc(struct request_sock_ops *ops,struct net*pnet)
{													
	struct request_sock *req = reqsk_alloc(ops,pnet);
	//struct inet_request_sock *ireq = inet_rsk(req);

	//if (req != NULL) {
	//	kmemcheck_annotate_bitfield(ireq, flags);		//smallboy: NO mem leak check;
	//	ireq->opt = NULL;								//
	//}

	return req;
}

static inline int INET_ECN_is_not_ect(__u8 dsfield)
{
	return (dsfield & INET_ECN_MASK) == INET_ECN_NOT_ECT;
}

static inline int inet_sk_ehashfn(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	const __be32 laddr = inet->inet_rcv_saddr;
	const __u16 lport = inet->inet_num;
	const __be32 faddr = inet->inet_daddr;
	const __be16 fport = inet->inet_dport;
	struct net *net = sock_net(sk);

	return inet_ehashfn(net, laddr, lport, faddr, fport);
}

static inline void INET_ECN_xmit(struct sock *sk)
{
	inet_sk(sk)->tos |= INET_ECN_ECT_0;
	//if (inet6_sk(sk) != NULL)
	//	inet6_sk(sk)->tclass |= INET_ECN_ECT_0;
}

static inline void INET_ECN_dontxmit(struct sock *sk)
{
	inet_sk(sk)->tos &= ~INET_ECN_MASK;
	//if (inet6_sk(sk) != NULL)
	//	inet6_sk(sk)->tclass &= ~INET_ECN_MASK;
}



#endif
