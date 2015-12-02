/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			ip.h
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/ 


#ifndef _US_IP_H
#define _US_IP_H

#include "types.h"
#include "inet_sock.h"

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__u16	tot_len;
	__u16	id;
	__u16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__u32	saddr;
	__u32	daddr;
	/*The options start here. */
};


struct inet_skb_parm {
	struct ip_options	opt;		/* Compiled IP options		*/
	unsigned char		flags;

#define IPSKB_FORWARDED		1
#define IPSKB_XFRM_TUNNEL_SIZE	2
#define IPSKB_XFRM_TRANSFORMED	4
#define IPSKB_FRAG_COMPLETE	8
#define IPSKB_REROUTED		16

	u16			frag_max_size;
};

struct kvec {
	void *iov_base; 	/* and that should *never* hold a userland pointer */
	size_t iov_len;
};

struct ip_reply_arg {
	struct 		kvec iov[1];   
	int	    	flags;
	__wsum 	    csum;
	int	    	csumoffset; /* u16 offset of csum in iov[0].iov_base -1 if not needed */ 
	int	   		bound_dev_if;
	u8  	    tos;
}; 

#define IP_REPLY_ARG_NOSRCCHECK 1

#define inet_v6_ipv6only(__sk)		0


#define IP_INC_STATS(net, field)	SNMP_INC_STATS64((net)->mib.ip_statistics, field)
#define IP_INC_STATS_BH(net, field)	SNMP_INC_STATS64_BH((net)->mib.ip_statistics, field)
#define IP_ADD_STATS(net, field, val)	SNMP_ADD_STATS64((net)->mib.ip_statistics, field, val)
#define IP_ADD_STATS_BH(net, field, val) SNMP_ADD_STATS64_BH((net)->mib.ip_statistics, field, val)
#define IP_UPD_PO_STATS(net, field, val) SNMP_UPD_PO_STATS64((net)->mib.ip_statistics, field, val)
#define IP_UPD_PO_STATS_BH(net, field, val) SNMP_UPD_PO_STATS64_BH((net)->mib.ip_statistics, field, val)
#define NET_INC_STATS(net, field)	SNMP_INC_STATS((net)->mib.net_statistics, field)
#define NET_INC_STATS_BH(net, field)	SNMP_INC_STATS_BH((net)->mib.net_statistics, field)
#define NET_INC_STATS_USER(net, field) 	SNMP_INC_STATS_USER((net)->mib.net_statistics, field)
#define NET_ADD_STATS_BH(net, field, adnd) SNMP_ADD_STATS_BH((net)->mib.net_statistics, field, adnd)
#define NET_ADD_STATS_USER(net, field, adnd) SNMP_ADD_STATS_USER((net)->mib.net_statistics, field, adnd)



/* IP_MTU_DISCOVER values */
#define IP_PMTUDISC_DONT		0	/* Never send DF frames */
#define IP_PMTUDISC_WANT		1	/* Use per route hints	*/
#define IP_PMTUDISC_DO			2	/* Always DF		*/
#define IP_PMTUDISC_PROBE		3       /* Ignore dst pmtu      */

/* IP flags. */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

/* Pseudo Header for IPv4/UDP/TCP checksum */
struct psd_header {
	u32 src_addr; /* IP address of source host. */
	u32 dst_addr; /* IP address of destination host(s). */
	u8  zero;     /* zero. */
	u8  proto;    /* L4 protocol type. */
	u16 len;      /* L4 length. */
} __attribute__((__packed__));


static inline u16 get_16b_sum(u16 *ptr16, u32 nr)
{
	u32 sum = 0;
	while (nr > 1)
	{
		sum +=*ptr16;
		nr -= sizeof(u16);
		ptr16++;
		if (sum > USHRT_MAX)
			sum -= USHRT_MAX;
	}

	/* If length is in odd bytes */
	if (nr)
		sum += *((u8*)ptr16);

	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	sum &= 0x0ffff;
	return (u16)sum;
}


static inline u16 get_ipv4_cksum(struct iphdr *ipv4_hdr)
{
	u16 cksum;
	cksum = get_16b_sum((u16*)ipv4_hdr, sizeof(struct iphdr));
	return (u16)((cksum == 0xffff)?cksum:~cksum);
}

static inline u16 get_ipv4_psd_sum (struct iphdr * ip_hdr)
{
	struct psd_header psd_hdr;
	psd_hdr.src_addr = ip_hdr->saddr;
	psd_hdr.dst_addr = ip_hdr->daddr;
	psd_hdr.zero     = 0;
	psd_hdr.proto    = ip_hdr->protocol;
	psd_hdr.len      = rte_cpu_to_be_16((u16)(rte_be_to_cpu_16(ip_hdr->tot_len)
				- sizeof(struct iphdr)));
	return get_16b_sum((u16*)&psd_hdr, sizeof(struct psd_header));
}


static inline u16 get_ipv4_udptcp_checksum(struct iphdr *ipv4_hdr, u16 *l4_hdr)
{
	u32 cksum;
	u32 l4_len;

	l4_len = rte_be_to_cpu_16(ipv4_hdr->tot_len) - sizeof(struct iphdr);

	cksum = get_16b_sum(l4_hdr, l4_len);
	cksum += get_ipv4_psd_sum(ipv4_hdr);

	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
	cksum = (~cksum) & 0xffff;
	if (cksum == 0)
		cksum = 0xffff;
	return (u16)cksum;

}

static inline void inet_reset_saddr(struct sock *sk)
{
	inet_sk(sk)->inet_rcv_saddr = inet_sk(sk)->inet_saddr = 0;
#ifdef CONFIG_IPV6
	if (sk->sk_family == PF_INET6) {
		struct ipv6_pinfo *np = inet6_sk(sk);

		memset(&np->saddr, 0, sizeof(np->saddr));
		memset(&np->rcv_saddr, 0, sizeof(np->rcv_saddr));
	}
#endif
}

static inline void __ip_select_ident(struct iphdr *iph, int more)
{
	US_ERR("TH:%u,should not be there!%s \n",US_GET_LCORE(),__FUNCTION__);
#if 0	
	struct net *net = dev_net(dst->dev);
	struct inet_peer *peer;

	peer = inet_getpeer_v4(net->ipv4.peers, iph->daddr, 1);
	if (peer) {
		iph->id = htons(inet_getid(peer, more));
		inet_putpeer(peer);
		return;
	}

	ip_select_fb_ident(iph);
#endif 
	iph->id = htons(ntohs(iph->id) + 1);
}


static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_network_header(skb);
}

static inline bool ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}

static inline void ip_select_ident(struct sk_buff *skb,  struct sock *sk)
{
	struct iphdr *iph = ip_hdr(skb);

	if ((iph->frag_off & htons(IP_DF)) && !skb->local_df) {
		/* This is only to work around buggy Windows95/2000
		 * VJ compression implementations.  If the ID field
		 * does not change, they drop every other packet in
		 * a TCP stream using header compression.
		 */
		iph->id = (sk && inet_sk(sk)->inet_daddr) ? htons(inet_sk(sk)->inet_id++) : 0;
	} else
		__ip_select_ident(iph,  0);
}

static inline void ip_select_ident_more(struct iphdr *iph, struct sock *sk, int more)
{
	if (iph->frag_off & htons(IP_DF)) {
		if (sk && inet_sk(sk)->inet_daddr) {
			iph->id = htons(inet_sk(sk)->inet_id);
			inet_sk(sk)->inet_id += 1 + more;
		} else
			iph->id = 0;
	} else
		__ip_select_ident(iph,more);
}


static inline int inet_is_reserved_local_port(struct net*pnet,int port)
{
	return test_bit(port, pnet->n_cfg.sysctl_local_reserved_ports);
}


static inline __u8 ipv4_get_dsfield(const struct iphdr *iph)
{
	return iph->tos;
}


extern int ip_queue_xmit(struct sk_buff *skb);
extern s32 ip_init(void);
extern int ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,__be32 saddr, __be32 daddr);
extern int ip_format_and_send_pkt(struct sk_buff *skb,struct sock*sk,__be32 saddr, __be32 daddr,u16 tcp_len);

#endif
