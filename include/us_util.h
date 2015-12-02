/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_util.h
* @brief			function for all the mem init;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/


#ifndef _US_UTIL_H
#define _US_UTIL_H

#include "types.h"
#include "us_rte.h"

enum US_THREAD_TYPE{
	US_THREAD_UNKNOW = 0,
	US_THREAD_MON 	 = 1,
	US_THREAD_RECEIVER = 2,
	US_THREAD_USTACK   = 3,
	US_THREAD_TYPE_MAX,
};

enum US_THREAD_STATE{
	US_THREAD_INIT 		= 0,		//before barrier;
	US_THREAD_RUNING 	= 1,
	US_THREAD_ABORT		= 2,
	US_THREAD_STATE_MAX,
};

typedef struct rte_mbuf* 	us_rte_mbuf_p;
typedef us_rte_mbuf_p 		us_rte_mbuf_a[US_MAX_PKT_BURST]; 

extern u32 ilog2(u32	x);
extern s32 us_fdir_init(u8 portid);
extern inline int mbuf_format_and_send(struct sk_buff *skb, u16 append);
extern inline s32 ip_send_out_batch(struct sk_buff *skb,struct net*pnet);
extern inline void mbuf_rebuild(struct sk_buff *skb ,us_nic_port * port);
extern s32 us_fdir_add(u8 portid , u8 queue_id ,u32 ip_dst_addr);
extern void skb_mbuf_format_recover(struct rte_mbuf *mbuf,u16 trim_len);
extern void skb_build_ip_head(struct sk_buff *skb,struct net *pnet);
//extern struct sk_buff *mbuf_to_skb(struct net *pnet,struct rte_mbuf *mbuf);

extern struct msghdr *msghdr_malloc(unsigned int iov_len,unsigned int iov_size);
extern s32 msghdr_realloc(struct msghdr *msg, int new_iov_len, int new_iov_size);
extern void msghdr_free(struct msghdr *msg,int flag);
extern void *msghdr_append(struct msghdr *msg ,int *len);
extern s32 msghdr_iov_len(struct msghdr *msg );
extern void *msghdr_get_data(struct msghdr*msg, int index, int *len);

extern void th_probe(void);
extern void th_state_debug(void);
extern void us_debug_th_info(struct tcp_info *th_info );
extern void us_debug_tcp_sock_info(void);
extern void dmesg_snmp_all(void);
extern void dmesg_all(const char *caller,int line);;
extern void memobj_dump_all(void);

extern s32 us_check_multithread(void);
extern s32 us_all_lcore_gone(void);
extern void us_check_lcore(void);



//@brief, ustack used only; magic_num == US_MSGHDR_MAGIC;
static inline	bool msghdr_magic_ok(struct msghdr*msg)
{
	return (unsigned long)msg->msg_control == US_MSGHDR_MAGIC ;
}

static inline int is_ipv4_csum_correct_offload(struct rte_mbuf *m)
{
	uint16_t pkt_ol_flags;

	pkt_ol_flags = m->ol_flags;

	return ((pkt_ol_flags & PKT_RX_IP_CKSUM_BAD) == 0);
}

static inline int is_l4_csum_correct_offload(struct rte_mbuf *m)
{
	uint16_t pkt_ol_flags;

	pkt_ol_flags = m->ol_flags;

	return ((pkt_ol_flags & PKT_RX_L4_CKSUM_BAD) == 0);
}


static inline void set_iptcp_csum_offload(struct rte_mbuf *m)
{
	u16 tx_ol_flags;
	u16 pkt_ol_flags;

	pkt_ol_flags = m->ol_flags;
	tx_ol_flags = (u16) (pkt_ol_flags & (~PKT_TX_L4_MASK));

	tx_ol_flags |= PKT_TX_IP_CKSUM;
	tx_ol_flags |= PKT_TX_TCP_CKSUM;

	m->ol_flags = tx_ol_flags;
}

static inline void set_ipv4_csum_offload(struct rte_mbuf *m)
{
	u16 tx_ol_flags;
	u16 pkt_ol_flags;

	pkt_ol_flags = m->ol_flags;
	tx_ol_flags = (u16) (pkt_ol_flags & (~PKT_TX_L4_MASK));

	tx_ol_flags |= PKT_TX_IP_CKSUM;

	m->ol_flags = tx_ol_flags;

	//printf("mmmmmmmmmmmmmmmmmmmmm m->ol_flags =%x:%x",m->ol_flags ,pkt_ol_flags);
}

static inline void mac_copy(void* d, void*s)
{
	uint16_t* dest = (uint16_t*)d;
	uint16_t* src  = (uint16_t*)s;
	*dest++ = *src++;
	*dest++ = *src++;
	*dest++ = *src++;
	return;
}

static inline void swap_mac(void *l2_header)
{
	uint16_t* p=(uint16_t*)l2_header;
	uint16_t tmp;

	tmp    = *p;
	*p     = *(p+3);
	*(p+3) = tmp;

	p++;

	tmp    = *p;
	*p     = *(p+3);
	*(p+3) = tmp;

	p++;

	tmp    = *p;
	*p     = *(p+3);
	*(p+3) = tmp;
}


static inline void swap_arp_ip(uint16_t* src, uint16_t* dest)
{
	uint16_t tmp = *src;
	*src = *dest;
	*dest = tmp;

	src++;
	dest++;

	tmp = *src;
	*src = *dest;
	*dest = tmp;

	return;
}

static inline int different_mac(u8* mac_a, u8* mac_b)
{
	u8 ret = (	(mac_a[0]^mac_b[0])
				|	(mac_a[1]^mac_b[1])
				|	(mac_a[2]^mac_b[2])
				|	(mac_a[3]^mac_b[3])
				|	(mac_a[4]^mac_b[4])
				|	(mac_a[5]^mac_b[5]));
		return (ret!=0);
}

static inline void us_spin_ms(u32 ms )
{
	rte_delay_us(ms*1000);
}

//@brief , return the pointer of mbuf associated with the skb;
//@note  , be called only when the skb->nohdr == 1;
static inline struct rte_mbuf *skb_mbuf(struct sk_buff *skb)
{
	return (struct rte_mbuf*)(skb->head);
}

//@biref  , when receive a mbuf, format a sk_buff struct at it's end;
//@input  , pnet--> the net which hold this mbuf;
//@input  , mbuf--> the pointer of this mbuf;
//@output , return the pointer of this sk_buff;
static inline struct sk_buff *mbuf_to_skb(struct net *pnet,struct rte_mbuf *mbuf, struct ether_hdr	*ethdr)
{	
	//if (skb->pkt_type != PACKET_HOST)						//smallboy: Do not care it here;
	//	goto discard_it;	
	u32 pkt_len ,l4_len,m_l4_len;
	//struct ether_hdr	*ethdr;
	struct sk_buff 		*skb_p;
	const struct iphdr  *iph;

#if 1
	skb_p = (struct sk_buff*)((char *)mbuf->buf_addr + (US_MBUF_LENGTH_MAX - US_SKB_OFFSET) - sizeof(struct sk_buff));
	//skb_p = (struct sk_buff*)((void *)mbuf->buf_addr + sizeof(struct rte_mbuf));
	//ethdr	=  rte_pktmbuf_mtod(mbuf,struct ether_hdr*);
	memset(skb_p,0,sizeof(struct sk_buff));
	pkt_len =  rte_pktmbuf_data_len(mbuf);
	
	skb_p->mac_header = (char*)ethdr;
	skb_p->network_header = (char *) (ethdr + 1);
	
	iph = (struct iphdr*)skb_p->network_header;
	skb_p->head = (char*)mbuf;
	
	if(pkt_len <= sizeof(struct iphdr) +  sizeof(struct ether_hdr)){
		skb_p->len = 0;
		skb_p->transport_header = NULL;
	}else{
		l4_len = ntohs(iph->tot_len) - sizeof(struct iphdr) ;
		m_l4_len = pkt_len - sizeof(struct iphdr) +  sizeof(struct ether_hdr);
		skb_p->len = (l4_len > m_l4_len) ? m_l4_len : l4_len;
		skb_p->transport_header = (((s8*)iph) + ((iph->ihl)<<2));
	}

	skb_p->data = (s8*)skb_p->transport_header;
	skb_p->protocol = iph->protocol;	
	skb_p->truesize = skb_p->len;
	skb_p->pkt_type = PACKET_HOST;
	skb_p->tail 	= skb_p->data + skb_p->len;//ethdr + skb_p->len + skb_p->mac_len;
	skb_p->end		= skb_p->tail;
	skb_p->nohdr	= 1;
	skb_p->skb_iif	= mbuf->pkt.in_port;
	skb_p->users	= 1;
	skb_p->pnet		= pnet;
	skb_p->hdr_len	= 1;
	skb_p->gso_segs = 1;
	skb_p->skb_id	= rte_mbuf_id_read(mbuf);
	//US_DEBUG("mbuf_to_skb skb->id:%u \n",skb_p->skb_id);
	rte_pktmbuf_prepend(mbuf,MAX_TCP_OPTION_SPACE); //reserve MAX_TCP_OPTION_SPACE for zero copy proxy here;
	return skb_p;
	//skb_p->used	= 0;
	//skb_p->cloned	= 0;
	//skb_p->sk		= NULL;
	//skb_p->next		= NULL;
	//skb_p->prev		= NULL;
	
	//skb_p->data_len	= 0;
	//skb_p->mac_len	= 0;

	//skb_p->local_df = 0;
	//skb_p->nf_trace = 0;
	//skb_p->cached	= 0;
	//skb_p->destructor	= NULL;
	//skb_p->vlan_proto	= 0;
	//skb_p->vlan_tci	= 0;
	//skb_p->skb_id	= 0;
	//skb_p->skb_id	= rte_mbuf_id_read(mbuf);
	//skb_p->data_header 		= skb_p->tail_header = NULL;
	//skb_p->delta_csum_len 	= 0;
	//skb_p->gso_size	= 0;
	//skb_p->gso_type = 0;
#else
	
	skb_p = us_skb_alloc();
	if(skb_p == NULL) {
		return NULL;
	}else{
		ethdr	=  rte_pktmbuf_mtod(mbuf,struct ether_hdr*);
		skb_p->mac_header = (char*)ethdr;
		skb_p->network_header = (char *) (ethdr + 1);
		iph =(struct iphdr*)skb_p->network_header;
		skb_p->head = (char*)mbuf;
	}

	skb_p->transport_header = (((s8*)iph) + ((iph->ihl)<<2));
	skb_p->len = ntohs(iph->tot_len) - sizeof(struct iphdr);
	skb_p->data = (s8*)skb_p->transport_header;
	skb_p->protocol = iph->protocol;

	skb_p->truesize = skb_p->len;
	skb_p->pkt_type = PACKET_HOST;
	skb_p->tail 	= skb_p->data + skb_p->len;//ethdr + skb_p->len + skb_p->mac_len;
	skb_p->end		= skb_p->tail ;
	skb_p->nohdr	= 1;
	skb_p->skb_iif	= mbuf->pkt.in_port;
	skb_p->users	= 1;
	skb_p->pnet		= pnet;

	return skb_p;
#endif	
}


#endif
