/*
 *	Definitions for the 'struct sk_buff' memory handlers.
 *
 *	Authors:
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Florian La Roche, <rzsfl@rz.uni-sb.de>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			skbuff.h
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/  

#ifndef _US_SKBUFF_H
#define _US_SKBUFF_H

#include "types.h"
#include "ktime.h"
#include "us_mem.h"
#include "us_error.h"


struct sock;
struct iovec;

/* Packet types */

#define PACKET_HOST			0		/* To us		*/
#define PACKET_BROADCAST	1		/* To all		*/
#define PACKET_MULTICAST	2		/* To group		*/
#define PACKET_OTHERHOST	3		/* To someone else 	*/
#define PACKET_OUTGOING		4		/* Outgoing of any type */
/* These ones are invisible by user level */
#define PACKET_LOOPBACK		5		/* MC/BRD frame looped back */
#define PACKET_FASTROUTE	6		/* Fastrouted frame	*/


enum {
	SKB_GSO_TCPV4 = 1 << 0,
	SKB_GSO_UDP = 1 << 1,

	/* This indicates the skb is from an untrusted source. */
	SKB_GSO_DODGY = 1 << 2,

	/* This indicates the tcp segment has CWR set. */
	SKB_GSO_TCP_ECN = 1 << 3,

	SKB_GSO_TCPV6 = 1 << 4,

	SKB_GSO_FCOE = 1 << 5,

	SKB_GSO_GRE = 1 << 6,

	SKB_GSO_UDP_TUNNEL = 1 << 7,
};


/*
 *	Definitions for the 'struct sk_buff' memory handlers.
 *
 *	Authors:
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Florian La Roche, <rzsfl@rz.uni-sb.de>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

struct sk_buff_head {
	struct sk_buff	*next;
	struct sk_buff	*prev;
	__u32			qlen;
	//spinlock_t	lock;		// smallboy:
};

/** 
 *	struct sk_buff - socket buffer
 *	@next: Next buffer in list
 *	@prev: Previous buffer in list
 *	@tstamp: Time we arrived
 *	@sk: Socket we are owned by
 *	@dev: Device we arrived on/are leaving by
 *	@cb: Control buffer. Free for use by every layer. Put private vars here
 *	@_skb_refdst: destination entry (with norefcount bit)
 *	@sp: the security path, used for xfrm
 *	@len: Length of actual data
 *	@data_len: Data length
 *	@mac_len: Length of link layer header
 *	@hdr_len: writable header length of cloned skb
 *	@csum: Checksum (must include start/offset pair)
 *	@csum_start: Offset from skb->head where checksumming should start
 *	@csum_offset: Offset from csum_start where checksum should be stored
 *	@priority: Packet queueing priority
 *	@local_df: allow local fragmentation
 *	@cloned: Head may be cloned (check refcnt to be sure)
 *	@ip_summed: Driver fed us an IP checksum
 *	@nohdr: Payload reference only, must not modify header
 *	@nfctinfo: Relationship of this skb to the connection
 *	@pkt_type: Packet class
 *	@fclone: skbuff clone status
 *	@ipvs_property: skbuff is owned by ipvs
 *	@peeked: this packet has been seen already, so stats have been
 *		done for it, don't do them again
 *	@nf_trace: netfilter packet trace flag
 *	@protocol: Packet protocol from driver
 *	@destructor: Destruct function
 *	@nfct: Associated connection, if any
 *	@nf_bridge: Saved data about a bridged frame - see br_netfilter.c
 *	@skb_iif: ifindex of device we arrived on
 *	@tc_index: Traffic control index
 *	@tc_verd: traffic control verdict
 *	@rxhash: the packet hash computed on receive
 *	@queue_mapping: Queue mapping for multiqueue devices
 *	@ndisc_nodetype: router type (from link layer)
 *	@ooo_okay: allow the mapping of a socket to a queue to be changed
 *	@l4_rxhash: indicate rxhash is a canonical 4-tuple hash over transport
 *		ports.
 *	@wifi_acked_valid: wifi_acked was set
 *	@wifi_acked: whether frame was acked on wifi or not
 *	@no_fcs:  Request NIC to treat last 4 bytes as Ethernet FCS
 *	@dma_cookie: a cookie to one of several possible DMA operations
 *		done by skb DMA functions
 *	@secmark: security marking
 *	@mark: Generic packet mark
 *	@dropcount: total number of sk_receive_queue overflows
 *	@vlan_proto: vlan encapsulation protocol
 *	@vlan_tci: vlan tag control information
 *	@inner_transport_header: Inner transport layer header (encapsulation)
 *	@inner_network_header: Network layer header (encapsulation)
 *	@inner_mac_header: Link layer header (encapsulation)
 *	@transport_header: Transport layer header
 *	@network_header: Network layer header
 *	@mac_header: Link layer header
 *	@tail: Tail pointer
 *	@end: End pointer
 *	@head: Head of buffer
 *	@data: Data head pointer
 *	@truesize: Buffer size
 *	@users: User count - see {datagram,tcp}.c
 */

struct sk_buff {
	struct sk_buff		*next;
	struct sk_buff		*prev;

	ktime_t				tstamp;

	struct sock			*sk;
	struct net 			*pnet;
	//struct net_device	*dev;		//smallboy: deleted here;

	/*
	 * This is the control buffer. It is free to use for every
	 * layer. Please put your private variables there. If you
	 * want to keep them across layers you have to do a skb_clone()
	 * first. This is owned by whoever has the skb queued ATM.
	 */
	char				cb[48];		//__aligned(8);

//	unsigned long		_skb_refdst;	//smallboy : no ip fragment ,no dst ;

//#ifdef CONFIG_XFRM
//	struct	sec_path	*sp;
//#endif
	unsigned int		len,
						data_len;		//smallboy: reserved now ,always be zero;
	__u16				mac_len,		//smallboy: some delta is writen here;
						hdr_len;		//smallboy: reserved;
	
	//union {							//smallboy: Always be csumed by hardware;	
	//	__wsum		csum;
	//	struct {
	//		__u16	csum_start;
	//		__u16	csum_offset;
	//	};
	//};
//	__u32				priority;
//	__u8				local_df:1,		//smallboy: always be 1;
//						cloned:1,		//smallboy: 0 or 1;
//						ip_summed:2,
//						nohdr:1,		//smallboy: 0 or 1;
//						nfctinfo:3;			
//	__u8				pkt_type:3,		//smallboy:
//						fclone:2,
//						ipvs_property:1,	
//						peeked:1,
//						nf_trace:2;		//smallboy:0,1 or 2; 
	__u8				local_df	:1,
						cloned		:1,
						nohdr		:1,
						nf_trace	:1,
						cached		:1,
						pkt_type	:3;				
						
	__be16				protocol;
	void				(*destructor)(struct sk_buff *skb);
	int					skb_iif;
	
	__be16				vlan_proto;
	__u16				vlan_tci;

	u32					skb_id;

	char				*data_header;
	char				*tail_header;

	char				*transport_header;
	char				*network_header;
	char				*mac_header;
	char				*tail;
	char				*end;
	char				*head;
	char				*data;

	unsigned int		delta_csum_len;
	unsigned int		truesize;
	u16					users;
	u16					used;					
	unsigned short		gso_size;
	unsigned short		gso_segs;
	unsigned short  	gso_type;

//#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
//	struct nf_conntrack	*nfct;
//#endif
//#ifdef CONFIG_BRIDGE_NETFILTER
//	struct nf_bridge_info	*nf_bridge;
//#endif
//	__u32				rxhash;
//#ifdef CONFIG_NET_SCHED
//	__u16			tc_index;	/* traffic control index */
//#ifdef CONFIG_NET_CLS_ACT
//	__u16			tc_verd;	/* traffic control verdict */
//#endif
//#endif

//	__u16			queue_mapping;
//	kmemcheck_bitfield_begin(flags2);
//#ifdef CONFIG_IPV6_NDISC_NODETYPE
//	__u8			ndisc_nodetype:2;
//#endif
//	__u8			pfmemalloc:1;
//	__u8			ooo_okay:1;
//	__u8			l4_rxhash:1;
//	__u8			wifi_acked_valid:1;
//	__u8			wifi_acked:1;
//	__u8			no_fcs:1;
//	__u8			head_frag:1;
	/* Encapsulation protocol and NIC drivers should use
	 * this flag to indicate to each other if the skb contains
	 * encapsulated packet or not and maybe use the inner packet
	 * headers if needed
	 */
//	__u8			encapsulation:1;
	/* 7/9 bit hole (depending on ndisc_nodetype presence) */
//	kmemcheck_bitfield_end(flags2);

//#ifdef CONFIG_NET_DMA
//	dma_cookie_t		dma_cookie;
//#endif
//#ifdef CONFIG_NETWORK_SECMARK
//	__u32			secmark;
//#endif
//	union {
//		__u32		mark;
//		__u32		dropcount;
//		__u32		reserved_tailroom;
//	};

//	sk_buff_data_t		inner_transport_header;
//	sk_buff_data_t		inner_network_header;
//	sk_buff_data_t		inner_mac_header;
//	sk_buff_data_t		transport_header;
//	sk_buff_data_t		network_header;
//	sk_buff_data_t		mac_header;
//	/* These elements must be at the end, see alloc_skb() for details.  */
//	sk_buff_data_t		tail;
//	sk_buff_data_t		end;
//	unsigned char		*head,
//						*data;
//	unsigned int		truesize;
//	atomic_t			users;
};


#define SKB_DATA_ALIGN(X)	(((X) + (SMP_CACHE_BYTES - 1)) & \
									 ~(SMP_CACHE_BYTES - 1))
#define SKB_TRUESIZE(X) ((X) + SKB_DATA_ALIGN(sizeof(struct sk_buff)))		//smallboy:Fix it later;



extern void kfree_skb(struct sk_buff *skb,bool more);
extern void __kfree_skb(struct sk_buff *skb,bool more);
extern struct sk_buff *alloc_skb(struct sock*sk,unsigned int size,int clone);
extern int skb_copy_datagram_iovec(const struct sk_buff *skb, int offset,
			    				struct iovec *to, int len);
extern void skb_copy_datagram(const struct sk_buff *skb, int offset,char *to, int len);
extern void skb_retry_get(struct sk_buff *skb);
extern void skb_retry_put(struct sk_buff *skb);
extern void skb_retry_set(struct sk_buff *skb , s32 num);
extern void skb_reset_data_header(struct sk_buff *skb);
extern char *skb_put(struct sk_buff *skb, unsigned int len);  //unsigned
extern void skb_split(struct sk_buff *skb, struct sk_buff *skb1, const u32 len);
extern int  skb_try_append(struct sk_buff *skb, int mss_now, char*send_data, int data_len);
extern void skb_moveto_datagram_iovec(const struct sk_buff *skb, int offset ,struct iovec *to);


#define skb_queue_walk(queue, skb) \
		for (skb = (queue)->next;					\
		     skb != (struct sk_buff *)(queue);				\
		     skb = skb->next)

#define skb_queue_walk_safe(queue, skb, tmp)					\
		for (skb = (queue)->next, tmp = skb->next;			\
			 skb != (struct sk_buff *)(queue);				\
			 skb = tmp, tmp = skb->next)


#define skb_queue_walk_from(queue, skb)						\
		for (; skb != (struct sk_buff *)(queue);			\
			 skb = skb->next)

#define skb_queue_walk_from_safe(queue, skb, tmp)	\
		for (tmp = skb->next;						\
			 skb != (struct sk_buff *)(queue);				\
			 skb = tmp, tmp = skb->next)
			 




/**
 *	skb_peek_tail - peek at the tail of an &sk_buff_head
 *	@list_: list to peek at
 *
 *	Peek an &sk_buff. Unlike most other operations you _MUST_
 *	be careful with this one. A peek leaves the buffer on the
 *	list and someone else may run off with it. You must hold
 *	the appropriate locks or have a private queue to do this.
 *
 *	Returns %NULL for an empty list or a pointer to the tail element.
 *	The reference count is not incremented and the reference is therefore
 *	volatile. Use with caution.
 */
static inline struct sk_buff *skb_peek_tail(const struct sk_buff_head *list_)
{
	struct sk_buff *skb = list_->prev;

	if (skb == (struct sk_buff *)list_)
		skb = NULL;
	return skb;

}

static inline void skb_reset_tail_pointer(struct sk_buff *skb)
{
	//skb->tail = skb->data - skb->head;
	skb->tail = skb->data;
}

static inline void skb_set_tail_pointer(struct sk_buff *skb, const int offset)
{
	skb_reset_tail_pointer(skb);
	skb->tail += offset;
}

static inline bool skb_is_nonlinear(const struct sk_buff *skb)
{
	return skb->data_len;
}

static inline s32 skb_trim(struct sk_buff *skb, unsigned int len)
{
	struct rte_mbuf *r_mp = NULL;
	if(unlikely(skb_is_nonlinear(skb))){
		return US_EINVAL;
	}

	if(skb->nohdr){
		r_mp = (struct rte_mbuf*)skb->head;
		if(skb->len < len || rte_pktmbuf_data_len(r_mp) < len)
			return US_EINVAL;

		if(rte_pktmbuf_trim(r_mp, len - rte_pktmbuf_data_len(r_mp)) < 0)
			return US_EINVAL;
		
		skb->len = len;
		skb_set_tail_pointer(skb, len);

		return US_RET_OK;
	}else{
		if(skb->len < len)
			return US_EINVAL;
		skb->len = len;
		skb_set_tail_pointer(skb, len);
		return US_RET_OK;
	}
	
}

static inline void __skb_trim(struct sk_buff *skb, unsigned int len)
{
	if (unlikely(skb_is_nonlinear(skb))) {
		//WARN_ON(1);
		return;
	}
	skb->len = len;
	skb_set_tail_pointer(skb, len);
}

static inline int __pskb_trim(struct sk_buff *skb, unsigned int len)
{
	//if (skb->data_len)
	//	return ___pskb_trim(skb, len);
	__skb_trim(skb, len);
	return 0;
}

static inline int pskb_trim(struct sk_buff *skb, unsigned int len)
{
	return (len < skb->len) ? __pskb_trim(skb, len) : 0;
}

static inline void __net_timestamp(struct sk_buff *skb)
{
	skb->tstamp = ktime_get_real();
}

/**
 *	skb_queue_is_first - check if skb is the first entry in the queue
 *	@list: queue head
 *	@skb: buffer
 *
 *	Returns true if @skb is the first buffer on the list.
 */
static inline bool skb_queue_is_first(const struct sk_buff_head *list,
				      const struct sk_buff *skb)
{
	return skb->prev == (struct sk_buff *)list;
}


static inline void __skb_insert(struct sk_buff *newsk,
				struct sk_buff *prev, struct sk_buff *next,
				struct sk_buff_head *list)
{
	newsk->next = next;
	newsk->prev = prev;
	next->prev  = prev->next = newsk;
	list->qlen++;
}


/**
 *	__skb_queue_after - queue a buffer at the list head
 *	@list: list to use
 *	@prev: place after this buffer
 *	@newsk: buffer to queue
 *
 *	Queue a buffer int the middle of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */
static inline void __skb_queue_after(struct sk_buff_head *list,
				     struct sk_buff *prev,
				     struct sk_buff *newsk)
{
	__skb_insert(newsk, prev, prev->next, list);
}


/**
 *	__skb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the start of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */
extern void skb_queue_head(struct sk_buff_head *list, struct sk_buff *newsk);
static inline void __skb_queue_head(struct sk_buff_head *list,
				    struct sk_buff *newsk)
{
	__skb_queue_after(list, (struct sk_buff *)list, newsk);
}

static inline void skb_reset_network_header(struct sk_buff *skb)
{
	skb->network_header = skb->data;
}

static inline void __skb_queue_before(struct sk_buff_head *list,
				      struct sk_buff *next,
				      struct sk_buff *newsk)
{
	__skb_insert(newsk, next->prev, next, list);
}


static inline void __skb_queue_tail(struct sk_buff_head *list,struct sk_buff *newskb)
{
	__skb_queue_before(list, (struct sk_buff *)list, newskb);
}


/**
 *	__skb_queue_head_init - initialize non-spinlock portions of sk_buff_head
 *	@list: queue to initialize
 *
 *	This initializes only the list and queue length aspects of
 *	an sk_buff_head object.  This allows to initialize the list
 *	aspects of an sk_buff_head without reinitializing things like
 *	the spinlock.  It can also be used for on-stack sk_buff_head
 *	objects where the spinlock is known to not be used.
 */
static inline void __skb_queue_head_init(struct sk_buff_head *list)
{
	list->prev = list->next = (struct sk_buff *)list;
	list->qlen = 0;
}

/**
 *	skb_queue_empty - check if a queue is empty
 *	@list: queue head
 *
 *	Returns true if the queue is empty, false otherwise.
 */
static inline int skb_queue_empty(const struct sk_buff_head *list)
{
	return list->next == (struct sk_buff *)list;
}


/*
 * This function creates a split out lock class for each invocation;
 * this is needed for now since a whole lot of users of the skb-queue
 * infrastructure in drivers have different locking usage (in hardirq)
 * than the networking core (in softirq only). In the long run either the
 * network layer or drivers should need annotation to consolidate the
 * main types of usage into 3 classes.
 */
static inline void skb_queue_head_init(struct sk_buff_head *list)
{
	//spin_lock_init(&list->lock);
	__skb_queue_head_init(list);
}

static inline void skb_reset_transport_header(struct sk_buff *skb)
{
	skb->transport_header = skb->data ;
}

/*
static inline u16 skb_get_queue_mapping(const struct sk_buff *skb)
{
	return skb->queue_mapping;
}

static inline void skb_set_queue_mapping(struct sk_buff *skb, u16 queue_mapping)
{
	skb->queue_mapping = queue_mapping;
}*/

/**
 *	skb_peek - peek at the head of an &sk_buff_head
 *	@list_: list to peek at
 *
 *	Peek an &sk_buff. Unlike most other operations you _MUST_
 *	be careful with this one. A peek leaves the buffer on the
 *	list and someone else may run off with it. You must hold
 *	the appropriate locks or have a private queue to do this.
 *
 *	Returns %NULL for an empty list or a pointer to the head element.
 *	The reference count is not incremented and the reference is therefore
 *	volatile. Use with caution.
 */
static inline struct sk_buff *skb_peek(const struct sk_buff_head *list_)
{
	struct sk_buff *skb = list_->next;

	if (skb == (struct sk_buff *)list_)
		skb = NULL;
	return skb;
}

static inline void __skb_unlink(struct sk_buff *skb, struct sk_buff_head *list)
{
	struct sk_buff *next, *prev;

	list->qlen--;
	next	   = skb->next;
	prev	   = skb->prev;
	skb->next  = skb->prev = NULL;
	next->prev = prev;
	prev->next = next;
}

/**
 *	__skb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. This function does not take any locks
 *	so must be used with appropriate locks held only. The head item is
 *	returned or %NULL if the list is empty.
 */
extern struct sk_buff *skb_dequeue(struct sk_buff_head *list);
static inline struct sk_buff *__skb_dequeue(struct sk_buff_head *list)
{
	struct sk_buff *skb = skb_peek(list);
	if (skb)
		__skb_unlink(skb, list);
	return skb;
}

/**
 *	__skb_queue_purge - empty a list
 *	@list: list to empty
 *
 *	Delete all buffers on an &sk_buff list. Each buffer is removed from
 *	the list and one reference dropped. This function does not take the
 *	list lock and the caller must hold the relevant locks to use it.
 */
extern void skb_queue_purge(struct sk_buff_head *list);
static inline void __skb_queue_purge(struct sk_buff_head *list)
{
	struct sk_buff *skb;
	while ((skb = __skb_dequeue(list)) != NULL)			
		kfree_skb(skb,US_MBUF_FREE_BY_STACK);	//	kfree_skb(skb);	//smallboy:Attention here;						
												//1 // 1: all sk_receive_queue is not cloned and nohdr == 1;
}												// 2: all ofo queue if not cloned and nohdr == 1;

/**
 *	skb_availroom - bytes at buffer end
 *	@skb: buffer to check
 *
 *	Return the number of bytes of free space at the tail of an sk_buff
 *	allocated by sk_stream_alloc()
 */
static inline int skb_availroom(const struct sk_buff *skb)
{
	if (skb_is_nonlinear(skb))
		return 0;

	//return skb->end - skb->tail - skb->reserved_tailroom;
	return skb->end - skb->tail ;
}

/**
 *	skb_queue_is_last - check if skb is the last entry in the queue
 *	@list: queue head
 *	@skb: buffer
 *
 *	Returns true if @skb is the last buffer on the list.
 */
static inline bool skb_queue_is_last(const struct sk_buff_head *list,
				     const struct sk_buff *skb)
{
	return skb->next == (struct sk_buff *)list;
}

/**
 *	skb_queue_next - return the next packet in the queue
 *	@list: queue head
 *	@skb: current buffer
 *
 *	Return the next packet in @list after @skb.  It is only valid to
 *	call this if skb_queue_is_last() evaluates to false.
 */
static inline struct sk_buff *skb_queue_next(const struct sk_buff_head *list,
					     const struct sk_buff *skb)
{
	/* This BUG_ON may seem severe, but if we just return then we
	 * are going to dereference garbage.
	 */
	//BUG_ON(skb_queue_is_last(list, skb));
	return skb->next;
}

static inline char *skb_transport_header(const struct sk_buff *skb)
{
	return skb->transport_header;
}

static inline  char *skb_network_header(const struct sk_buff *skb)  //unsigned char *
{
	return skb->network_header;
}

static inline  char *skb_mac_header(const struct sk_buff *skb)
{
	return skb->mac_header;
}

static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
	return skb->len - skb->data_len;			//smallboy: data_len be 0 always;
}

static inline  char *skb_tail_pointer(const struct sk_buff *skb) //unsigned
{
	return skb->tail;
}

/**
 *	skb_reserve - adjust headroom
 *	@skb: buffer to alter
 *	@len: bytes to move
 *
 *	Increase the headroom of an empty &sk_buff by reducing the tail
 *	room. This is only allowed for an empty buffer.
 */
static inline void skb_reserve(struct sk_buff *skb, int len)
{
	skb->data += len;
	skb->tail += len;
}

/**
 *	skb_cloned - is the buffer a clone
 *	@skb: buffer to check
 *
 *	Returns true if the buffer was generated with skb_clone() and is
 *	one of multiple shared copies of the buffer. Cloned buffers are
 *	shared data so must not be written to under normal circumstances.
 */
static inline int skb_cloned(const struct sk_buff *skb)
{
	//return skb->cloned &&
	 //      (atomic_read(&skb_shinfo(skb)->dataref) & SKB_DATAREF_MASK) != 1;
	return skb->cloned;
}

static inline int pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
	//smallboy: we do not use the data_len of skb;
	if(likely(len <=  skb_headlen(skb))){
		return 1;
	}else{
		return 0;
	}
	
	//if (likely(len <= skb_headlen(skb)))				
	//	return 1;
	//if (unlikely(len > skb->len))
	//	return 0;
	//return __pskb_pull_tail(skb, len - skb_headlen(skb)) != NULL;
}

static inline int inet_iif(const struct sk_buff *skb)
{
	//int iif = skb_rtable(skb)->rt_iif;
	//if (iif)
	//	return iif;
	return skb->skb_iif;			
}

/**
 *	skb_orphan - orphan a buffer
 *	@skb: buffer to orphan
 *
 *	If a buffer currently has an owner then we call the owner's
 *	destructor function and make the @skb unowned. The buffer continues
 *	to exist but is no longer charged to its former owner.
 */
static inline void skb_orphan(struct sk_buff *skb)
{
	if (skb->destructor)
		skb->destructor(skb);
	skb->destructor = NULL;
	skb->sk		= NULL;
}

/**
 *	skb_push - add data to the start of a buffer
 *	@skb: buffer to use
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer at the buffer
 *	start. If this would exceed the total buffer headroom the kernel will
 *	panic. A pointer to the first byte of the extra data is returned.
 */
static inline char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data -= len;
	skb->len  += len;
	//if (unlikely(skb->data<skb->head))
	//	skb_under_panic(skb, len, __builtin_return_address(0));
	return skb->data;
}

extern  char *skb_pull(struct sk_buff *skb, unsigned int len);  //unsigned
static inline  char *__skb_pull(struct sk_buff *skb, unsigned int len) //unsigned
{
	skb->len -= len;
	//BUG_ON(skb->len < skb->data_len);
	return skb->data += len;
}

static inline bool skb_can_gso(const struct sk_buff *skb)
{
	//return skb_shinfo(skb)->gso_size;
	return skb->gso_size;	//yeah ,while not zero;
}


/**
 *	skb_queue_prev - return the prev packet in the queue
 *	@list: queue head
 *	@skb: current buffer
 *
 *	Return the prev packet in @list before @skb.  It is only valid to
 *	call this if skb_queue_is_first() evaluates to false.
 */
static inline struct sk_buff *skb_queue_prev(const struct sk_buff_head *list,
					     const struct sk_buff *skb)
{
	/* This BUG_ON may seem severe, but if we just return then we
	 * are going to dereference garbage.
	 */
	//BUG_ON(skb_queue_is_first(list, skb));
	return skb->prev;
}

static inline ktime_t net_invalid_timestamp(void)
{
	return ktime_set(0, 0);
}

static inline int skb_unclone(struct sk_buff *skb)  //, gfp_t pri
{
	return !skb->cloned;
#if 0	
	might_sleep_if(pri & __GFP_WAIT);

	if (skb_cloned(skb))
		return pskb_expand_head(skb, 0, 0, pri);

	return 0;
#endif	
}


static inline struct sk_buff* us_skb_alloc(void)
{
	us_abort(US_GET_LCORE());
	s32 ret,skb_id;
	struct sk_buff	*skb;
	ret = us_slab_get(US_PER_LCORE(sk_head_pool),(void**)&skb);
	if(ret < 0){
		return NULL;
	}else{
		skb_id = skb->skb_id;
		memset(skb,0,sizeof(*skb));
		skb->skb_id = skb_id;
		return skb;
	}
}

static inline void us_skb_free(struct sk_buff	*skb)
{
	us_abort(US_GET_LCORE());
	if (skb){
		us_slab_free(US_PER_LCORE(sk_head_pool),skb);
	}
}


#endif

