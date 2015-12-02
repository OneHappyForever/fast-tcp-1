/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the AF_INET socket handler.
 *
 * Version:	@(#)sock.h	1.0.4	05/13/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche <flla@stud.uni-sb.de>
 *
 * Fixes:
 *		Alan Cox	:	Volatiles in skbuff pointers. See
 *					skbuff comments. May be overdone,
 *					better to prove they can be removed
 *					than the reverse.
 *		Alan Cox	:	Added a zapped field for tcp to note
 *					a socket is reset and must stay shut up
 *		Alan Cox	:	New fields for options
 *	Pauline Middelink	:	identd support
 *		Alan Cox	:	Eliminate low level recv/recvfrom
 *		David S. Miller	:	New socket lookup architecture.
 *              Steve Whitehouse:       Default routines for sock_ops
 *              Arnaldo C. Melo :	removed net_pinfo, tp_pinfo and made
 *              			protinfo be just a void pointer, as the
 *              			protocol specific parts were moved to
 *              			respective headers and ipv4/v6, etc now
 *              			use private slabcaches for its socks
 *              Pedro Hortas	:	New flags field for socket options
 *
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
* @file 			sock.h
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/ 

#ifndef _US_SOCK_H
#define _US_SOCK_H

#include "types.h"
#include "list.h"
#include "bitops.h"
#include "skbuff.h"
#include "ktime.h"
#include "net.h"
#include "tcp_metrics.h"
#include "atomic.h"
#include "us_timer.h"
#include "us_memobj_slab.h"

#define SHUTDOWN_MASK	3
#define RCV_SHUTDOWN	1
#define SEND_SHUTDOWN	2


typedef __u32 __bitwise __portpair;
typedef __u64 __bitwise __addrpair;


struct sock;
struct socket;
struct msghdr;
struct sockaddr ;
struct request_sock_ops;
struct timewait_sock_ops;
struct inet_hashinfo;

#define GSO_MAX_SIZE		65536			//smallboy:Fix it later;
#define GSO_MAX_SEGS		65532

enum {
	SOCK_WAKE_IO,
	SOCK_WAKE_WAITD,
	SOCK_WAKE_SPACE,
	SOCK_WAKE_URG,
};

/* Sock flags */
enum sock_flags {
	SOCK_DEAD,
	SOCK_DONE,
	SOCK_URGINLINE,
	SOCK_KEEPOPEN,
	SOCK_LINGER,
	SOCK_DESTROY,
	SOCK_BROADCAST,
	SOCK_TIMESTAMP,
	SOCK_ZAPPED,
	SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
	SOCK_DBG, /* %SO_DEBUG setting */
	SOCK_RCVTSTAMP, /* %SO_TIMESTAMP setting */
	SOCK_RCVTSTAMPNS, /* %SO_TIMESTAMPNS setting */
	SOCK_LOCALROUTE, /* route locally only, %SO_DONTROUTE setting */
	SOCK_QUEUE_SHRUNK, /* write queue has been shrunk recently */
	SOCK_MEMALLOC, /* VM depends on this socket for swapping */
	SOCK_TIMESTAMPING_TX_HARDWARE,  /* %SOF_TIMESTAMPING_TX_HARDWARE */
	SOCK_TIMESTAMPING_TX_SOFTWARE,  /* %SOF_TIMESTAMPING_TX_SOFTWARE */
	SOCK_TIMESTAMPING_RX_HARDWARE,  /* %SOF_TIMESTAMPING_RX_HARDWARE */
	SOCK_TIMESTAMPING_RX_SOFTWARE,  /* %SOF_TIMESTAMPING_RX_SOFTWARE */
	SOCK_TIMESTAMPING_SOFTWARE,     /* %SOF_TIMESTAMPING_SOFTWARE */
	SOCK_TIMESTAMPING_RAW_HARDWARE, /* %SOF_TIMESTAMPING_RAW_HARDWARE */
	SOCK_TIMESTAMPING_SYS_HARDWARE, /* %SOF_TIMESTAMPING_SYS_HARDWARE */
	SOCK_FASYNC, /* fasync() active */
	SOCK_RXQ_OVFL,
	SOCK_ZEROCOPY, /* buffers from userspace */
	SOCK_WIFI_STATUS, /* push wifi status to userspace */
	SOCK_NOFCS, /* Tell NIC not to do the Ethernet FCS.
		     * Will use last 4 bytes of packet sent from
		     * user-space instead.
		     */
	SOCK_FILTER_LOCKED, /* Filter cannot be changed anymore */
	SOCK_SELECT_ERR_QUEUE, /* Wake select on error queue */
};





/* Networking protocol blocks we attach to sockets.
 * socket layer -> transport layer interface
 * transport -> network interface is defined by struct inet_proto
 */
struct proto {
	void		(*close)(struct sock *sk,long timeout);
	int			(*connect)(struct sock *sk,struct sockaddr *uaddr,int addr_len);
	int			(*disconnect)(struct sock *sk, int flags);
	struct sock*	(*accept)(struct sock *sk, int flags, int *err);
	//int			(*ioctl)(struct sock *sk, int cmd, unsigned long arg);
	int			(*init)(struct sock *sk);
	void		(*destroy)(struct sock *sk);
	void		(*shutdown)(struct sock *sk, int how);
	int			(*setsockopt)(struct sock *sk, int level,int optname, char __user *optval,unsigned int optlen);
	int			(*getsockopt)(struct sock *sk, int level,int optname,char __user *optval,int __user *option);
				//smallboy: delete compat get/set sockopt;
	int			(*sendmsg)(struct sock *sk,struct msghdr *msg, size_t len);
	int			(*sendv)(struct sock *sk,struct msghdr *msg, size_t len);	
	
	int 		(*recvmsg)(struct socket *skt, char *buf,int len,int flags,int *addr_len);
	int			(*recvv)(struct socket *skt, struct msghdr *msg,int len,int flags,int *addr_len);
	//int			(*recvmsg)(struct sock *sk,struct msghdr *msg,size_t len, int noblock, int flags,int *addr_len);
	//int			(*sendpage)(struct sock *sk, struct page *page,int offset, size_t size, int flags);
	int			(*bind)(struct sock *sk,struct sockaddr *uaddr, int addr_len);
	//int			(*backlog_rcv) (struct sock *sk,struct sk_buff *skb);
	//void		(*release_cb)(struct sock *sk);
	//void		(*mtu_reduced)(struct sock *sk);

	/* Keeping track of sk's, looking them up, and port selection methods. */
	void		(*hash)(struct sock *sk);
	void		(*unhash)(struct sock *sk);
	void		(*rehash)(struct sock *sk);
	int			(*get_port)(struct sock *sk, unsigned short snum);
	void		(*clear_sk)(struct sock *sk, int size);

//#ifdef CONFIG_PROC_FS
//	unsigned int		inuse_idx; 	/* Keeping track of sockets in use */
//#endif
	//void		(*enter_memory_pressure)(struct sock *sk);  	/* Memory pressure */
	atomic_long_t	memory_allocated;		// Current allocated memory. 
	atomic_long_t	sockets_allocated;		// Current number of sockets. 
	/*
	 * Pressure flag: try to collapse.
	 * Technical note: it is used by multiple contexts non atomically.
	 * All the __sk_mem_schedule() is of this nature: accounting
	 * is strict, actions are advisory and have some latency.
	 */
	int				memory_pressure;
	long			sysctl_mem[3];
	int				sysctl_wmem[3];
	int				sysctl_rmem[3];
	int				max_header;
	bool			no_autobind;	//smallboy:proto is per_lcore;so no pointer at now ; 	

	//struct kmem_cache	*slab;		//smallboy:no slab here;	
	unsigned int	obj_size;
	//int			slab_flags;

	atomic_t		orphan_count;

	struct request_sock_ops	*rsk_prot;
	struct timewait_sock_ops *twsk_prot;

	union {
		struct inet_hashinfo	*hashinfo;
		//struct udp_table		*udp_table;   //smallboy:Not used at now;
		//struct raw_hashinfo	*raw_hash;
	} h;

	//struct module		*owner;		//smallboy:no owner and module here;
	char			name[32];
	struct us_list_head	node;
	atomic_t		socks;
};    //smallboy: all proto is percpu;


/**
 *	struct sock_common - minimal network layer representation of sockets
 *	@skc_daddr: Foreign IPv4 addr
 *	@skc_rcv_saddr: Bound local IPv4 addr
 *	@skc_hash: hash value used with various protocol lookup tables
 *	@skc_u16hashes: two u16 hash values used by UDP lookup tables
 *	@skc_dport: placeholder for inet_dport/tw_dport
 *	@skc_num: placeholder for inet_num/tw_num
 *	@skc_family: network address family
 *	@skc_state: Connection state
 *	@skc_reuse: %SO_REUSEADDR setting
 *	@skc_reuseport: %SO_REUSEPORT setting
 *	@skc_bound_dev_if: bound device index if != 0
 *	@skc_bind_node: bind hash linkage for various protocol lookup tables
 *	@skc_portaddr_node: second hash linkage for UDP/UDP-Lite protocol
 *	@skc_prot: protocol handlers inside a network family
 *	@skc_net: reference to the network namespace of this socket
 *	@skc_node: main hash linkage for various protocol lookup tables
 *	@skc_nulls_node: main hash linkage for TCP/UDP/UDP-Lite protocol
 *	@skc_tx_queue_mapping: tx queue number for this connection
 *	@skc_refcnt: reference count
 *
 *	This is the minimal network layer representation of sockets, the header
 *	for struct sock and struct inet_timewait_sock.
 */
struct sock_common {
	// skc_daddr and skc_rcv_saddr must be grouped on a 8 bytes aligned
	// address on 64bit arches : cf INET_MATCH() and INET_TW_MATCH()
	union {
		__addrpair			skc_addrpair;
		struct {
			__be32			skc_daddr;
			__be32			skc_rcv_saddr;
		};
	};
	
	union  {
		unsigned int		skc_hash;
		__u16				skc_u16hashes[2];
	};
	// skc_dport && skc_num must be grouped as well 
	union {
		__portpair			skc_portpair;
		struct {
			__be16			skc_dport;
			__u16			skc_num;
		};
	};

	unsigned short			skc_family;
	volatile unsigned char	skc_state;
	unsigned char			skc_reuse		:4;
	unsigned char			skc_reuseport	:4;
	int						skc_bound_dev_if;
	union {
		struct us_hlist_node		skc_bind_node;
		//struct hlist_nulls_node skc_portaddr_node;	//smallboy: Fix it later;	
	};
	struct proto			*skc_prot;

#ifdef CONFIG_NET_NS
	struct net	 			*skc_net;
#endif

	// fields between dontcopy_begin/dontcopy_end
	//are not copied in sock_copy()

	// private:
	int						skc_dontcopy_begin[0];
	// public: 
	union {
		struct us_hlist_node		skc_node;
		//struct hlist_nulls_node skc_nulls_node;		//samllboy: fixit later;
	};
	//int					skc_tx_queue_mapping;		//smallboy: Not used;
	atomic_t				skc_refcnt;
	int						skc_id;						//smallboy: Add id here,do not copied;
	// private: 
	int                 	skc_dontcopy_end[0];
	// public: 
};


/**
  *	struct sock - network layer representation of sockets
  *	@__sk_common: shared layout with inet_timewait_sock
  *	@sk_shutdown: mask of %SEND_SHUTDOWN and/or %RCV_SHUTDOWN
  *	@sk_userlocks: %SO_SNDBUF and %SO_RCVBUF settings
  *	@sk_lock:	synchronizer
  *	@sk_rcvbuf: size of receive buffer in bytes
  *	@sk_wq: sock wait queue and async head
  *	@sk_rx_dst: receive input route used by early tcp demux
  *	@sk_dst_cache: destination cache
  *	@sk_dst_lock: destination cache lock
  *	@sk_policy: flow policy
  *	@sk_receive_queue: incoming packets
  *	@sk_wmem_alloc: transmit queue bytes committed
  *	@sk_write_queue: Packet sending queue
  *	@sk_async_wait_queue: DMA copied packets
  *	@sk_omem_alloc: "o" is "option" or "other"
  *	@sk_wmem_queued: persistent queue size
  *	@sk_forward_alloc: space allocated forward
  *	@sk_allocation: allocation mode
  *	@sk_pacing_rate: Pacing rate (if supported by transport/packet scheduler)
  *	@sk_sndbuf: size of send buffer in bytes
  *	@sk_flags: %SO_LINGER (l_onoff), %SO_BROADCAST, %SO_KEEPALIVE,
  *		   %SO_OOBINLINE settings, %SO_TIMESTAMPING settings
  *	@sk_no_check: %SO_NO_CHECK setting, whether or not checkup packets
  *	@sk_route_caps: route capabilities (e.g. %NETIF_F_TSO)
  *	@sk_route_nocaps: forbidden route capabilities (e.g NETIF_F_GSO_MASK)
  *	@sk_gso_type: GSO type (e.g. %SKB_GSO_TCPV4)
  *	@sk_gso_max_size: Maximum GSO segment size to build
  *	@sk_gso_max_segs: Maximum number of GSO segments
  *	@sk_lingertime: %SO_LINGER l_linger setting
  *	@sk_backlog: always used with the per-socket spinlock held
  *	@sk_callback_lock: used with the callbacks in the end of this struct
  *	@sk_error_queue: rarely used
  *	@sk_prot_creator: sk_prot of original sock creator (see ipv6_setsockopt,
  *			  IPV6_ADDRFORM for instance)
  *	@sk_err: last error
  *	@sk_err_soft: errors that don't cause failure but are the cause of a
  *		      persistent failure not just 'timed out'
  *	@sk_drops: raw/udp drops counter
  *	@sk_ack_backlog: current listen backlog
  *	@sk_max_ack_backlog: listen backlog set in listen()
  *	@sk_priority: %SO_PRIORITY setting
  *	@sk_cgrp_prioidx: socket group's priority map index
  *	@sk_type: socket type (%SOCK_STREAM, etc)
  *	@sk_protocol: which protocol this socket belongs in this network family
  *	@sk_peer_pid: &struct pid for this socket's peer
  *	@sk_peer_cred: %SO_PEERCRED setting
  *	@sk_rcvlowat: %SO_RCVLOWAT setting
  *	@sk_rcvtimeo: %SO_RCVTIMEO setting
  *	@sk_sndtimeo: %SO_SNDTIMEO setting
  *	@sk_rxhash: flow hash received from netif layer
  *	@sk_filter: socket filtering instructions
  *	@sk_protinfo: private area, net family specific, when not using slab
  *	@sk_timer: sock cleanup timer
  *	@sk_stamp: time stamp of last packet received
  *	@sk_socket: Identd and reporting IO signals
  *	@sk_user_data: RPC layer private data
  *	@sk_frag: cached page frag
  *	@sk_peek_off: current peek_offset value
  *	@sk_send_head: front of stuff to transmit
  *	@sk_security: used by security modules
  *	@sk_mark: generic packet mark
  *	@sk_classid: this socket's cgroup classid
  *	@sk_cgrp: this socket's cgroup-specific proto data
  *	@sk_write_pending: a write to stream socket waits to start
  *	@sk_state_change: callback to indicate change in the state of the sock
  *	@sk_data_ready: callback to indicate there is data to be processed
  *	@sk_write_space: callback to indicate there is bf sending space available
  *	@sk_error_report: callback to indicate errors (e.g. %MSG_ERRQUEUE)
  *	@sk_backlog_rcv: callback to process the backlog
  *	@sk_destruct: called at sock freeing time, i.e. when all refcnt == 0
 */
struct sock {

	 // Now struct inet_timewait_sock also uses sock_common, so please just
	 // don't add nothing before this first member (__sk_common) --acme

	struct sock_common		__sk_common;
#define sk_node				__sk_common.skc_node
//#define sk_nulls_node		__sk_common.skc_nulls_node
#define sk_refcnt			__sk_common.skc_refcnt
//#define sk_tx_queue_mapping	__sk_common.skc_tx_queue_mapping

#define sk_dontcopy_begin	__sk_common.skc_dontcopy_begin
#define sk_dontcopy_end		__sk_common.skc_dontcopy_end
#define sk_hash				__sk_common.skc_hash
#define sk_family			__sk_common.skc_family
#define sk_state			__sk_common.skc_state
#define sk_reuse			__sk_common.skc_reuse
#define sk_reuseport		__sk_common.skc_reuseport
#define sk_bound_dev_if		__sk_common.skc_bound_dev_if
#define sk_bind_node		__sk_common.skc_bind_node
#define sk_prot				__sk_common.skc_prot
#define sk_net				__sk_common.skc_net
#define sk_id				__sk_common.skc_id
	//socket_lock_t			sk_lock;		//smallboy: no lock anymore anywhere anytime;
	struct sk_buff_head		sk_receive_queue;

	//struct {								//smallboy: one receive_queue is enough;									
	//	atomic_t	rmem_alloc;
	//	int		len;
	//	struct sk_buff	*head;
	//	struct sk_buff	*tail;
	//} sk_backlog;
//#define sk_rmem_alloc sk_backlog.rmem_alloc
//#ifdef CONFIG_RPS							//smallboy: no rps,rfs,xps too;
//	__u32			sk_rxhash;
//#endif
	//struct sk_filter __rcu	*sk_filter;	//smallboy: no sk_filter now && no waitq also;
	//struct socket_wq __rcu	*sk_wq;
//#ifdef CONFIG_NET_DMA
//	struct sk_buff_head	sk_async_wait_queue;
//#endif	
//#ifdef CONFIG_XFRM						//smallboy: netfilter and xfrm are deleted ;
//	struct xfrm_policy	*sk_policy[2];
//#endif	
//	struct dst_entry		*sk_rx_dst; 	//smallboy: dst cache system is deleted too;
//	struct dst_entry __rcu	*sk_dst_cache;
//	spinlock_t		sk_dst_lock;

	int						sk_forward_alloc;
	atomic_t				sk_drops;
	int						sk_rcvbuf;

	unsigned long 			sk_flags;		//get/setsockopt;
	int						sk_rmem_alloc;  
	int						sk_wmem_alloc;	//alloc but not queued;	free when skb free; truesize == size;
	//atomic_t				sk_wmem_alloc;
	//atomic_t				sk_omem_alloc;	//smallboy : sk_omem_all ??
	int						sk_sndbuf;
	
	struct sk_buff_head		sk_write_queue;
	//struct sk_buff_head		sk_cache_head;
	//kmemcheck_bitfield_begin(flags);
	unsigned int			sk_shutdown  : 2,
							sk_no_check  : 2,
							sk_userlocks : 4,
							sk_protocol  : 8,
							sk_type      : 16;
	unsigned short			sk_skb_rcv_num;
	unsigned short			sk_skb_snd_num;
	//kmemcheck_bitfield_end(flags);
	
	int						sk_wmem_queued;		//smallboy: queued in write queue but not send out; 
												// free when ack;	truesize == size;													
	//gfp_t					sk_allocation;		// smallboy: No memcached here;
	u32						sk_pacing_rate; 	// bytes per second 

	//netdev_features_t	sk_route_caps;			// smallboy: vlan;csum;
	//netdev_features_t	sk_route_nocaps;
	int						sk_gso_type;		// tcpv4 or tcpv6;
	unsigned int			sk_gso_max_size;
	u16						sk_gso_max_segs;
	int						sk_rcvlowat;		// default 1 here;
	unsigned long	        sk_lingertime;		// ??
	//struct sk_buff_head	sk_error_queue;		// smallboy: no error_queue;
	//rwlock_t				sk_callback_lock;	// smallboy: no callback here;
	struct proto			*sk_prot_creator;
	struct tcp_metrics_block *sk_tcpm;
	int						sk_err,
							sk_err_soft;		// smallboy: ????	
	unsigned short			sk_ack_backlog;		// smallboy: ????
	unsigned short			sk_max_ack_backlog;	// smallboy: ????
	__u32					sk_priority;		// smallboy: ????
//#if IS_ENABLED(CONFIG_NETPRIO_CGROUP)
//	__u32			sk_cgrp_prioidx;			// smallboy: no cgroup anymore;
//#endif
//	struct pid		*sk_peer_pid;				// smallboy: no any sk peer ; all in the tcp_metric;
//	const struct cred	*sk_peer_cred;
	long					sk_rcvtimeo;
	long					sk_sndtimeo;		// smallboy: reserved; always non-block in ustack;
	//void					*sk_protinfo;
	struct us_timer_list	sk_timer;
	ktime_t					sk_stamp;		// smallboy: fix it later;
	struct socket			*sk_socket;
	void					*sk_user_data;
//	struct page_frag		sk_frag;			// smallboy: not used;
	struct sk_buff			*sk_send_head;
	__s32					sk_peek_off;
//	int						sk_write_pending;	
//#ifdef CONFIG_SECURITY						// smallboy: no firewall no security;
//	void			*sk_security;
//#endif
//	__u32			sk_mark;					// smallboy: no route and no iptables;
//	u32						sk_classid;
//	struct cg_proto			*sk_cgrp;
	void			(*sk_state_change)(struct sock *sk);
	void			(*sk_data_ready)(struct sock *sk, int bytes);
	void			(*sk_write_space)(struct sock *sk);
	void			(*sk_error_report)(struct sock *sk);
//	int				(*sk_backlog_rcv)(struct sock *sk,struct sk_buff *skb);	//smallboy: not used anymore;
	void            (*sk_destruct)(struct sock *sk);
};

#define SOCK_SNDBUF_LOCK	1
#define SOCK_RCVBUF_LOCK	2
#define SOCK_BINDADDR_LOCK	4
#define SOCK_BINDPORT_LOCK	8

/*
 * SK_CAN_REUSE and SK_NO_REUSE on a socket mean that the socket is OK
 * or not whether his port will be reused by someone else. SK_FORCE_REUSE
 * on a socket means that the socket will reuse everybody else's port
 * without looking at the other's sk_reuse value.
 */

#define SK_NO_REUSE		0
#define SK_CAN_REUSE	1
#define SK_FORCE_REUSE	2


#define SOCK_MIN_SNDBUF 2048

#define SK_MEM_SEND	0
#define SK_MEM_RECV	1

/*
 * Since sk_rmem_alloc sums skb->truesize, even a small frame might need
 * sizeof(sk_buff) + MTU + padding, unless net driver perform copybreak
 */
#define SOCK_MIN_RCVBUF (2048 + sizeof(struct sk_buff))


#define sk_for_each(__sk, list) \
	us_hlist_for_each_entry(__sk, list, sk_node)


#define sk_for_each_bound(__sk, list) \
	us_hlist_for_each_entry(__sk, list, sk_bind_node)



extern inline int sock_sendv(struct socket *sock, struct msghdr *msg, size_t size);
extern inline int sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size);
extern void sk_reset_timer(struct sock *sk, struct us_timer_list* timer,unsigned long expires);
extern void sk_stop_timer(struct sock *sk, struct us_timer_list* timer);
extern int sk_stream_error(struct sock *sk, int flags, int err);

extern struct sock* us_sock_alloc(struct net*pnet);
extern void us_sock_free(struct sock *sk);

extern void sk_free(struct sock *sk);
extern void sk_stream_write_space(struct sock *sk);
extern void sock_init_data(struct socket *skt, struct sock *sk);
extern void release_sock(struct sock *sk);
extern void sock_wfree(struct sk_buff *skb);
extern struct sk_buff *sock_wmalloc(struct sock *sk, unsigned long size, int force,int clone);
extern struct sock *sk_clone_lock(const struct sock *sk);
extern void sock_rfree(struct sk_buff *skb);
extern int sock_getsockopt(struct socket *sock, int level, int optname,
		    char __user *optval, int __user *optlen);
extern int sock_setsockopt(struct socket *sock, int level, int optname,
		    char __user *optval, unsigned int optlen);

extern int sock_common_setsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, unsigned int optlen);
extern int sock_common_getsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, int __user *optlen);

extern inline void sock_graft(struct sock *sk, struct socket *parent);
extern int __sk_mem_schedule(struct sock *sk, int size, int kind);
extern int sock_wake_async(struct sock *sk, int how, int band);
extern void us_sk_event_insert(struct sock *sk,int band);

/*
 *	Recover an error report and clear atomically
 */
static inline int sock_error(struct sock *sk)
{
	int err;
	if (likely(!sk->sk_err))
		return 0;
	err = xchg(&sk->sk_err, 0);
	return -err;
}

static inline bool sk_acceptq_is_full(const struct sock *sk)
{
	return sk->sk_ack_backlog > sk->sk_max_ack_backlog;
}

static inline void sk_add_bind_node(struct sock *sk,struct us_hlist_head *list)
{
	us_hlist_add_head(&sk->sk_bind_node, list);
}

static inline bool sk_can_gso(const struct sock *sk)
{
	//return net_gso_ok(sk->sk_route_caps, sk->sk_gso_type);  //smallboy: Attention later;
	return true;
}

static inline void sk_setup_caps(struct sock *sk)
{
	if (sk_can_gso(sk)) {
		//sk->sk_route_caps |= NETIF_F_SG | NETIF_F_HW_CSUM;
		sk->sk_gso_max_size = GSO_MAX_SIZE;
		sk->sk_gso_max_segs = GSO_MAX_SEGS;
	}
}

static inline void sk_acceptq_removed(struct sock *sk)
{
	sk->sk_ack_backlog--;
}

/* Ungrab socket and destroy it, if it was the last reference. */
static inline void sock_put(struct sock *sk)
{
	if (atomic_dec_and_test(&sk->sk_refcnt))
		sk_free(sk);
}

static inline void sk_set_tcpm(struct sock*sk,struct tcp_metrics_block *tm)
{
	sk->sk_tcpm = tm;
	tm->tcpm_ref_cnt++;
}

static inline void sk_set_socket(struct sock *sk, struct socket *skt)
{
	//sk_tx_queue_clear(sk);
	sk->sk_socket = skt;
}

static inline struct sock *__sk_head(const struct us_hlist_head *head)
{
	return us_hlist_entry(head->first, struct sock, sk_node);
}

static inline struct sock *sk_head(const struct us_hlist_head *head)
{
	return us_hlist_empty(head) ? NULL : __sk_head(head);
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
	__set_bit(flag, &sk->sk_flags);
}

static inline void sock_reset_flag(struct sock *sk, enum sock_flags flag)
{
	__clear_bit(flag, &sk->sk_flags);
}

static inline bool sock_flag(const struct sock *sk, enum sock_flags flag)
{
	return test_bit(flag, &sk->sk_flags);
}

/* Detach socket from process context.
 * Announce socket dead, detach it from wait queue and inode.
 * Note that parent inode held reference count on this struct sock,
 * we do not release it in this function, because protocol
 * probably wants some additional cleanups or even continuing
 * to work with this socket (TCP).
 */
static inline void sock_orphan(struct sock *sk)
{
	//write_lock_bh(&sk->sk_callback_lock);
	sock_set_flag(sk, SOCK_DEAD);
	sk_set_socket(sk, NULL);
	//sk->sk_wq  = NULL;
	//write_unlock_bh(&sk->sk_callback_lock);
}

static inline void sk_stream_moderate_sndbuf(struct sock *sk)
{
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK)) {
		sk->sk_sndbuf = min(sk->sk_sndbuf, sk->sk_wmem_queued >> 1);
		sk->sk_sndbuf = max(sk->sk_sndbuf, SOCK_MIN_SNDBUF);
	}
}

static inline bool sk_has_account(struct sock *sk)
{
	/* return true if protocol supports memory accounting */
	//return !!sk->sk_prot->memory_allocated;
	return false;  //smallboy: fix it later;
}


static inline bool sk_wmem_schedule(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return true;
	return size <= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_SEND);
}


/*
 * Compute minimal free write space needed to queue new packets.
 */
static inline int sk_stream_min_wspace(const struct sock *sk)
{
	return sk->sk_wmem_queued >> 1;
}


static inline void sk_mem_reclaim(struct sock *sk)
{
#if 0			//smallboy: Fix the mem problem later;	
	if (!sk_has_account(sk))
		return;
	if (sk->sk_forward_alloc >= SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk);
#endif	
}

/*
 *	Queue a received datagram if it will fit. Stream and sequenced
 *	protocols can't normally use this as they need to fit buffers in
 *	and play with them.
 *
 *	Inlined as it's very short and called for pretty much every
 *	packet ever received.
 */

static inline void skb_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_wfree;
	/*
	 * We used to take a refcount on sk, but following operation
	 * is enough to guarantee sk_free() wont free this sock until
	 * all in-flight packets are completed
	 */
	atomic_add(skb->truesize, &sk->sk_wmem_alloc);

	//US_DEBUG("TH;%u FUNC:%s truesize;%u skb->id:%u skb->len:%u sk->id:%u  sk_wmem_alloc:%u\n"
	//			,US_GET_LCORE(),__FUNCTION__,skb->truesize,skb->skb_id,skb->len,sk->sk_id,sk->sk_wmem_alloc);
}

static inline long sk_prot_mem_limits(const struct sock *sk, int index)
{
	long *prot = sk->sk_prot->sysctl_mem;
	//if (mem_cgroup_sockets_enabled && sk->sk_cgrp)
	//	prot = sk->sk_cgrp->sysctl_mem;
	return prot[index];
}

static inline u16 sk_skb_rcv_num(struct sock * sk)
{
	return sk->sk_skb_rcv_num;
}

static inline u16 sk_skb_snd_num(struct sock*sk)
{
	return sk->sk_skb_snd_num;
}

static inline long sk_memory_allocated(const struct sock *sk)
{
	struct proto *prot = sk->sk_prot;
	//if (mem_cgroup_sockets_enabled && sk->sk_cgrp)
	//	return memcg_memory_allocated_read(sk->sk_cgrp);

	return atomic_long_read(&prot->memory_allocated);
}


static inline struct sock *skb_steal_sock(struct sk_buff *skb)
{
	if (skb->sk) {
		struct sock *sk = skb->sk;

		skb->destructor = NULL;
		skb->sk = NULL;
		return sk;
	}
	return NULL;
}

static inline struct net *sock_net(const struct sock *sk)
{
	//return read_pnet(&sk->sk_net);
	return sk->sk_net;
}

static inline void sk_acceptq_added(struct sock *sk)
{
	sk->sk_ack_backlog++;
}

static inline void sk_wake_async(struct sock *sk, int how, int band)
{	//US_DEBUG("TH:%u,func;%s\n",US_GET_LCORE(),__FUNCTION__);
	if (sock_flag(sk, SOCK_FASYNC))
		sock_wake_async(sk, how, band);  //sk->sk_socket
}

static inline long sock_rcvtimeo(const struct sock *sk, bool noblock)
{
	return noblock ? 0 : sk->sk_rcvtimeo;
}

static inline int sock_rcvlowat(const struct sock *sk, int waitall, int len)
{
	return (waitall ? len : min_t(int, sk->sk_rcvlowat, len)) ? : 1;
}

//static inline void sk_tx_queue_clear(struct sock *sk)
//{
//	sk->sk_tx_queue_mapping = -1;
//}

static inline void sk_node_init(struct us_hlist_node *node)
{
	node->pprev = NULL;
}

static inline long sock_sndtimeo(const struct sock *sk, bool noblock)
{
	return noblock ? 0 : sk->sk_sndtimeo;
}

/* Grab socket reference count. This operation is valid only
   when sk is ALREADY grabbed f.e. it is found in hash table
   or a list and the lookup is made under lock preventing hash table
   modifications.
 */

static inline void sock_hold(struct sock *sk)
{
	atomic_inc(&sk->sk_refcnt);		//smallboy: fix it later;
}

/* Ungrab socket in the context, which assumes that socket refcnt
   cannot hit zero, f.e. it is true in context of any socketcall.
 */
static inline void __sock_put(struct sock *sk)
{
	atomic_dec(&sk->sk_refcnt); 
	//atomic_dec(&sk->sk_refcnt);      //smallboy: fix it later;
}


static inline void sk_mem_uncharge(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc += size;
}

static inline void sk_wmem_free_skb(struct sock *sk, struct sk_buff *skb,u32 seq,u32 end_seq)
{								
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);	
	sk->sk_wmem_queued -= skb->truesize;
	sk_mem_uncharge(sk, skb->truesize);

	//US_ERR("func:%s sk_id:%u skb_id:%u skb_len:%u skb_snd_num:%u \n"
	//	,__FUNCTION__,sk->sk_id,skb->skb_id,skb->len,sk->sk_skb_snd_num);

	sk->sk_skb_snd_num -= skb->nohdr;

	//US_DEBUG("FUNC:%s sk_wmem_queued:%u truesize:%u skb->len:%u skb->skb_id:%u sk->sk_id:%u mbuf_id:%u mbuf_ref:%u "
	//		  "skb_seq:%u end_seq:%u\n"	
	//			,__FUNCTION__,sk->sk_wmem_queued,skb->truesize,skb->len
	//			,skb->skb_id,sk->sk_id,rte_mbuf_id_read(skb->head),rte_mbuf_ref_read(skb->head)
	//			,seq,end_seq);


	if(skb->destructor)
		skb->destructor(skb);

	if(skb->hdr_len){
		if(skb->nohdr){
			if(skb->used == 0){			//smallboy: mbuf that never be sended out in the write_queue;
				rte_mbuf_ref_set((struct rte_mbuf *)skb->head,1);
			}				

			rte_pktmbuf_free((struct rte_mbuf *)(skb->head));	//smallboy:	sended out by stack or driver;	
			//US_DEBUG("sk_wmem_free_skb skb_id:%u \n",skb->skb_id);
		}else{
			us_buf_slab_free(skb->head);
		}
	}else {
		us_abort(US_GET_LCORE());
	/*	
		if(skb->nohdr){
			if(skb->used == 0){				//smallboy: mbuf that never be sended out in the write_queue;
				rte_mbuf_ref_set((struct rte_mbuf *)skb->head,1);
			}
			rte_pktmbuf_free((struct rte_mbuf *)(skb->head));	//smallboy:	sended out by stack or driver;
		}else{
			//free(skb->head);
			us_buf_slab_free(skb->head);
		}

		us_skb_free(skb);
	*/	
	}
	//__kfree_skb(skb);
}

static inline bool sk_stream_memory_free(const struct sock *sk)
{
	return sk->sk_wmem_queued < sk->sk_sndbuf;
}

static inline int sk_stream_wspace(const struct sock *sk)
{
	return sk->sk_sndbuf - sk->sk_wmem_queued;
}

static inline bool sk_unhashed(const struct sock *sk)
{
	return us_hlist_unhashed(&sk->sk_node);
}

static inline bool sk_hashed(const struct sock *sk)
{
	return !sk_unhashed(sk);
}

static inline void __sk_del_node(struct sock *sk)
{
	__us_hlist_del(&sk->sk_node);
}

/* NB: equivalent to hlist_del_init_rcu */
static inline bool __sk_del_node_init(struct sock *sk)
{
	if (sk_hashed(sk)) {
		__sk_del_node(sk);
		sk_node_init(&sk->sk_node);
		return true;
	}
	return false;
}

static inline void __sk_del_bind_node(struct sock *sk)
{
	__us_hlist_del(&sk->sk_bind_node);
}


static inline void sk_sockets_allocated_dec(struct sock *sk)
{
	//struct proto *prot = sk->sk_prot;

	//if (mem_cgroup_sockets_enabled && sk->sk_cgrp) {
	//	struct cg_proto *cg_proto = sk->sk_cgrp;

	//	for (; cg_proto; cg_proto = parent_cg_proto(prot, cg_proto))
	//		percpu_counter_dec(cg_proto->sockets_allocated);
	//}

	//percpu_counter_dec(prot->sockets_allocated);
	atomic_long_dec(1, &sk->sk_prot->sockets_allocated);
}


static inline void sk_sockets_allocated_inc(struct sock *sk)
{
	//struct proto *prot = sk->sk_prot;
	atomic_long_add(1, &sk->sk_prot->sockets_allocated);
	//percpu_counter_inc(prot->sockets_allocated);
}

static inline void __sk_add_node(struct sock *sk, struct us_hlist_head *list)
{
	us_hlist_add_head(&sk->sk_node, list);
}

static inline bool sk_under_memory_pressure(const struct sock *sk)
{
	return false;
/*	
	if (!sk->sk_prot->memory_pressure)
		return false;

	//if (mem_cgroup_sockets_enabled && sk->sk_cgrp)
	//	return !!*sk->sk_cgrp->memory_pressure;

	return !!*sk->sk_prot->memory_pressure;
*/	
}

static inline void sk_mem_charge(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc -= size;
}

static inline void skb_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_rfree;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, skb->truesize);
	sk->sk_skb_rcv_num++ ;

	//US_ERR("TH:%u,FUNC:%s skb->id:%u skb->len:%u skb->truesize:%u sk->id:%u sk_rmem_alloc:%u rcv_num:%u\n"
	//				,US_GET_LCORE(),__FUNCTION__,skb->skb_id,skb->len,skb->truesize,sk->sk_id,sk->sk_rmem_alloc
	//				,sk->sk_skb_rcv_num);

	
}

static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	__kfree_skb(skb,US_MBUF_FREE_BY_STACK);
}

static inline void sk_skb_debug_p(struct sock *sk,const char *func,int line)
{	
	struct sk_buff	*skb = NULL;
	struct sk_buff	*tmp = NULL;
	
	skb_queue_walk_safe(&sk->sk_receive_queue, skb ,tmp) { 
		US_DEBUG("func:%s,%u skb->id:%u skb->len:%u sk->id:%u \n"
				,func,line,skb->skb_id,skb->len,sk->sk_id);	
	}
	
}

static inline void sk_cache_skb(struct sock *sk, struct sk_buff *skb)
{
	__skb_unlink(skb, &sk->sk_receive_queue);

	if (skb->destructor) {
		skb->destructor(skb);
		skb->destructor = NULL;
	}
	skb->cached = 1;
	//__skb_queue_tail(&sk->sk_cache_head , skb);
	skb->sk = sk;
	//sk_skb_debug_p(sk,NULL,__LINE__);
}

static inline void sock_valbool_flag(struct sock *sk, int bit, int valbool)
{
	if (valbool)
		sock_set_flag(sk, bit);
	else
		sock_reset_flag(sk, bit);
}

/**
 *	__sk_reclaim - reclaim memory_allocated
 *	@sk: socket
 */
static inline void __sk_mem_reclaim(struct sock *sk)			//smallboy:Fix it later;
{
#if 0	
	sk_memory_allocated_sub(sk,
				sk->sk_forward_alloc >> SK_MEM_QUANTUM_SHIFT);
	sk->sk_forward_alloc &= SK_MEM_QUANTUM - 1;

	if (sk_under_memory_pressure(sk) &&
	    (sk_memory_allocated(sk) < sk_prot_mem_limits(sk, 0)))
		sk_leave_memory_pressure(sk);
#endif	
}


static inline void sk_mem_reclaim_partial(struct sock *sk)
{
#if 0	
	if (!sk_has_account(sk))
		return;
	if (sk->sk_forward_alloc > SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk);
#endif	
}

static inline bool sk_skb_rcv_full(struct sock *sk)
{
	struct net *pnet = sock_net(sk);
	return !!(sk->sk_skb_rcv_num >= pnet->n_cfg.sysctl_skb_limit_rcv);
	//return false;
}

static inline bool sk_skb_snd_full(struct sock *sk)
{
	struct net *pnet = sock_net(sk);
	return !!(sk->sk_skb_snd_num >= pnet->n_cfg.sysctl_skb_limit_snd);
}


#endif

