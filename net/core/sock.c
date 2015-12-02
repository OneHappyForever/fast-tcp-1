/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Generic socket support routines. Memory allocators, socket lock/release
 *		handler for protocols to use and generic option handler.
 *
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Alan Cox, <A.Cox@swansea.ac.uk>
 *
 * Fixes:
 *		Alan Cox	: 	Numerous verify_area() problems
 *		Alan Cox	:	Connecting on a connecting socket
 *					now returns an error for tcp.
 *		Alan Cox	:	sock->protocol is set correctly.
 *					and is not sometimes left as 0.
 *		Alan Cox	:	connect handles icmp errors on a
 *					connect properly. Unfortunately there
 *					is a restart syscall nasty there. I
 *					can't match BSD without hacking the C
 *					library. Ideas urgently sought!
 *		Alan Cox	:	Disallow bind() to addresses that are
 *					not ours - especially broadcast ones!!
 *		Alan Cox	:	Socket 1024 _IS_ ok for users. (fencepost)
 *		Alan Cox	:	sock_wfree/sock_rfree don't destroy sockets,
 *					instead they leave that for the DESTROY timer.
 *		Alan Cox	:	Clean up error flag in accept
 *		Alan Cox	:	TCP ack handling is buggy, the DESTROY timer
 *					was buggy. Put a remove_sock() in the handler
 *					for memory when we hit 0. Also altered the timer
 *					code. The ACK stuff can wait and needs major
 *					TCP layer surgery.
 *		Alan Cox	:	Fixed TCP ack bug, removed remove sock
 *					and fixed timer/inet_bh race.
 *		Alan Cox	:	Added zapped flag for TCP
 *		Alan Cox	:	Move kfree_skb into skbuff.c and tidied up surplus code
 *		Alan Cox	:	for new sk_buff allocations wmalloc/rmalloc now call alloc_skb
 *		Alan Cox	:	kfree_s calls now are kfree_skbmem so we can track skb resources
 *		Alan Cox	:	Supports socket option broadcast now as does udp. Packet and raw need fixing.
 *		Alan Cox	:	Added RCVBUF,SNDBUF size setting. It suddenly occurred to me how easy it was so...
 *		Rick Sladkey	:	Relaxed UDP rules for matching packets.
 *		C.E.Hawkins	:	IFF_PROMISC/SIOCGHWADDR support
 *	Pauline Middelink	:	identd support
 *		Alan Cox	:	Fixed connect() taking signals I think.
 *		Alan Cox	:	SO_LINGER supported
 *		Alan Cox	:	Error reporting fixes
 *		Anonymous	:	inet_create tidied up (sk->reuse setting)
 *		Alan Cox	:	inet sockets don't set sk->type!
 *		Alan Cox	:	Split socket option code
 *		Alan Cox	:	Callbacks
 *		Alan Cox	:	Nagle flag for Charles & Johannes stuff
 *		Alex		:	Removed restriction on inet fioctl
 *		Alan Cox	:	Splitting INET from NET core
 *		Alan Cox	:	Fixed bogus SO_TYPE handling in getsockopt()
 *		Adam Caldwell	:	Missing return in SO_DONTROUTE/SO_DEBUG code
 *		Alan Cox	:	Split IP from generic code
 *		Alan Cox	:	New kfree_skbmem()
 *		Alan Cox	:	Make SO_DEBUG superuser only.
 *		Alan Cox	:	Allow anyone to clear SO_DEBUG
 *					(compatibility fix)
 *		Alan Cox	:	Added optimistic memory grabbing for AF_UNIX throughput.
 *		Alan Cox	:	Allocator for a socket is settable.
 *		Alan Cox	:	SO_ERROR includes soft errors.
 *		Alan Cox	:	Allow NULL arguments on some SO_ opts
 *		Alan Cox	: 	Generic socket allocation to make hooks
 *					easier (suggested by Craig Metz).
 *		Michael Pall	:	SO_ERROR returns positive errno again
 *              Steve Whitehouse:       Added default destructor to free
 *                                      protocol private data.
 *              Steve Whitehouse:       Added various other default routines
 *                                      common to several socket families.
 *              Chris Evans     :       Call suser() check last on F_SETOWN
 *		Jay Schulist	:	Added SO_ATTACH_FILTER and SO_DETACH_FILTER.
 *		Andi Kleen	:	Add sock_kmalloc()/sock_kfree_s()
 *		Andi Kleen	:	Fix write_space callback
 *		Chris Evans	:	Security fixes - signedness again
 *		Arnaldo C. Melo :       cleanups, use skb_queue_purge
 *
 * To Fix:
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
* @file 			sock.c
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/ 


#include "sock.h"
#include "socket.h"
#include "tcp.h"
#include "us_mem.h"
#include "atomic.h"

//#include <arpa/inet.h>

struct net;
//US_DECLARE_PER_LCORE(us_netio_evb *,evb);

#define SK_FLAGS_TIMESTAMP ((1UL << SOCK_TIMESTAMP) | (1UL << SOCK_TIMESTAMPING_RX_SOFTWARE))


void sk_reset_timer(struct sock *sk, struct us_timer_list* timer,unsigned long expires)
{
	if (!us_mod_timer(timer, expires))			//smallboy: check timer later;
		sock_hold(sk);
}

void sk_stop_timer(struct sock *sk, struct us_timer_list* timer)
{
	if (us_del_timer(timer))
		__sock_put(sk);
}

int sk_stream_error(struct sock *sk, int flags, int err)
{	
	if (err == -EPIPE)
		err = sock_error(sk) ? : -EPIPE;
	
	if (err == -EPIPE && !(flags & MSG_NOSIGNAL))
		 sk->sk_error_report(sk);//send_sig(SIGPIPE, current, 0);
	return err;
}

/*
 * Read buffer destructor automatically called from kfree_skb.
 */
void sock_rfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	unsigned int len = skb->truesize;

	//US_DEBUG("func:%s skb->id:%u sk:%p \n",__FUNCTION__,skb->skb_id,sk);

	atomic_sub(len, &sk->sk_rmem_alloc);
	sk_mem_uncharge(sk, len);
	sk->sk_skb_rcv_num--;

	//US_ERR("TH:%u,FUNC:%s skb->id:%u skb->len:%u skb->truesize:%u sk->id:%u sk_rmem_alloc:%u rcv_num:%u\n"
	//			,US_GET_LCORE(),__FUNCTION__,skb->skb_id,skb->len,skb->truesize,sk->sk_id,sk->sk_rmem_alloc
	//			,sk->sk_skb_rcv_num);
}


/*
 *	Default Socket Callbacks
 */

static void sock_def_wakeup(struct sock *sk)
{
	//smallboy: Only one thread,No schedule,no sleep;
	//US_ERR("TH:%d,should not be there!%s\n",US_GET_LCORE(),__FUNCTION__);
/*	
	struct socket_wq *wq;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq_has_sleeper(wq))
		wake_up_interruptible_all(&wq->wait);
	rcu_read_unlock();
*/
}

static void sock_def_readable(struct sock *sk, int len)
{
//smallboy: Fix it later;	  Why  SOCK_FASYNC ?? why SOCK_WAKE_IO ??
	//if (sock_flag(sk, SOCK_FASYNC)){						
		sock_wake_async(sk, SOCK_WAKE_IO, US_POLL_IN);
	//}
/*	
	struct socket_wq *wq;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, POLLIN | POLLPRI |
						POLLRDNORM | POLLRDBAND);
	sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
	rcu_read_unlock();
*/
}

static void sock_def_write_space(struct sock *sk)
{
	//smallboy: App should take charge of the reties;
#if 0	
	struct socket_wq *wq;

	rcu_read_lock();

	/* Do not wake up a writer until he can make "significant"
	 * progress.  --DaveM
	 */
	if ((atomic_read(&sk->sk_wmem_alloc) << 1) <= sk->sk_sndbuf) {
		wq = rcu_dereference(sk->sk_wq);
		if (wq_has_sleeper(wq))
			wake_up_interruptible_sync_poll(&wq->wait, POLLOUT |
						POLLWRNORM | POLLWRBAND);

		/* Should agree with poll, otherwise some programs break */
		if (sock_writeable(sk))
			sk_wake_async(sk, SOCK_WAKE_SPACE, POLL_OUT);
	}

	rcu_read_unlock();
#endif	
	us_abort(US_GET_LCORE());
}

static void sock_def_error_report(struct sock *sk)
{
	sk_wake_async(sk, SOCK_WAKE_IO, US_POLL_ERR);
/*
	struct socket_wq *wq;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq_has_sleeper(wq))
		wake_up_interruptible_poll(&wq->wait, POLLERR);
	sk_wake_async(sk, SOCK_WAKE_IO, POLL_ERR);
	rcu_read_unlock();
*/	
}


static void sock_def_destruct(struct sock *sk)
{
#if 0	
	kfree(sk->sk_protinfo);
#endif
}


void sock_init_data(struct socket *skt, struct sock *sk)
{
	 struct net *pnet = sk->sk_net;
	 skb_queue_head_init(&sk->sk_receive_queue);
	 skb_queue_head_init(&sk->sk_write_queue);
//	 skb_queue_head_init(&sk->sk_cache_head);								
//	 skb_queue_head_init(&sk->sk_error_queue);		//Drop all error pkts; No error_queue;

//#ifdef CONFIG_NET_DMA								//smallboy:delete all about NET DMA;
//	 skb_queue_head_init(&sk->sk_async_wait_queue);
//#endif
 
	 sk->sk_send_head	 =	 NULL;
 
	 us_init_timer(&sk->sk_timer,sk->sk_id,TIMER_TYPE_SK);						//smallboy:timer system is simplified;
 
	 //sk->sk_allocation	 =	 GFP_KERNEL;
	 sk->sk_rcvbuf		 =	pnet->n_cfg.sysctl_rmem_default;
	 sk->sk_sndbuf		 =	pnet->n_cfg.sysctl_wmem_default;
	 sk->sk_state		 =	TCP_CLOSE;
	 sk_set_socket(sk, skt);
 
	 sock_set_flag(sk, SOCK_ZAPPED);		//smallboy:????

	 skt->sk	 = sk;
 	 sk->sk_type = skt->type;
	 //if (sock) {							//smallboy:no sock->type;
	//	 sk->sk_type =	 sock->type;
	//	 sk->sk_wq	 =	 sock->wq;
	//	 sock->sk	 =	 sk;
	 //} else
	//	 sk->sk_wq	 =	 NULL;
 
	 //spin_lock_init(&sk->sk_dst_lock);
	 //rwlock_init(&sk->sk_callback_lock);
	 //lockdep_set_class_and_name(&sk->sk_callback_lock,
	//		 af_callback_keys + sk->sk_family,
	//		 af_family_clock_key_strings[sk->sk_family]);
 
	 sk->sk_state_change =	 sock_def_wakeup;
	 sk->sk_data_ready	 =	 sock_def_readable;
	 sk->sk_write_space  =	 sock_def_write_space;
	 sk->sk_error_report =	 sock_def_error_report;
	 sk->sk_destruct	 =	 sock_def_destruct;
 
	 //sk->sk_frag.page	 =	 NULL;
	 //sk->sk_frag.offset  =	 0;
	 sk->sk_peek_off	 =	 -1;
 
	 //sk->sk_peer_pid	 =	 NULL;
	 //sk->sk_peer_cred	 =	 NULL;
	 //sk->sk_write_pending	 =	 0;
	 sk->sk_rcvlowat	 =	 1;
	 sk->sk_rcvtimeo	 =	 pnet->n_cfg.max_schedule_timeout;	//smallboy:Never be used;
	 sk->sk_sndtimeo	 =	 pnet->n_cfg.max_schedule_timeout;
 
	 sk->sk_stamp = ktime_set(-1L, 0);
 
	 sk->sk_pacing_rate = ~0U;
	 sk->sk_skb_snd_num	= 0;
	 sk->sk_skb_rcv_num = 0;
	 // Before updating sk_refcnt, we must commit prior changes to memory
	 // (Documentation/RCU/rculist_nulls.txt for details)

	 //smp_wmb();
	 atomic_set(&sk->sk_refcnt, 1);
	 atomic_set(&sk->sk_drops, 0);
	 
}

void release_sock(struct sock *sk)
{
	//US_DEBUG("TH:%u,Attention here!\n",US_GET_LCORE());	
	//if (sk->sk_prot->release_cb)		//smallboy: Fix it later ;;			
	//	sk->sk_prot->release_cb(sk);		
	// The sk_lock has mutex_unlock() semantics:
	/*
	mutex_release(&sk->sk_lock.dep_map, 1, _RET_IP_);

	spin_lock_bh(&sk->sk_lock.slock);
	if (sk->sk_backlog.tail)
		__release_sock(sk);

	if (sk->sk_prot->release_cb)
		sk->sk_prot->release_cb(sk);

	sk->sk_lock.owned = 0;
	if (waitqueue_active(&sk->sk_lock.wq))
		wake_up(&sk->sk_lock.wq);
	spin_unlock_bh(&sk->sk_lock.slock);
	*/
}
	
static void __sk_free(struct sock *sk)
{	
	if (sk->sk_destruct)
		sk->sk_destruct(sk);	
	put_net(sock_net(sk));
	tcp_metric_put(sock_net(sk),sk->sk_tcpm);
	us_sock_free(sk);
#if 0	
	struct sk_filter *filter;

	if (sk->sk_destruct)
		sk->sk_destruct(sk);

	filter = rcu_dereference_check(sk->sk_filter,atomic_read(&sk->sk_wmem_alloc) == 0);
	if (filter) {
		sk_filter_uncharge(sk, filter);
		RCU_INIT_POINTER(sk->sk_filter, NULL);
	}

	sock_disable_timestamp(sk, SK_FLAGS_TIMESTAMP);

	if (atomic_read(&sk->sk_omem_alloc))
		pr_debug("%s: optmem leakage (%d bytes) detected\n",
			 __func__, atomic_read(&sk->sk_omem_alloc));

	if (sk->sk_peer_cred)
		put_cred(sk->sk_peer_cred);
	put_pid(sk->sk_peer_pid);
	put_net(sock_net(sk));
	sk_prot_free(sk->sk_prot_creator, sk);
#endif	
}

void sk_free(struct sock *sk)
{
	/*
	 * We subtract one from sk_wmem_alloc and can know if
	 * some packets are still in some tx queue.
	 * If not null, sock_wfree() will call __sk_free(sk) later
	 */
	if (atomic_dec_and_test(&sk->sk_wmem_alloc))
		__sk_free(sk);
}


/*
 * Write buffer destructor automatically called from kfree_skb.
 */
void sock_wfree(struct sk_buff *skb)
{	
	struct sock *sk = skb->sk;
	unsigned int len = skb->truesize;

	if (!sock_flag(sk, SOCK_USE_WRITE_QUEUE)) {
		/*
		 * Keep a reference on sk_wmem_alloc, this will be released
		 * after sk_write_space() call
		 */
		atomic_sub(len - 1, &sk->sk_wmem_alloc);
		sk->sk_write_space(sk);
		len = 1;
	}
	/*
	 * if sk_wmem_alloc reaches 0, we must finish what sk_free()
	 * could not do because of in-flight packets
	 */
	if (atomic_sub_and_test(len, &sk->sk_wmem_alloc))
		__sk_free(sk);		
	
	//US_DEBUG("TH:%u,FUNC:%s skb->id:%u skb->len:%u skb->truesize:%u sk->id:%u sk_wmem_alloc:%u\n"
	//			,US_GET_LCORE(),__FUNCTION__,skb->skb_id,skb->len,skb->truesize,sk->sk_id,sk->sk_wmem_alloc);
}

static struct sock *sk_prot_alloc(struct net*pnet,struct proto *prot, int family)
{
	struct sock *sk;
	sk = us_sock_alloc(pnet);
	if (sk == NULL) {
		return sk;
	}
	
	if (prot->clear_sk) {
		prot->clear_sk(sk, prot->obj_size);
	}
	//else {											//All be cleared by us_sock_alloc;
	//	sk_prot_clear_nulls(sk, prot->obj_size);
	//}

	//sk_tx_queue_clear(sk);
	return sk;
}

/*
 * Copy all fields from osk to nsk but nsk->sk_refcnt must not change yet,
 * even temporarly, because of RCU lookups. sk_node should also be left as is.
 * We must not copy fields between sk_dontcopy_begin and sk_dontcopy_end
 */
static void sock_copy(struct sock *nsk, const struct sock *osk)
{
#ifdef CONFIG_SECURITY_NETWORK
	void *sptr = nsk->sk_security;
#endif
	memcpy(nsk, osk, offsetof(struct sock, sk_dontcopy_begin));

	memcpy(&nsk->sk_dontcopy_end, &osk->sk_dontcopy_end,
	       osk->sk_prot->obj_size - offsetof(struct sock, sk_dontcopy_end));

#ifdef CONFIG_SECURITY_NETWORK
	nsk->sk_security = sptr;
	security_sk_clone(osk, nsk);
#endif
}


/**
 *	sk_clone_lock - clone a socket, and lock its clone
 *	@sk: the socket to clone
 *	@priority: for allocation (%GFP_KERNEL, %GFP_ATOMIC, etc)
 *
 *	Caller must unlock socket even in error path (bh_unlock_sock(newsk))
 */
struct sock *sk_clone_lock(const struct sock *sk)
{
	struct sock *newsk;
	struct net  *pnet = sock_net(sk);
	
	newsk = sk_prot_alloc(pnet,sk->sk_prot,  sk->sk_family);
	if (newsk != NULL) {
		//US_DEBUG("TH:%u,newsk_id:%u\n",US_GET_LCORE(),newsk->sk_id);
		//struct sk_filter *filter;

		sock_copy(newsk, sk);				//smallboy:Attention;		
		newsk->sk_timer.base_vec = NULL;	//smallboy:We change the timer system,so attention here!!!
		
		/* SANITY */
		get_net(sock_net(newsk)); 
		sk_node_init(&newsk->sk_node);
		//sock_lock_init(newsk);
		//bh_lock_sock(newsk);
		//newsk->sk_backlog.head	= newsk->sk_backlog.tail = NULL;
		//newsk->sk_backlog.len = 0;

		//atomic_set(&newsk->sk_skb_rcv_num, 0);	
		//atomic_set(&newsk->sk_skb_snd_num, 0);

		newsk->sk_skb_rcv_num = 0;
		newsk->sk_skb_snd_num = 0;
		atomic_set(&newsk->sk_rmem_alloc, 0);
		/*
		 * sk_wmem_alloc set to one (see sk_free() and sock_wfree())
		 */
		atomic_set(&newsk->sk_wmem_alloc, 1);
		//atomic_set(&newsk->sk_omem_alloc, 0);
		
		skb_queue_head_init(&newsk->sk_receive_queue);
//		skb_queue_head_init(&newsk->sk_cache_head);
		skb_queue_head_init(&newsk->sk_write_queue);
//#ifdef CONFIG_NET_DMA
//		skb_queue_head_init(&newsk->sk_async_wait_queue);
//#endif

		//spin_lock_init(&newsk->sk_dst_lock);
		//rwlock_init(&newsk->sk_callback_lock);
		//lockdep_set_class_and_name(&newsk->sk_callback_lock,
		//		af_callback_keys + newsk->sk_family,
		//		af_family_clock_key_strings[newsk->sk_family]);

		//newsk->sk_dst_cache	= NULL;
		newsk->sk_wmem_queued	= 0;
		newsk->sk_forward_alloc = 0;
		newsk->sk_send_head	= NULL;

		//US_DEBUG("TH:%u,newsk_userlocks:%u,%u,sk_userlocks:%u\n"
		//			,US_GET_LCORE(),newsk->sk_userlocks
		//			,(sk->sk_userlocks & ~SOCK_BINDPORT_LOCK),sk->sk_userlocks);
		
		newsk->sk_userlocks	= sk->sk_userlocks & ~SOCK_BINDPORT_LOCK;
	

		sock_reset_flag(newsk, SOCK_DONE);
		//skb_queue_head_init(&newsk->sk_error_queue);

		//filter = rcu_dereference_protected(newsk->sk_filter, 1);
		//if (filter != NULL)
		//	sk_filter_charge(newsk, filter);

		//if (unlikely(xfrm_sk_clone_policy(newsk))) {
			/* It is still raw copy of parent, so invalidate
			 * destructor and make plain sk_free() */
			//newsk->sk_destruct = NULL;
			//bh_unlock_sock(newsk);
			//sk_free(newsk);
			//newsk = NULL;
			//goto out;
		//}

		newsk->sk_err	   = 0;
		newsk->sk_priority = 0;
		/*
		 * Before updating sk_refcnt, we must commit prior changes to memory
		 * (Documentation/RCU/rculist_nulls.txt for details)
		 */
		//smp_wmb();
		atomic_set(&newsk->sk_refcnt, 2);			//smallboy:Attention;

		/*
		 * Increment the counter in the same struct proto as the master
		 * sock (sk_refcnt_debug_inc uses newsk->sk_prot->socks, that
		 * is the same as sk->sk_prot->socks, as this field was copied
		 * with memcpy).
		 *
		 * This _changes_ the previous behaviour, where
		 * tcp_create_openreq_child always was incrementing the
		 * equivalent to tcp_prot->socks (inet_sock_nr), so this have
		 * to be taken into account in all callers. -acme
		 */
		//sk_refcnt_debug_inc(newsk);
		sk_set_socket(newsk, NULL);
		//newsk->sk_wq = NULL;

		//sk_update_clone(sk, newsk);

		if (newsk->sk_prot->sockets_allocated)
			sk_sockets_allocated_inc(newsk);

		//if (newsk->sk_flags & SK_FLAGS_TIMESTAMP)		//mallboy:For  SOCK_RCVTSTAMP opt;
		//	net_enable_timestamp();
	}
//out:
	return newsk;
}

/**
 *	__sk_mem_schedule - increase sk_forward_alloc and memory_allocated
 *	@sk: socket
 *	@size: memory size to allocate
 *	@kind: allocation type
 *
 *	If kind is SK_MEM_SEND, it means wmem allocation. Otherwise it means
 *	rmem allocation. This function assumes that protocols which have
 *	memory_pressure use sk_wmem_queued as write buffer accounting.
 */
int __sk_mem_schedule(struct sock *sk, int size, int kind)
{
#if 0	
	struct proto *prot = sk->sk_prot;
	int amt = sk_mem_pages(size);
	long allocated;
	int parent_status = UNDER_LIMIT;

	sk->sk_forward_alloc += amt * SK_MEM_QUANTUM;

	allocated = sk_memory_allocated_add(sk, amt, &parent_status);

	/* Under limit. */
	if (parent_status == UNDER_LIMIT &&
			allocated <= sk_prot_mem_limits(sk, 0)) {
		sk_leave_memory_pressure(sk);
		return 1;
	}

	/* Under pressure. (we or our parents) */
	if ((parent_status > SOFT_LIMIT) ||
			allocated > sk_prot_mem_limits(sk, 1))
		sk_enter_memory_pressure(sk);

	/* Over hard limit (we or our parents) */
	if ((parent_status == OVER_LIMIT) ||
			(allocated > sk_prot_mem_limits(sk, 2)))
		goto suppress_allocation;

	/* guarantee minimum buffer size under pressure */
	if (kind == SK_MEM_RECV) {
		if (atomic_read(&sk->sk_rmem_alloc) < prot->sysctl_rmem[0])
			return 1;

	} else { /* SK_MEM_SEND */
		if (sk->sk_type == SOCK_STREAM) {
			if (sk->sk_wmem_queued < prot->sysctl_wmem[0])
				return 1;
		} else if (atomic_read(&sk->sk_wmem_alloc) <
			   prot->sysctl_wmem[0])
				return 1;
	}

	if (sk_has_memory_pressure(sk)) {
		int alloc;

		if (!sk_under_memory_pressure(sk))
			return 1;
		alloc = sk_sockets_allocated_read_positive(sk);
		if (sk_prot_mem_limits(sk, 2) > alloc *
		    sk_mem_pages(sk->sk_wmem_queued +
				 atomic_read(&sk->sk_rmem_alloc) +
				 sk->sk_forward_alloc))
			return 1;
	}

suppress_allocation:

	if (kind == SK_MEM_SEND && sk->sk_type == SOCK_STREAM) {
		sk_stream_moderate_sndbuf(sk);

		/* Fail only if socket is _under_ its sndbuf.
		 * In this case we cannot block, so that we have to fail.
		 */
		if (sk->sk_wmem_queued + size >= sk->sk_sndbuf)
			return 1;
	}

	trace_sock_exceed_buf_limit(sk, prot, allocated);

	/* Alas. Undo changes. */
	sk->sk_forward_alloc -= amt * SK_MEM_QUANTUM;

	sk_memory_allocated_sub(sk, amt);
#endif
	return 0;
}


/*
 * Allocate a skb from the socket's send buffer.
 */
struct sk_buff *sock_wmalloc(struct sock *sk, unsigned long size, int force,int clone)
{
	if (force || atomic_read(&sk->sk_wmem_alloc) < sk->sk_sndbuf) {		//smallboy:  More limits here;
		struct sk_buff *skb = alloc_skb(sk,size, clone);
		if (skb) {
			skb_set_owner_w(skb, sk);
			return skb;
		}
	}
	return NULL;
}

struct sock* us_sock_alloc(struct net*pnet)
{
	//s32 ret,skc_id;
	s32 ret = 0;
	struct sock	*sk;
	//ret = us_slab_get(US_PER_LCORE(sock_pool),(void**)&sk);
	ret = us_slab_get(pnet->sock_pool ,(void**)&sk);
	if(unlikely(ret < 0)){
		return NULL;
	}/*else{
		skc_id = sk->sk_id;
		memset(sk, 0, sizeof(struct sock));
		sk->sk_id = skc_id;
	}*/

	return sk;
}

void us_sock_free(struct sock *sk)
{
	struct net *pnet = sock_net(sk);
	if (sk){
		//us_slab_free(pnet->sock_pool ,sk);
		us_slab_free(US_PER_LCORE(sock_pool),sk);
	}
}

static int sock_set_timeout(long *timeo_p, char __user *optval, int optlen)
{
	struct timeval tv;

	if (optlen < sizeof(tv))
		return -EINVAL;

	memcpy(&tv, optval,sizeof(tv));
	//if (copy_from_user(&tv, optval, sizeof(tv)))
	//	return -EFAULT;
	if (tv.tv_usec < 0 || tv.tv_usec >= USEC_PER_SEC || tv.tv_sec < 0)
		return -EDOM;

	//if (tv.tv_sec < 0) {
	//	static int warned ;

	//	*timeo_p = 0;
	//	if (warned < 10 && net_ratelimit()) {
	//		warned++;
	//		US_LOG("TH:%u,%s  tries to set negative timeout\n"
	//			,US_GET_LCORE(),__func__);
	//	}
	//	return 0;
	//}
	*timeo_p = MAX_SCHEDULE_TIMEOUT;
	if (tv.tv_sec == 0 && tv.tv_usec == 0)
		return 0;
	if (tv.tv_sec < (MAX_SCHEDULE_TIMEOUT/HZ - 1))
		*timeo_p = tv.tv_sec*HZ + (tv.tv_usec+(1000000/HZ-1))/(1000000/HZ);
	return 0;
}


/**
 * sk_stream_write_space - stream socket write_space callback.
 * @sk: socket
 *
 * FIXME: write proper description
 */
void sk_stream_write_space(struct sock *sk)
{	
	struct socket *skt = sk->sk_socket;
	//struct socket_wq *wq;

	if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk) && skt
		&& !sk_skb_snd_full(sk) ) {
		__clear_bit(SOCK_NOSPACE, &skt->flags);				//smallboy: Attention about the cwnd associated;

		//rcu_read_lock();
		//wq = rcu_dereference(sk->sk_wq);
		//if (wq_has_sleeper(wq))
		//	wake_up_interruptible_poll(&wq->wait, POLLOUT |
		//				POLLWRNORM | POLLWRBAND);
		//if (wq && wq->fasync_list && !(sk->sk_shutdown & SEND_SHUTDOWN))
		//	sock_wake_async(sock, SOCK_WAKE_SPACE, POLL_OUT);
		//rcu_read_unlock();
	}	
}

inline void sock_graft(struct sock *sk, struct socket *parent)
{
	//write_lock_bh(&sk->sk_callback_lock);
	//sk->sk_wq = parent->wq;
	parent->sk = sk;
	sk_set_socket(sk, parent);
	//security_sock_graft(sk, parent);
	//write_unlock_bh(&sk->sk_callback_lock);
}

inline int sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	return sock->ops->sendmsg(sock, msg, size);
}

inline int sock_sendv(struct socket *sock, struct msghdr *msg, size_t size)
{
	return sock->ops->sendv(sock, msg, size);
}


/*
 *	Set socket options on an inet socket.
 */
int sock_common_setsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;

	return sk->sk_prot->setsockopt(sk, level, optname, optval, optlen);
}



/*
 *	This is meant for all protocols to use and covers goings on
 *	at the socket level. Everything here is generic.
 */

int sock_setsockopt(struct socket *sock, int level, int optname,
		    char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	int val;
	int valbool;
	struct linger ling;
	int ret = 0;

	/*
	 *	Options without arguments
	 */

	//if (optname == SO_BINDTODEVICE)
	//	return sock_setbindtodevice(sk, optval, optlen);

	if (optlen < sizeof(int))
		return -EINVAL;

	val = *(int*)optval;
	//if (get_user(val, (int __user *)optval))
	//	return -EFAULT;

	valbool = val ? 1 : 0;

	//lock_sock(sk);

	switch (optname) {
	//case SO_DEBUG:
		//if (val && !capable(CAP_NET_ADMIN))
		//	ret = -EACCES;
		//else
		//	sock_valbool_flag(sk, SOCK_DBG, valbool);
			
	//	break;
	case SO_REUSEADDR:
		sk->sk_reuse = (valbool ? SK_CAN_REUSE : SK_NO_REUSE);
		break;
	case SO_REUSEPORT:
		sk->sk_reuseport = valbool;
		break;
	case SO_TYPE:
	case SO_PROTOCOL:
	case SO_DOMAIN:
	case SO_ERROR:
		ret = -ENOPROTOOPT;
		break;
	//case SO_DONTROUTE:
	//	sock_valbool_flag(sk, SOCK_LOCALROUTE, valbool);
	//	break;
	//case SO_BROADCAST:
	//	sock_valbool_flag(sk, SOCK_BROADCAST, valbool);
	//	break;
	case SO_SNDBUF:
		/* Don't error on this BSD doesn't and if you think
		 * about it this is right. Otherwise apps have to
		 * play 'guess the biggest size' games. RCVBUF/SNDBUF
		 * are treated in BSD as hints
		 */
		val = min_t(u32, val, sock_net(sk)->n_cfg.sysctl_wmem_max);
set_sndbuf:
		sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
		sk->sk_sndbuf = max_t(u32, val * 2, SOCK_MIN_SNDBUF);
		/* Wake up sending tasks if we upped the value. */
		sk->sk_write_space(sk);
		break;

	case SO_SNDBUFFORCE:
		//if (!capable(CAP_NET_ADMIN)) {
		//	ret = -EPERM;
		//	break;
		//}
		goto set_sndbuf;

	case SO_RCVBUF:
		/* Don't error on this BSD doesn't and if you think
		 * about it this is right. Otherwise apps have to
		 * play 'guess the biggest size' games. RCVBUF/SNDBUF
		 * are treated in BSD as hints
		 */
		val = min_t(u32, val, sock_net(sk)->n_cfg.sysctl_rmem_max);
set_rcvbuf:
		sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
		/*
		 * We double it on the way in to account for
		 * "struct sk_buff" etc. overhead.   Applications
		 * assume that the SO_RCVBUF setting they make will
		 * allow that much actual data to be received on that
		 * socket.
		 *
		 * Applications are unaware that "struct sk_buff" and
		 * other overheads allocate from the receive buffer
		 * during socket buffer allocation.
		 *
		 * And after considering the possible alternatives,
		 * returning the value we actually used in getsockopt
		 * is the most desirable behavior.
		 */
		sk->sk_rcvbuf = max_t(u32, val * 2, SOCK_MIN_RCVBUF);
		break;

	case SO_RCVBUFFORCE:
		//if (!capable(CAP_NET_ADMIN)) {
		//	ret = -EPERM;
		//	break;
		//}
		goto set_rcvbuf;

	case SO_KEEPALIVE:
#ifdef CONFIG_INET
		if (sk->sk_protocol == IPPROTO_TCP &&
		    sk->sk_type == SOCK_STREAM)
			tcp_set_keepalive(sk, valbool);
#endif
		sock_valbool_flag(sk, SOCK_KEEPOPEN, valbool);
		break;

	case SO_OOBINLINE:
		sock_valbool_flag(sk, SOCK_URGINLINE, valbool);
		break;

	case SO_NO_CHECK:
		sk->sk_no_check = valbool;
		break;

	//case SO_PRIORITY:
	//	if ((val >= 0 && val <= 6) ||
	//	    ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
	//		sk->sk_priority = val;
	//	else
	//		ret = -EPERM;
	//	break;

	case SO_LINGER:
		if (optlen < sizeof(ling)) {
			ret = -EINVAL;	/* 1003.1g */
			break;
		}
		memcpy(&ling, optval,sizeof(ling));
		//if (copy_from_user(&ling, optval, sizeof(ling))) {
		//	ret = -EFAULT;
		//	break;
		//}
		if (!ling.l_onoff)
			sock_reset_flag(sk, SOCK_LINGER);
		else {
#if (BITS_PER_LONG == 32)
			if ((unsigned int)ling.l_linger >= MAX_SCHEDULE_TIMEOUT/HZ)
				sk->sk_lingertime = MAX_SCHEDULE_TIMEOUT;
			else
#endif
				sk->sk_lingertime = (unsigned int)ling.l_linger * HZ;
			sock_set_flag(sk, SOCK_LINGER);
		}
		break;

	//case SO_BSDCOMPAT:
	//	sock_warn_obsolete_bsdism("setsockopt");
	//	break;
	/*
	case SO_PASSCRED:
		if (valbool)
			set_bit(SOCK_PASSCRED, &sock->flags);
		else
			clear_bit(SOCK_PASSCRED, &sock->flags);
		break;
	
	case SO_TIMESTAMP:
	case SO_TIMESTAMPNS:
		if (valbool)  {
			if (optname == SO_TIMESTAMP)
				sock_reset_flag(sk, SOCK_RCVTSTAMPNS);
			else
				sock_set_flag(sk, SOCK_RCVTSTAMPNS);
			sock_set_flag(sk, SOCK_RCVTSTAMP);
			sock_enable_timestamp(sk, SOCK_TIMESTAMP);
		} else {
			sock_reset_flag(sk, SOCK_RCVTSTAMP);
			sock_reset_flag(sk, SOCK_RCVTSTAMPNS);
		}
		break;

	case SO_TIMESTAMPING:
		if (val & ~SOF_TIMESTAMPING_MASK) {
			ret = -EINVAL;
			break;
		}
		sock_valbool_flag(sk, SOCK_TIMESTAMPING_TX_HARDWARE,
				  val & SOF_TIMESTAMPING_TX_HARDWARE);
		sock_valbool_flag(sk, SOCK_TIMESTAMPING_TX_SOFTWARE,
				  val & SOF_TIMESTAMPING_TX_SOFTWARE);
		sock_valbool_flag(sk, SOCK_TIMESTAMPING_RX_HARDWARE,
				  val & SOF_TIMESTAMPING_RX_HARDWARE);
		if (val & SOF_TIMESTAMPING_RX_SOFTWARE)
			sock_enable_timestamp(sk,
					      SOCK_TIMESTAMPING_RX_SOFTWARE);
		else
			sock_disable_timestamp(sk,
					       (1UL << SOCK_TIMESTAMPING_RX_SOFTWARE));
		sock_valbool_flag(sk, SOCK_TIMESTAMPING_SOFTWARE,
				  val & SOF_TIMESTAMPING_SOFTWARE);
		sock_valbool_flag(sk, SOCK_TIMESTAMPING_SYS_HARDWARE,
				  val & SOF_TIMESTAMPING_SYS_HARDWARE);
		sock_valbool_flag(sk, SOCK_TIMESTAMPING_RAW_HARDWARE,
				  val & SOF_TIMESTAMPING_RAW_HARDWARE);
		break;
	*/
	case SO_RCVLOWAT:
		if (val < 0)
			val = INT_MAX;
		sk->sk_rcvlowat = val ? : 1;
		break;

	case SO_RCVTIMEO:
		ret = sock_set_timeout(&sk->sk_rcvtimeo, optval, optlen);
		break;

	case SO_SNDTIMEO:
		ret = sock_set_timeout(&sk->sk_sndtimeo, optval, optlen);
		break;

	//case SO_ATTACH_FILTER:
	//	ret = -EINVAL;
	//	if (optlen == sizeof(struct sock_fprog)) {
	//		struct sock_fprog fprog;

	//		ret = -EFAULT;
	//		if (copy_from_user(&fprog, optval, sizeof(fprog)))
	//			break;

	//		ret = sk_attach_filter(&fprog, sk);
	//	}
	//	break;

	//case SO_DETACH_FILTER:
	//	ret = sk_detach_filter(sk);
	//	break;

	case SO_LOCK_FILTER:
		if (sock_flag(sk, SOCK_FILTER_LOCKED) && !valbool)
			ret = -EPERM;
		else
			sock_valbool_flag(sk, SOCK_FILTER_LOCKED, valbool);
		break;

	//case SO_PASSSEC:
	//	if (valbool)
	//		set_bit(SOCK_PASSSEC, &sock->flags);
	//	else
	//		clear_bit(SOCK_PASSSEC, &sock->flags);
	//	break;
	//case SO_MARK:
	//	if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
	//		ret = -EPERM;
	//	else
	//		sk->sk_mark = val;
	//	break;

		/* We implement the SO_SNDLOWAT etc to
		   not be settable (1003.1g 5.3) */
	case SO_RXQ_OVFL:
		sock_valbool_flag(sk, SOCK_RXQ_OVFL, valbool);
		break;

	//case SO_WIFI_STATUS:
	//	sock_valbool_flag(sk, SOCK_WIFI_STATUS, valbool);
	//	break;

	//case SO_PEEK_OFF:
	//	if (sock->ops->set_peek_off)
	//		sock->ops->set_peek_off(sk, val);
	//	else
	//		ret = -EOPNOTSUPP;
	//	break;

	//case SO_NOFCS:
	//	sock_valbool_flag(sk, SOCK_NOFCS, valbool);
	//	break;

	//case SO_SELECT_ERR_QUEUE:
	//	sock_valbool_flag(sk, SOCK_SELECT_ERR_QUEUE, valbool);
	//	break;

	default:
		ret = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	return ret;
}


/*
 *	Get a socket option on an socket.
 *
 *	FIX: POSIX 1003.1g is very ambiguous here. It states that
 *	asynchronous errors should be reported by getsockopt. We assume
 *	this means if you specify SO_ERROR (otherwise whats the point of it).
 */
int sock_common_getsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;

	return sk->sk_prot->getsockopt(sk, level, optname, optval, optlen);
}

int sock_getsockopt(struct socket *skt, int level, int optname,
		    char __user *optval, int __user *optlen)
{
	struct sock *sk = skt->sk;
	union {
		int val;
		struct linger ling;
		struct timeval tm;
	} v;
	int  lv = sizeof(v);
	if(*optlen <lv)
		return US_EINVAL;
	
	v.val = 0;
	
	switch (optname) {
		//case SO_DEBUG:
		//	v.val = sock_flag(sk, SOCK_DBG);
		//	break;
	
		//case SO_DONTROUTE:
		//	v.val = sock_flag(sk, SOCK_LOCALROUTE);
		//	break;
	
		//case SO_BROADCAST:
		//	v.val = sock_flag(sk, SOCK_BROADCAST);
		//	break;
	
		//case SO_SNDBUF:
		//	v.val = sk->sk_sndbuf;
		//	break;
	
		//case SO_RCVBUF:
		//	v.val = sk->sk_rcvbuf;
		//	break;
	
		//case SO_REUSEADDR:
		//	v.val = sk->sk_reuse;
		//	break;
	
		//case SO_REUSEPORT:
		//	v.val = sk->sk_reuseport;
		//	break;
	
		case SO_KEEPALIVE:
			v.val = sock_flag(sk, SOCK_KEEPOPEN);
			break;
	
		case SO_TYPE:
			v.val = sk->sk_type;
			break;
	
		case SO_PROTOCOL:
			v.val = sk->sk_protocol;
			break;
	
		case SO_DOMAIN:
			v.val = sk->sk_family;
			break;
	
		case SO_ERROR:
			v.val = -sock_error(sk);
			if (v.val == 0)
				v.val = xchg(&sk->sk_err_soft, 0);
			break;
	
		//case SO_OOBINLINE:
		//	v.val = sock_flag(sk, SOCK_URGINLINE);
		//	break;
	
		case SO_NO_CHECK:
			v.val = sk->sk_no_check;  //udp
			break;
	
		case SO_PRIORITY:
			v.val = sk->sk_priority; // not used;
			break;
	
		case SO_LINGER:
			lv		= sizeof(v.ling);
			v.ling.l_onoff	= sock_flag(sk, SOCK_LINGER);
			v.ling.l_linger = sk->sk_lingertime / HZ;
			break;
	
		//case SO_BSDCOMPAT:
		//	sock_warn_obsolete_bsdism("getsockopt");
		//	break;
	
		//case SO_TIMESTAMP:
		//	v.val = sock_flag(sk, SOCK_RCVTSTAMP) &&
		//			!sock_flag(sk, SOCK_RCVTSTAMPNS);
		//	break;
	
		//case SO_TIMESTAMPNS:
		//	v.val = sock_flag(sk, SOCK_RCVTSTAMPNS);
		//	break;
	
		//case SO_TIMESTAMPING:
		//	v.val = 0;
		//	if (sock_flag(sk, SOCK_TIMESTAMPING_TX_HARDWARE))
		//		v.val |= SOF_TIMESTAMPING_TX_HARDWARE;
		//	if (sock_flag(sk, SOCK_TIMESTAMPING_TX_SOFTWARE))
		//		v.val |= SOF_TIMESTAMPING_TX_SOFTWARE;
		//	if (sock_flag(sk, SOCK_TIMESTAMPING_RX_HARDWARE))
		//		v.val |= SOF_TIMESTAMPING_RX_HARDWARE;
		//	if (sock_flag(sk, SOCK_TIMESTAMPING_RX_SOFTWARE))
		//		v.val |= SOF_TIMESTAMPING_RX_SOFTWARE;
		//	if (sock_flag(sk, SOCK_TIMESTAMPING_SOFTWARE))
		//		v.val |= SOF_TIMESTAMPING_SOFTWARE;
		//	if (sock_flag(sk, SOCK_TIMESTAMPING_SYS_HARDWARE))
		//		v.val |= SOF_TIMESTAMPING_SYS_HARDWARE;
		//	if (sock_flag(sk, SOCK_TIMESTAMPING_RAW_HARDWARE))
		//		v.val |= SOF_TIMESTAMPING_RAW_HARDWARE;
		//	break;
	
		case SO_RCVTIMEO:
			lv = sizeof(struct timeval);
			if (sk->sk_rcvtimeo == MAX_SCHEDULE_TIMEOUT) {
				v.tm.tv_sec = 0;
				v.tm.tv_usec = 0;
			} else {
				v.tm.tv_sec = sk->sk_rcvtimeo / HZ;
				v.tm.tv_usec = ((sk->sk_rcvtimeo % HZ) * 1000000) / HZ;
			}
			break;
	
		//case SO_SNDTIMEO:
		//	lv = sizeof(struct timeval);
		//	if (sk->sk_sndtimeo == MAX_SCHEDULE_TIMEOUT) {
		//		v.tm.tv_sec = 0;
		//		v.tm.tv_usec = 0;
		//	} else {
		//		v.tm.tv_sec = sk->sk_sndtimeo / HZ;
		//		v.tm.tv_usec = ((sk->sk_sndtimeo % HZ) * 1000000) / HZ;
		//	}
		//	break;
	
		case SO_RCVLOWAT:
			v.val = sk->sk_rcvlowat;
			break;
	
		case SO_SNDLOWAT:
			v.val = 1;
			break;
	
		//case SO_PASSCRED:
		//	v.val = !!test_bit(SOCK_PASSCRED, &sock->flags);
		//	break;
	
		//case SO_PEERCRED:
		//{
		//	struct ucred peercred;
		//	if (len > sizeof(peercred))
		//		len = sizeof(peercred);
		//	cred_to_ucred(sk->sk_peer_pid, sk->sk_peer_cred, &peercred);
		//	if (copy_to_user(optval, &peercred, len))
		//		return -EFAULT;
		//	goto lenout;
		//}
	
		//case SO_PEERNAME:					//smallboy:Fix it later;
		//{
		//	char address[128];
	
		//	if (skt->ops->getname(skt, (struct sockaddr *)address, &lv, 2))
		//		return -ENOTCONN;
		//	if (lv < len)
		//		return -EINVAL;
		//	if (copy_to_user(optval, address, len))
		//		return -EFAULT;
		//	goto lenout;
	//	}
	
		/* Dubious BSD thing... Probably nobody even uses it, but
		 * the UNIX standard wants it for whatever reason... -DaveM
		 */
		case SO_ACCEPTCONN:
			v.val = sk->sk_state == TCP_LISTEN;
			break;
	
		//case SO_PASSSEC:
		//	v.val = !!test_bit(SOCK_PASSSEC, &sock->flags);
		//	break;
	
		//case SO_PEERSEC:
		//	return security_socket_getpeersec_stream(sock, optval, optlen, len);
	
		//case SO_MARK:
		//	v.val = sk->sk_mark;
		//	break;
	
		//case SO_RXQ_OVFL:
		//	v.val = sock_flag(sk, SOCK_RXQ_OVFL);
		//	break;
	
		//case SO_WIFI_STATUS:
		//	v.val = sock_flag(sk, SOCK_WIFI_STATUS);
		//	break;
	
		//case SO_PEEK_OFF:
		//	if (!skt->ops->set_peek_off)
		//		return -EOPNOTSUPP;
	//
		//	v.val = sk->sk_peek_off;
		//	break;
		//case SO_NOFCS:
		//	v.val = sock_flag(sk, SOCK_NOFCS);
		//	break;
	
		//case SO_BINDTODEVICE:
		//	return sock_getbindtodevice(sk, optval, optlen, len);
	
		//case SO_GET_FILTER:
		//	len = sk_get_filter(sk, (struct sock_filter __user *)optval, len);
		//	if (len < 0)
		//		return len;
	
		//	goto lenout;
	
		///case SO_LOCK_FILTER:
		//	v.val = sock_flag(sk, SOCK_FILTER_LOCKED);
		//	break;
	
		//case SO_SELECT_ERR_QUEUE:
		//	v.val = sock_flag(sk, SOCK_SELECT_ERR_QUEUE);
		//	break;
	
		default:
			return -ENOPROTOOPT;
		}

		memcpy(optval,&v,*optlen);
		*optlen = lv;

		return 0;
}

void us_sk_event_insert(struct sock *sk,int band)
{	
	u32 i,evs_num,find;
	struct net *pnet = sock_net(sk);
	//us_netio_evb	*evb_p = US_PER_LCORE(evb);

	struct us_netio_evb		*evb_p = pnet->evb_p;
	struct us_netio_events  *ev_p  = &evb_p->ev_b[(evb_p->evb_index+1)&(0x1)];
	struct us_netio_event	*e_p   = &ev_p->netio_events[0];

	evs_num = ev_p->netio_event_index;
	
	for(i=0,find = 0;i<evs_num;i++){
		if(e_p->sk == sk){
			find = 1;
			break;
		}
		e_p++;
	}

	if(i >= US_MAX_EVENT_BURST){
		US_ERR("TH:%u,sig lost!!!!!!!!!!!!! %d\n",US_GET_LCORE(),band);
		goto out ;
	}

	ev_p->netio_events[i].sk = sk;
	ev_p->netio_events[i].skt = sk->sk_socket;	//If there is a err event, in the eventloop,there is no sock then;
	ev_p->netio_event_index += 1-find;

	if(band == US_POLL_IN){
		ev_p->netio_events[i].read_ev++ ;
		goto out ;
	}
	
	if(band == US_POLL_OUT){
		ev_p->netio_events[i].write_ev++ ;
		goto out ;
	}
	
	if(band == US_POLL_ERR || band == US_POLL_HUP){
		ev_p->netio_events[i].err_ev++ ;
	}else{
		ev_p->netio_events[i].unknown++;
		US_ERR("TH:%u,unknow sig lost!!!!!!!!!!!!!!!!!!! %d\n",US_GET_LCORE(),band);
	}

out:

#if 0	
	fprintf(stderr,"bgw_sk_event_insert \n");
	for(j=0;j<evs_p->netio_event_index;j++){
		if(evs_p->netio_events[i].sk){
			fprintf(stderr,"%u,sk_id:%u,%u,%u,%u,%u,%u\n"
					,((netio_ev_bindex+1)&0x1)
					,evs_p->netio_events[i].sk->__sk_common.skc_id
					,evs_p->netio_events[i].read_ev
					,evs_p->netio_events[i].write_ev
					,evs_p->netio_events[i].err_ev
					,evs_p->netio_events[i].ev_id_r
					,evs_p->netio_events[i].ev_id_w);
		}
	}
	fprintf(stderr,"bgw_sk_event_insert over\n\n");
#endif
	return ;

}


int sock_wake_async(struct sock *sk, int how, int band)
{	//US_DEBUG("TH:%u,func;%s\n",US_GET_LCORE(),__FUNCTION__);
	//struct socket_wq *wq;

	if (!sk)
		return -1;
	//rcu_read_lock();
	//wq = rcu_dereference(sock->wq);
	//if (!wq || !wq->fasync_list) {
	//	rcu_read_unlock();
	//	return -1;
	//}

	struct socket *skt = sk->sk_socket;
	switch (how) {
	case SOCK_WAKE_WAITD:
		if (skt && test_bit(SOCK_ASYNC_WAITDATA, &skt->flags))
			break;
		goto call_kill;
	case SOCK_WAKE_SPACE:
		if (skt && !test_and_clear_bit(SOCK_ASYNC_NOSPACE, &skt->flags))
			break;
		/* fall through */
	case SOCK_WAKE_IO:
call_kill:
		us_sk_event_insert(sk,band);
		//kill_fasync(&wq->fasync_list, SIGIO, band);
		break;
	case SOCK_WAKE_URG:
		break;
		//kill_fasync(&wq->fasync_list, SIGURG, band);
	}
	//rcu_read_unlock();
	return 0;
}


