/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Support for INET connection oriented protocols.
 *
 * Authors:	See the TCP sources
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or(at your option) any later version.
 */

/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			inet_connection_sock.c
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/



#include "types.h"
#include "sock.h"
#include "socket.h"
#include "tcp.h"
#include "us_timer.h"
#include "inet_connection_sock.h"

#ifdef CONFIG_IPV6
#define AF_INET_FAMILY(fam) ((fam) == AF_INET)
#else
#define AF_INET_FAMILY(fam) 1
#endif

static inline u32 inet_synq_hash(const __be32 raddr, const __be16 rport,
				 const u32 rnd, const u32 synq_hsize)
{
	return us_jhash_2words((__force u32)raddr, (__force u32)rport, rnd) & (synq_hsize - 1);
}

struct request_sock *inet_csk_search_req(const struct sock *sk,struct request_sock ***prevp,
					 const __be16 rport, const __be32 raddr,const __be32 laddr)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;
	struct request_sock *req, **prev;

	u32 hash = inet_synq_hash(raddr, rport, lopt->hash_rnd,lopt->nr_table_entries);
	for(prev = &lopt->syn_table[hash];(req = *prev) != NULL;prev = &req->dl_next) {
		const struct inet_request_sock *ireq = inet_rsk(req);
		
		if (ireq->rmt_port == rport &&
		    ireq->rmt_addr == raddr &&
		    ireq->loc_addr == laddr &&
		    AF_INET_FAMILY(req->rsk_ops->family)) {
			//WARN_ON(req->sk);				//smallboy:Fix it later;
			*prevp = prev;
			break;
		}
	}
	
	return req;
}

int inet_rtx_syn_ack(struct sock *parent, struct request_sock *req)
{
	int err = req->rsk_ops->rtx_syn_ack(parent, req);

	if (!err)
		req->num_retrans++;
	return err;
}

void inet_get_local_port_range(struct net* pnet,int *low, int *high)
{
	*low = pnet->n_cfg.sysctl_portrange_low;
	*high = pnet->n_cfg.sysctl_portrange_high;
/*	
	unsigned int seq;

	do {
		seq = read_seqbegin(&sysctl_local_ports.lock);

		*low = sysctl_local_ports.range[0];
		*high = sysctl_local_ports.range[1];
	} while (read_seqretry(&sysctl_local_ports.lock, seq));
*/	
}


/* Obtain a reference to a local port for the given sock,
 * if snum is zero it means select any available local port.
 */
int inet_csk_get_port(struct sock *sk, unsigned short snum)
{	
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	struct inet_bind_hashbucket *head;
	struct inet_bind_bucket *tb;
	int ret, attempts = 5;
	
	struct net *net = sock_net(sk);
	int smallest_size = -1, smallest_rover;
	//kuid_t uid = sock_i_uid(sk);

	//local_bh_disable();
	if (!snum) {
		int remaining, rover, low, high;

again:
		inet_get_local_port_range(net,&low, &high);
		remaining = (high - low) + 1;
		smallest_rover = rover = net_random() % remaining + low;

		smallest_size = -1;
		do {
			if (inet_is_reserved_local_port(net,rover))
				goto next_nolock;
			head = &hashinfo->bhash[inet_bhashfn(net, rover, hashinfo->bhash_size)];
			//spin_lock(&head->lock);
			inet_bind_bucket_for_each(tb, &head->chain)
				if (net_eq(ib_net(tb), net) && tb->port == rover) {
					if (((tb->fastreuse > 0 && sk->sk_reuse && sk->sk_state != TCP_LISTEN) 
						|| (tb->fastreuseport > 0 && sk->sk_reuseport ))  //  && uid_eq(tb->fastuid, uid)
						&& (tb->num_owners < smallest_size || smallest_size == -1)) {
						smallest_size = tb->num_owners;
						smallest_rover = rover;
						if ((atomic_read(&hashinfo->bsockets) > (high - low) + 1) 
							&& (!inet_csk(sk)->icsk_af_ops->bind_conflict(sk, tb, false))) {
							snum = smallest_rover;
							goto tb_found;
						}
					}
					if (!inet_csk(sk)->icsk_af_ops->bind_conflict(sk, tb, false)) {
						snum = rover;
						goto tb_found;
					}
					goto next;
				}
				
			break;
		next:
			//spin_unlock(&head->lock);
		next_nolock:
			if (++rover > high)
				rover = low;
		} while (--remaining > 0);

		/* Exhausted local port range during search?  It is not
		 * possible for us to be holding one of the bind hash
		 * locks if this test triggers, because if 'remaining'
		 * drops to zero, we broke out of the do/while loop at
		 * the top level, not from the 'break;' statement.
		 */
		ret = 1;
		if (remaining <= 0) {
			if (smallest_size != -1) {
				snum = smallest_rover;
				goto have_snum;
			}
			goto fail;
		}
		/* OK, here is the one we will use.  HEAD is
		 * non-NULL and we hold it's mutex.
		 */
		snum = rover;
	} else {
have_snum:
		head = &hashinfo->bhash[inet_bhashfn(net, snum, hashinfo->bhash_size)];
		//spin_lock(&head->lock);
		inet_bind_bucket_for_each(tb, &head->chain) {
			if (net_eq(ib_net(tb), net) && tb->port == snum)
				goto tb_found;
		}
	}
	tb = NULL;
	goto tb_not_found;
tb_found:
	if (!us_hlist_empty(&tb->owners)) {
		if (sk->sk_reuse == SK_FORCE_REUSE)
			goto success;

		if (((tb->fastreuse > 0 && sk->sk_reuse && sk->sk_state != TCP_LISTEN) 
			|| (tb->fastreuseport > 0 && sk->sk_reuseport ))   //&& uid_eq(tb->fastuid, uid)
			&& smallest_size == -1) {
			goto success;
		} else {
			ret = 1;
			if (inet_csk(sk)->icsk_af_ops->bind_conflict(sk, tb, true)) {
				if (((sk->sk_reuse && sk->sk_state != TCP_LISTEN)
					|| (tb->fastreuseport > 0 && sk->sk_reuseport ))   //&& uid_eq(tb->fastuid, uid)
					&& smallest_size != -1 && --attempts >= 0) {
					//spin_unlock(&head->lock);
					goto again;
				}

				goto fail_unlock;
			}
		}
	}
tb_not_found:
	ret = 1;
	if (!tb && (tb = inet_bind_bucket_create(net, head, snum)) == NULL)
		goto fail_unlock;
	if (us_hlist_empty(&tb->owners)) {
		if (sk->sk_reuse && sk->sk_state != TCP_LISTEN)
			tb->fastreuse = 1;
		else
			tb->fastreuse = 0;
		if (sk->sk_reuseport) {
			tb->fastreuseport = 1;
			//tb->fastuid = uid;
		} else
			tb->fastreuseport = 0;
	} else {
		if (tb->fastreuse &&
		    (!sk->sk_reuse || sk->sk_state == TCP_LISTEN))
			tb->fastreuse = 0;
		if (tb->fastreuseport &&
		    (!sk->sk_reuseport ))   //|| !uid_eq(tb->fastuid, uid)
			tb->fastreuseport = 0;
	}
success:
	if (!inet_csk(sk)->icsk_bind_hash)
		inet_bind_hash(sk, tb, snum);
	//WARN_ON(inet_csk(sk)->icsk_bind_hash != tb);
	ret = 0;

fail_unlock:
	//spin_unlock(&head->lock);
fail:
	//local_bh_enable();
	return ret;
}


/*
 * Using different timers for retransmit, delayed acks and probes
 * We may wish use just one timer maintaining a list of expire jiffies
 * to optimize.
 */
void inet_csk_init_xmit_timers(struct sock *sk,
			       void (*retransmit_handler)(unsigned long),
			       void (*delack_handler)(unsigned long),
			       void (*keepalive_handler)(unsigned long))
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	setup_timer(&icsk->icsk_retransmit_timer, retransmit_handler, sk,TIMER_TYPE_REW);
	setup_timer(&icsk->icsk_delack_timer, delack_handler, sk,TIMER_TYPE_DACK);
	setup_timer(&sk->sk_timer, keepalive_handler, sk,TIMER_TYPE_KEEP);
	icsk->icsk_pending = icsk->icsk_ack.pending = 0;
}

void inet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req, unsigned long timeout)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;
	const u32 h = inet_synq_hash(inet_rsk(req)->rmt_addr, inet_rsk(req)->rmt_port,
				     lopt->hash_rnd, lopt->nr_table_entries);

	reqsk_queue_hash_req(&icsk->icsk_accept_queue, h, req, timeout);
	inet_csk_reqsk_queue_added(sk, timeout);
}

void sk_stream_kill_queues(struct sock *sk)
{
	/* First the read buffer. */
	__skb_queue_purge(&sk->sk_receive_queue);
	//__skb_queue_purge(&sk->sk_cache_head);

	/* Next, the error queue. */
	//__skb_queue_purge(&sk->sk_error_queue);

	/* Next, the write queue. */
	//WARN_ON(!skb_queue_empty(&sk->sk_write_queue));

	/* Account for returned memory. */
	sk_mem_reclaim(sk);

	//WARN_ON(sk->sk_wmem_queued);
	//WARN_ON(sk->sk_forward_alloc);

	/* It is _impossible_ for the backlog to contain anything
	 * when we get here.  All user references to this socket
	 * have gone away, only the net layer knows can touch it.
	 */
}

/*
 * At this point, there should be no process reference to this
 * socket, and thus no user references at all.  Therefore we
 * can assume the socket waitqueue is inactive and nobody will
 * try to jump onto it.
 */
void inet_csk_destroy_sock(struct sock *sk)
{
	//WARN_ON(sk->sk_state != TCP_CLOSE);
	//WARN_ON(!sock_flag(sk, SOCK_DEAD));

	/* It cannot be in hash table! */
	//WARN_ON(!sk_unhashed(sk));

	/* If it has not 0 inet_sk(sk)->inet_num, it must be bound */
	//WARN_ON(inet_sk(sk)->inet_num && !inet_csk(sk)->icsk_bind_hash);

	sk->sk_prot->destroy(sk);

	sk_stream_kill_queues(sk);

	//xfrm_sk_free_policy(sk);

	//sk_refcnt_debug_release(sk);

	//percpu_counter_dec(sk->sk_prot->orphan_count);
	atomic_dec(&sk->sk_prot->orphan_count);
	sock_put(sk);
}

/* This function allows to force a closure of a socket after the call to
 * tcp/dccp_create_openreq_child().
 */
void inet_csk_prepare_forced_close(struct sock *sk) //__releases(&sk->sk_lock.slock)
{
	/* sk_clone_lock locked the socket and set refcnt to 2 */
	//bh_unlock_sock(sk);
	sock_put(sk);

	/* The below has to be done to allow calling inet_csk_destroy_sock */
	sock_set_flag(sk, SOCK_DEAD);
	//percpu_counter_inc(sk->sk_prot->orphan_count);
	atomic_inc(&sk->sk_prot->orphan_count);
	inet_sk(sk)->inet_num = 0;
}


/**
 *	inet_csk_clone_lock - clone an inet socket, and lock its clone
 *	@sk: the socket to clone
 *	@req: request_sock
 *	@priority: for allocation (%GFP_KERNEL, %GFP_ATOMIC, etc)
 *
 *	Caller must unlock socket even in error path (bh_unlock_sock(newsk))
 */
struct sock *inet_csk_clone_lock(const struct sock *sk, const struct request_sock *req)
{
	struct sock *newsk = sk_clone_lock(sk);

	if (newsk != NULL) {
		struct inet_connection_sock *newicsk = inet_csk(newsk);

		newsk->sk_state = TCP_SYN_RECV;
		newicsk->icsk_bind_hash = NULL;

		inet_sk(newsk)->inet_dport = inet_rsk(req)->rmt_port;
		inet_sk(newsk)->inet_num = ntohs(inet_rsk(req)->loc_port);
		inet_sk(newsk)->inet_sport = inet_rsk(req)->loc_port;
		newsk->sk_write_space = sk_stream_write_space;

		newicsk->icsk_retransmits = 0;
		newicsk->icsk_backoff	  = 0;
		newicsk->icsk_probes_out  = 0;

		/* Deinitialize accept_queue to trap illegal accesses. */
		memset(&newicsk->icsk_accept_queue, 0, sizeof(newicsk->icsk_accept_queue));

		//security_inet_csk_clone(newsk, req);
	}
	return newsk;
}


/*
 *	This routine closes sockets which have been at least partially
 *	opened, but not yet accepted.
 */
void inet_csk_listen_stop(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct request_sock *acc_req;
	struct request_sock *req;

	inet_csk_delete_keepalive_timer(sk);

	/* make all the listen_opt local to us */
	acc_req = reqsk_queue_yank_acceptq(queue);

	/* Following specs, it would be better either to send FIN
	 * (and enter FIN-WAIT-1, it is normal close)
	 * or to send active reset (abort).
	 * Certainly, it is pretty dangerous while synflood, but it is
	 * bad justification for our negligence 8)
	 * To be honest, we are not able to make either
	 * of the variants now.			--ANK
	 */
	reqsk_queue_destroy(queue);

	while ((req = acc_req) != NULL) {
		struct sock *child = req->sk;

		acc_req = req->dl_next;

		//local_bh_disable();
		//bh_lock_sock(child);
		//WARN_ON(sock_owned_by_user(child));
		sock_hold(child);

		sk->sk_prot->disconnect(child, O_NONBLOCK);

		sock_orphan(child);

		//percpu_counter_inc(sk->sk_prot->orphan_count);
		atomic_inc(&sk->sk_prot->orphan_count);

		if (sk->sk_protocol == IPPROTO_TCP && tcp_rsk(req)->listener) {
			//BUG_ON(tcp_sk(child)->fastopen_rsk != req);
			//BUG_ON(sk != tcp_rsk(req)->listener);

			/* Paranoid, to prevent race condition if
			 * an inbound pkt destined for child is
			 * blocked by sock lock in tcp_v4_rcv().
			 * Also to satisfy an assertion in
			 * tcp_v4_destroy_sock().
			 */
			tcp_sk(child)->fastopen_rsk = NULL;
			sock_put(sk);
		}
		inet_csk_destroy_sock(child);

		//bh_unlock_sock(child);
		//local_bh_enable();
		sock_put(child);

		sk_acceptq_removed(sk);
		__reqsk_free(req);
	}
	if (queue->fastopenq != NULL) {
		/* Free all the reqs queued in rskq_rst_head. */
		//spin_lock_bh(&queue->fastopenq->lock);
		acc_req = queue->fastopenq->rskq_rst_head;
		queue->fastopenq->rskq_rst_head = NULL;
		//spin_unlock_bh(&queue->fastopenq->lock);
		while ((req = acc_req) != NULL) {
			acc_req = req->dl_next;
			__reqsk_free(req);
		}
	}
	//WARN_ON(sk->sk_ack_backlog);
}


int inet_csk_listen_start(struct sock *sk, const int nr_table_entries)
{
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_metrics_block	*tcp_m = NULL;
	int rc = reqsk_queue_alloc(&icsk->icsk_accept_queue, nr_table_entries);

	if (rc != 0)
		return rc;

	sk->sk_max_ack_backlog = 0;
	sk->sk_ack_backlog = 0;
	inet_csk_delack_init(sk);

	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */
	sk->sk_state = TCP_LISTEN;
	if (!sk->sk_prot->get_port(sk, inet->inet_num)) {
		inet->inet_sport = htons(inet->inet_num);

		//sk_dst_reset(sk);							//smallboy:Fix it later;
		tcp_m	= tcp_get_metrics(sk , true);		//smallboy: create with 0.0.0.0 address;
		if(tcp_m == NULL)
			goto err_out;

		sk_set_tcpm(sk, tcp_m) ;					//smallboy: For commom attr in metrics;
		sk->sk_prot->hash(sk);
		return 0;
	}

err_out:
	sk->sk_state = TCP_CLOSE;
	__reqsk_queue_destroy(&icsk->icsk_accept_queue);
	return -EADDRINUSE;
}

void inet_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr)
{	
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	const struct inet_sock *inet = inet_sk(sk);

	sin->sin_family			= AF_INET;
	sin->sin_addr.s_addr	= inet->inet_daddr;
	sin->sin_port			= inet->inet_dport;

}

int inet_csk_bind_conflict(const struct sock *sk,const struct inet_bind_bucket *tb, bool relax)
{
	
	struct sock *sk2;
	int reuse = sk->sk_reuse;
	int reuseport = sk->sk_reuseport;
	//kuid_t uid = sock_i_uid((struct sock *)sk);

	/*
	 * Unlike other sk lookup places we do not check
	 * for sk_net here, since _all_ the socks listed
	 * in tb->owners list belong to the same net - the
	 * one this bucket belongs to.
	 */

	sk_for_each_bound(sk2, &tb->owners) {
		if (sk != sk2 
			&& !inet_v6_ipv6only(sk2) 
			&& (!sk->sk_bound_dev_if ||  !sk2->sk_bound_dev_if || sk->sk_bound_dev_if == sk2->sk_bound_dev_if)) {
			if ((!reuse || !sk2->sk_reuse || sk2->sk_state == TCP_LISTEN) 
				&& (!reuseport || !sk2->sk_reuseport || (sk2->sk_state != TCP_TIME_WAIT ))) {  //&& !uid_eq(uid, sock_i_uid(sk2))
				const __be32 sk2_rcv_saddr = sk_rcv_saddr(sk2);
				if (!sk2_rcv_saddr || !sk_rcv_saddr(sk) ||  sk2_rcv_saddr == sk_rcv_saddr(sk))
					break;
			}
			if (!relax && reuse && sk2->sk_reuse &&
			    sk2->sk_state != TCP_LISTEN) {
				const __be32 sk2_rcv_saddr = sk_rcv_saddr(sk2);

				if (!sk2_rcv_saddr || !sk_rcv_saddr(sk) || sk2_rcv_saddr == sk_rcv_saddr(sk))
					break;
			}
		}
	}
	return sk2 != NULL;
}

void inet_csk_delete_keepalive_timer(struct sock *sk)
{
	sk_stop_timer(sk, &sk->sk_timer);
}

void inet_csk_clear_xmit_timers(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_pending = icsk->icsk_ack.pending = icsk->icsk_ack.blocked = 0;

	sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
	sk_stop_timer(sk, &icsk->icsk_delack_timer);
	sk_stop_timer(sk, &sk->sk_timer);
}

void inet_csk_reset_keepalive_timer(struct sock *sk, unsigned long len)
{ //US_DEBUG("TH:%u,func:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);
	sk_reset_timer(sk, &sk->sk_timer, jiffies + len);
}

/* Decide when to expire the request and when to resend SYN-ACK */
static inline void syn_ack_recalc(struct request_sock *req, const int thresh,
				  const int max_retries,
				  const u8 rskq_defer_accept,
				  int *expire, int *resend)
{
	if (!rskq_defer_accept) {
		*expire = req->num_timeout >= thresh;
		*resend = 1;
		return;
	}
	*expire = req->num_timeout >= thresh &&
		  (!inet_rsk(req)->acked || req->num_timeout >= max_retries);
	/*
	 * Do not resend while waiting for data after ACK,
	 * start to resend on end of deferring period to give
	 * last chance for data or ACK to create established socket.
	 */
	*resend = !inet_rsk(req)->acked ||
		  req->num_timeout >= rskq_defer_accept - 1;
}


void inet_csk_reqsk_queue_prune(struct sock *parent,
				const unsigned long interval,
				const unsigned long timeout,
				const unsigned long max_rto)
{
	struct inet_connection_sock *icsk = inet_csk(parent);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct listen_sock *lopt = queue->listen_opt;
	
	int max_retries = icsk->icsk_syn_retries ? : sock_net(parent)->n_cfg.sysctl_tcp_synack_retries;
	int thresh = max_retries;
	unsigned long now = jiffies;
	struct request_sock **reqp, *req;
	int i, budget;

	if (lopt == NULL || lopt->qlen == 0)
		return;

	/* Normally all the openreqs are young and become mature
	 * (i.e. converted to established socket) for first timeout.
	 * If synack was not acknowledged for 1 second, it means
	 * one of the following things: synack was lost, ack was lost,
	 * rtt is high or nobody planned to ack (i.e. synflood).
	 * When server is a bit loaded, queue is populated with old
	 * open requests, reducing effective size of queue.
	 * When server is well loaded, queue size reduces to zero
	 * after several minutes of work. It is not synflood,
	 * it is normal operation. The solution is pruning
	 * too old entries overriding normal timeout, when
	 * situation becomes dangerous.
	 *
	 * Essentially, we reserve half of room for young
	 * embrions; and abort old ones without pity, if old
	 * ones are about to clog our table.
	 */
	if (lopt->qlen>>(lopt->max_qlen_log-1)) {
		int young = (lopt->qlen_young<<1);

		while (thresh > 2) {
			if (lopt->qlen < young)
				break;
			thresh--;
			young <<= 1;
		}
	}

	if (queue->rskq_defer_accept)
		max_retries = queue->rskq_defer_accept;

	budget = 2 * (lopt->nr_table_entries / (timeout / interval));
	i = lopt->clock_hand;

	do {
		reqp=&lopt->syn_table[i];
		while ((req = *reqp) != NULL) {
			if (time_after_eq(now, req->expires)) {
				int expire = 0, resend = 0;

				syn_ack_recalc(req, thresh, max_retries, queue->rskq_defer_accept,  &expire, &resend);
				req->rsk_ops->syn_ack_timeout(parent, req);
				if (!expire &&
				    (!resend ||
				     !inet_rtx_syn_ack(parent, req) ||
				     inet_rsk(req)->acked)) {
					unsigned long timeo;

					if (req->num_timeout++ == 0)
						lopt->qlen_young--;
					timeo = min(timeout << req->num_timeout,  max_rto);
					req->expires = now + timeo;
					reqp = &req->dl_next;
					continue;
				}

				/* Drop this request */
				inet_csk_reqsk_queue_unlink(parent, req, reqp);
				reqsk_queue_removed(queue, req);
				reqsk_free(req);

				//US_DEBUG("TH:%u,func:%s,%u unlink_req:%p  \n",US_GET_LCORE(),__FUNCTION__,__LINE__,req);
				continue;
			}
			reqp = &req->dl_next;
		}

		i = (i + 1) & (lopt->nr_table_entries - 1);

	} while (--budget > 0);

	lopt->clock_hand = i;

	if (lopt->qlen) {
		US_DEBUG("TH:%u,func:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);
		inet_csk_reset_keepalive_timer(parent, interval);
	}
}


