/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Generic TIME_WAIT sockets functions
 *
 *		From code orinally in TCP
 */

/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			inet_timewait_sock.c
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/


#include "atomic.h"
#include "tcp.h"
#include "inet_timewait_sock.h"

static inline void twsk_destructor(struct sock *sk)
{
	//BUG_ON(sk == NULL);
	//BUG_ON(sk->sk_prot == NULL);
	//BUG_ON(sk->sk_prot->twsk_prot == NULL);
	if (sk->sk_prot->twsk_prot->twsk_destructor != NULL)
		sk->sk_prot->twsk_prot->twsk_destructor(sk);
}

void inet_twsk_free(struct inet_timewait_sock *tw)
{	
	//struct module *owner = tw->tw_prot->owner;
	twsk_destructor((struct sock *)tw);
//#ifdef SOCK_REFCNT_DEBUG
//	pr_debug("%s timewait_sock %p released\n", tw->tw_prot->name, tw);
//#endif
	//US_DEBUG("TH:%u tw_id:%u\n",US_GET_LCORE(),tw->tw_id);
	release_net(twsk_net(tw));
	us_tw_free(tw,twsk_net(tw));
	//kmem_cache_free(tw->tw_prot->twsk_prot->twsk_slab, tw);
	//module_put(owner);	
}


/**
 *	inet_twsk_unhash - unhash a timewait socket from established hash
 *	@tw: timewait socket
 *
 *	unhash a timewait socket from established hash, if hashed.
 *	ehash lock must be held by caller.
 *	Returns 1 if caller should call inet_twsk_put() after lock release.
 */
int inet_twsk_unhash(struct inet_timewait_sock *tw)
{
	if(us_hlist_unhashed(&tw->tw_node))
		return 0;

	us_hlist_del(&tw->tw_node);
	sk_node_init(&tw->tw_node);
	return 1;
/*	
	if (hlist_nulls_unhashed(&tw->tw_node))
		return 0;

	hlist_nulls_del_rcu(&tw->tw_node);
	sk_nulls_node_init(&tw->tw_node);

	// We cannot call inet_twsk_put() ourself under lock, caller must call it for us.

	return 1;
*/	
}


void inet_twsk_put(struct inet_timewait_sock *tw)
{
	if (atomic_dec_and_test(&tw->tw_refcnt))
		inet_twsk_free(tw);
}


/**
 *	inet_twsk_bind_unhash - unhash a timewait socket from bind hash
 *	@tw: timewait socket
 *	@hashinfo: hashinfo pointer
 *
 *	unhash a timewait socket from bind hash, if hashed.
 *	bind hash lock must be held by caller.
 *	Returns 1 if caller should call inet_twsk_put() after lock release.
 */
int inet_twsk_bind_unhash(struct inet_timewait_sock *tw, struct inet_hashinfo *hashinfo)
{
	struct inet_bind_bucket *tb = tw->tw_tb;

	if (!tb)
		return 0;

	__us_hlist_del(&tw->tw_bind_node);
	tw->tw_tb = NULL;
	inet_bind_bucket_destroy( tb); //hashinfo->bind_bucket_cachep,
	/*
	 * We cannot call inet_twsk_put() ourself under lock,
	 * caller must call it for us.
	 */
	return 1;
}


/* Must be called with locally disabled BHs. */
static void __inet_twsk_kill(struct inet_timewait_sock *tw,struct inet_hashinfo *hashinfo)
{
	struct inet_bind_hashbucket *bhead;
	int refcnt;
	/* Unlink from established hashes. */
	//spinlock_t *lock = inet_ehash_lockp(hashinfo, tw->tw_hash);

	//spin_lock(lock);
	refcnt = inet_twsk_unhash(tw);
	//spin_unlock(lock);

	/* Disassociate with bind bucket. */
	bhead = &hashinfo->bhash[inet_bhashfn(twsk_net(tw), tw->tw_num,
			hashinfo->bhash_size)];

	//spin_lock(&bhead->lock);
	refcnt += inet_twsk_bind_unhash(tw, hashinfo);
	//spin_unlock(&bhead->lock);

#ifdef SOCK_REFCNT_DEBUG
	if (atomic_read(&tw->tw_refcnt) != 1) {
		pr_debug("%s timewait_sock %p refcnt=%d\n",
			 tw->tw_prot->name, tw, atomic_read(&tw->tw_refcnt));
	}
#endif
	while (refcnt) {
		inet_twsk_put(tw);
		refcnt--;
	}
}

/* This is for handling early-kills of TIME_WAIT sockets. */
//void inet_twsk_deschedule(struct inet_timewait_sock *tw, struct inet_timewait_death_row *twdr)
void inet_twsk_deschedule(struct inet_timewait_sock *tw,struct inet_timewait_death_row *twdr)
{	
	//spin_lock(&twdr->death_lock);
	if (inet_twsk_del_dead_node(tw)) {
		inet_twsk_put(tw);
		if (--twdr->tw_count == 0)
			us_del_timer(&twdr->tw_timer);
	}
	//spin_unlock(&twdr->death_lock);
	__inet_twsk_kill(tw, twdr->hashinfo);
}


/* Returns non-zero if quota exceeded.  */
static int inet_twdr_do_twkill_work(struct inet_timewait_death_row *twdr, const int slot)
{
	struct inet_timewait_sock *tw;
	unsigned int killed;
	int ret;
	//struct net *pnet = &US_PER_LCORE(init_net);

	/* NOTE: compare this to previous version where lock
	 * was released after detaching chain. It was racy,
	 * because tw buckets are scheduled in not serialized context
	 * in 2.3 (with netfilter), and with softnet it is common, because
	 * soft irqs are not sequenced.
	 */
	killed = 0;
	ret = 0;
rescan:
	inet_twsk_for_each_inmate(tw, &twdr->cells[slot]) {
	//US_DEBUG("TH:%u,func:%s,%u,slot:%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__,slot);	
		__inet_twsk_del_dead_node(tw);
		//spin_unlock(&twdr->death_lock);
		__inet_twsk_kill(tw, twdr->hashinfo);

#ifdef CONFIG_NET_NS
		NET_INC_STATS_BH(twsk_net(tw), LINUX_MIB_TIMEWAITED);
#endif
		inet_twsk_put(tw);
		killed++;
		//spin_lock(&twdr->death_lock);
		if (killed > INET_TWDR_TWKILL_QUOTA) {
			ret = 1;
			break;
		}

		/* While we dropped twdr->death_lock, another cpu may have
		 * killed off the next TW bucket in the list, therefore
		 * do a fresh re-read of the hlist head node with the
		 * lock reacquired.  We still use the hlist traversal
		 * macro in order to get the prefetches.
		 */
		goto rescan;
	}

	twdr->tw_count -= killed;

	//US_DEBUG("TH:%u,func:%s,%u slot:%u killed:%u \n",US_GET_LCORE(),__FUNCTION__,__LINE__,slot,killed);	
//#ifndef CONFIG_NET_NS
	//NET_ADD_STATS_BH(&init_net, LINUX_MIB_TIMEWAITED, killed);
	//NET_ADD_STATS_BH(pnet, LINUX_MIB_TIMEWAITED, killed);
//#endif
	return ret;
}


void inet_twdr_hangman(unsigned long data)
{
	//US_DEBUG("TH:%u,func:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);	
	struct inet_timewait_death_row *twdr;
	unsigned int need_timer;

	twdr = (struct inet_timewait_death_row *)data;
	//spin_lock(&twdr->death_lock);

	if (twdr->tw_count == 0)
		return;

	//US_DEBUG("TH:%u,func:%s,%u slot:%u ,period:%d \n",US_GET_LCORE(),__FUNCTION__,__LINE__
	//								,twdr->slot,twdr->period);
	need_timer = 0;
	if (inet_twdr_do_twkill_work(twdr, twdr->slot)) {
		twdr->thread_slots |= (1 << twdr->slot);
		//schedule_work(&twdr->twkill_work);
		//need_timer = 1;
		need_timer = 2;
	} else {												//smallboy:Always be zero here;
		// We purged the entire slot, anything left?  
		if (twdr->tw_count)
			need_timer = 1;
		twdr->slot = ((twdr->slot + 1) & (INET_TWDR_TWKILL_SLOTS - 1));
	}
	
	if (need_timer == 1){
		us_mod_timer(&twdr->tw_timer, jiffies + twdr->period);
	}else if(need_timer == 2){
		us_mod_timer(&twdr->tw_timer, jiffies + 1000);			// smallboy: More quick;
	}
//out:
	//spin_unlock(&twdr->death_lock);
}

void inet_twdr_twcal_tick(unsigned long data)
{
	//US_DEBUG("TH:%u,func:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);
	struct inet_timewait_death_row *twdr;
	int n, slot;
	unsigned long j;
	unsigned long now = jiffies;
	int killed = 0;
	int adv = 0;
	//struct net* pnet = &US_PER_LCORE(init_net);

	twdr = (struct inet_timewait_death_row *)data;

	//spin_lock(&twdr->death_lock);
	if (twdr->twcal_hand < 0)
		goto out;

	slot = twdr->twcal_hand;
	j = twdr->twcal_jiffie;

	for (n = 0; n < INET_TWDR_RECYCLE_SLOTS; n++) {
		if (time_before_eq(j, now)) {
			struct us_hlist_node *safe;
			struct inet_timewait_sock *tw;

			inet_twsk_for_each_inmate_safe(tw, safe, &twdr->twcal_row[slot]) {
				__inet_twsk_del_dead_node(tw);
				__inet_twsk_kill(tw, twdr->hashinfo);
#ifdef CONFIG_NET_NS
				NET_INC_STATS_BH(twsk_net(tw), LINUX_MIB_TIMEWAITKILLED);
#endif
				inet_twsk_put(tw);
				killed++;
			}
		} else {
			if (!adv) {
				adv = 1;
				twdr->twcal_jiffie = j;
				twdr->twcal_hand = slot;
			}

			if (!us_hlist_empty(&twdr->twcal_row[slot])) {
				us_mod_timer(&twdr->twcal_timer, j);
				goto out;
			}
		}
		j += 1 << INET_TWDR_RECYCLE_TICK;
		slot = (slot + 1) & (INET_TWDR_RECYCLE_SLOTS - 1);
	}
	twdr->twcal_hand = -1;

out:
	if ((twdr->tw_count -= killed) == 0)
		us_del_timer(&twdr->tw_timer);
//#ifndef CONFIG_NET_NS
	//NET_ADD_STATS_BH(&init_net, LINUX_MIB_TIMEWAITKILLED, killed);
	//NET_ADD_STATS_BH(pnet, LINUX_MIB_TIMEWAITKILLED, killed);
//#endif
	//spin_unlock(&twdr->death_lock);
}

struct inet_timewait_sock *inet_twsk_alloc( struct sock *sk, const int state) //const
{
	//struct inet_timewait_sock *tw =
	//	kmem_cache_alloc(sk->sk_prot_creator->twsk_prot->twsk_slab, GFP_ATOMIC);
	struct inet_timewait_sock *tw = us_tw_alloc(sk);
	if (tw != NULL) {
		const struct inet_sock *inet = inet_sk(sk);

		//kmemcheck_annotate_bitfield(tw, flags);

		/* Give us an identity. */
		tw->tw_daddr	    = inet->inet_daddr;
		tw->tw_rcv_saddr    = inet->inet_rcv_saddr;
		tw->tw_bound_dev_if = sk->sk_bound_dev_if;
		tw->tw_tos	    	= inet->tos;
		tw->tw_num	    	= inet->inet_num;
		tw->tw_state	    = TCP_TIME_WAIT;
		tw->tw_substate	    = state;
		tw->tw_sport	    = inet->inet_sport;
		tw->tw_dport	    = inet->inet_dport;
		tw->tw_family	    = sk->sk_family;
		tw->tw_reuse	    = sk->sk_reuse;
		tw->tw_hash	   		= sk->sk_hash;
		tw->tw_ipv6only	    = 0;
		tw->tw_transparent  = inet->transparent;
		tw->tw_prot	    	= sk->sk_prot_creator;

		tw->tw_id			= sk->sk_id;
		tw->tw_net			= sk->sk_net;
		//twsk_net_set(tw, hold_net(sock_net(sk)));
		/*
		 * Because we use RCU lookups, we should not set tw_refcnt
		 * to a non null value before everything is setup for this
		 * timewait socket.
		 */
		atomic_set(&tw->tw_refcnt, 0);
		inet_twsk_dead_node_init(tw);
		//__module_get(tw->tw_prot->owner);
	}

	return tw;
}

/*
 * Enter the time wait state. This is called with locally disabled BH.
 * Essentially we whip up a timewait bucket, copy the relevant info into it
 * from the SK, and mess with hash chains and list linkage.
 */
void __inet_twsk_hashdance(struct inet_timewait_sock *tw, struct sock *sk,
			   struct inet_hashinfo *hashinfo)
{
	const struct inet_sock *inet = inet_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_ehash_bucket *ehead = inet_ehash_bucket(hashinfo, sk->sk_hash);
	//spinlock_t *lock = inet_ehash_lockp(hashinfo, sk->sk_hash);
	struct inet_bind_hashbucket *bhead;
	/* Step 1: Put TW into bind hash. Original socket stays there too.
	   Note, that any socket with inet->num != 0 MUST be bound in
	   binding cache, even if it is closed.
	 */
	bhead = &hashinfo->bhash[inet_bhashfn(twsk_net(tw), inet->inet_num,
			hashinfo->bhash_size)];

	//spin_lock(&bhead->lock);
	tw->tw_tb = icsk->icsk_bind_hash;
	//WARN_ON(!icsk->icsk_bind_hash);
	inet_twsk_add_bind_node(tw, &tw->tw_tb->owners);
	//spin_unlock(&bhead->lock);

	//spin_lock(lock);

	/*
	 * Step 2: Hash TW into TIMEWAIT chain.
	 * Should be done before removing sk from established chain
	 * because readers are lockless and search established first.
	 */
	//inet_twsk_add_node_rcu(tw, &ehead->twchain);
	inet_twsk_add_node(tw, &ehead->twchain);

	/* Step 3: Remove SK from established hash. */
	//if (__sk_nulls_del_node_init_rcu(sk))
	//	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);

	__sk_del_node_init(sk);
	/*
	 * Notes :
	 * - We initially set tw_refcnt to 0 in inet_twsk_alloc()
	 * - We add one reference for the bhash link
	 * - We add one reference for the ehash link
	 * - We want this refcnt update done before allowing other
	 *   threads to find this tw in ehash chain.
	 */
	atomic_add(1 + 1 + 1, &tw->tw_refcnt);
	//US_DEBUG("TH:%u,func:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);

	//spin_unlock(lock);
}

void inet_twsk_schedule(struct inet_timewait_sock *tw, struct inet_timewait_death_row *twdr,
		       const int timeo, const int timewait_len)
{//US_DEBUG("TH:%u func:%s,%u \n",US_GET_LCORE(),__FUNCTION__,__LINE__);
	struct us_hlist_head *list;
	int slot;

	/* timeout := RTO * 3.5
	 *
	 * 3.5 = 1+2+0.5 to wait for two retransmits.
	 *
	 * RATIONALE: if FIN arrived and we entered TIME-WAIT state,
	 * our ACK acking that FIN can be lost. If N subsequent retransmitted
	 * FINs (or previous seqments) are lost (probability of such event
	 * is p^(N+1), where p is probability to lose single packet and
	 * time to detect the loss is about RTO*(2^N - 1) with exponential
	 * backoff). Normal timewait length is calculated so, that we
	 * waited at least for one retransmitted FIN (maximal RTO is 120sec).
	 * [ BTW Linux. following BSD, violates this requirement waiting
	 *   only for 60sec, we should wait at least for 240 secs.
	 *   Well, 240 consumes too much of resources 8)
	 * ]
	 * This interval is not reduced to catch old duplicate and
	 * responces to our wandering segments living for two MSLs.
	 * However, if we use PAWS to detect
	 * old duplicates, we can reduce the interval to bounds required
	 * by RTO, rather than MSL. So, if peer understands PAWS, we
	 * kill tw bucket after 3.5*RTO (it is important that this number
	 * is greater than TS tick!) and detect old duplicates with help
	 * of PAWS.
	 */
	slot = (timeo + (1 << INET_TWDR_RECYCLE_TICK) - 1) >> INET_TWDR_RECYCLE_TICK;

	//US_DEBUG("TH:%u func:%s,%u slot:%d \n",US_GET_LCORE(),__FUNCTION__,__LINE__,slot);
	//spin_lock(&twdr->death_lock);

	/* Unlink it, if it was scheduled */
	if (inet_twsk_del_dead_node(tw))
		twdr->tw_count--;
	else
		atomic_inc(&tw->tw_refcnt);

	if (slot >= INET_TWDR_RECYCLE_SLOTS) {
		/* Schedule to slow timer */
		if (timeo >= timewait_len) {
			slot = INET_TWDR_TWKILL_SLOTS - 1;
		} else {
			slot = DIV_ROUND_UP(timeo, twdr->period);
			if (slot >= INET_TWDR_TWKILL_SLOTS)
				slot = INET_TWDR_TWKILL_SLOTS - 1;
		}
		tw->tw_ttd = jiffies + timeo;
		slot = (twdr->slot + slot) & (INET_TWDR_TWKILL_SLOTS - 1);
		list = &twdr->cells[slot];

		//US_DEBUG("TH:%u func:%s,%u slot:%d \n",US_GET_LCORE(),__FUNCTION__,__LINE__,slot);	
	} else {
		tw->tw_ttd = jiffies + (slot << INET_TWDR_RECYCLE_TICK);

		if (twdr->twcal_hand < 0) {
			twdr->twcal_hand = 0;
			twdr->twcal_jiffie = jiffies;
			twdr->twcal_timer.expires = twdr->twcal_jiffie + (slot << INET_TWDR_RECYCLE_TICK);  //<<6;
			us_add_timer(&twdr->twcal_timer);
		} else {
			if (time_after(twdr->twcal_timer.expires, jiffies + (slot << INET_TWDR_RECYCLE_TICK)))
				us_mod_timer(&twdr->twcal_timer, jiffies + (slot << INET_TWDR_RECYCLE_TICK));
			slot = (twdr->twcal_hand + slot) & (INET_TWDR_RECYCLE_SLOTS - 1);
		}
		list = &twdr->twcal_row[slot];

		//US_DEBUG("TH:%u func:%s,%u slot:%d \n",US_GET_LCORE(),__FUNCTION__,__LINE__,slot);	
	}

	us_hlist_add_head(&tw->tw_death_node, list);

	if (twdr->tw_count++ == 0)
		us_mod_timer(&twdr->tw_timer, jiffies + twdr->period);
	//spin_unlock(&twdr->death_lock);
}


struct inet_timewait_sock *us_tw_alloc(struct sock*sk)
{
#if 0	
	s32 ret;
	struct inet_timewait_sock	*tw_sk;

	struct net *pnet = sock_net(sk);
	tw_sk = us_memobj_slab_alloc(pnet->tw_slab);
	return tw_sk;
#else
	s32 ret;
	struct inet_timewait_sock	*tw_sk;
	struct net*pnet = sock_net(sk);
	us_mempool *us_p = pnet->sk_tw_pool;
	ret = us_slab_get(us_p,(void**)&tw_sk);
	//ret = us_slab_get(US_PER_LCORE(sk_tw_pool),(void**)&tw_sk);
	if(ret < 0){
		return NULL;
	}
	
	/*else{
		skc_id = sk->sk_id;
		memset(sk, 0, sizeof(struct sock));
		sk->sk_id = skc_id;
	}*/

	return tw_sk;
#endif
}

void us_tw_free(struct inet_timewait_sock *tw,struct net*pnet)
{
	if (tw){
		//us_memobj_slab_free(tw) ;
		//us_slab_free(US_PER_LCORE(sk_tw_pool),tw);
		us_slab_free(pnet->sk_tw_pool,tw);
	}
}

