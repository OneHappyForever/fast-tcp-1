/*
 * Plugable TCP congestion control support and newReno
 * congestion control.
 * Based on ideas from I/O scheduler support and Web100.
 *
 * Copyright (C) 2005 Stephen Hemminger <shemminger@osdl.org>
 */

/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			tcp_cong.c
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/ 


#include "tcp.h"

struct sock;
struct tcp_sock;

/*
 * Slow start is used when congestion window is less than slow start
 * threshold. This version implements the basic RFC2581 version
 * and optionally supports:
 * 	RFC3742 Limited Slow Start  	  - growth limited to max_ssthresh
 *	RFC3465 Appropriate Byte Counting - growth limited by bytes acknowledged
 */
void tcp_slow_start(struct tcp_sock *tp)
{	
	int cnt; /* increase in packets */
	unsigned int delta = 0;
	u32 snd_cwnd = tp->snd_cwnd;
	tcp_ip_stack_config	*n_cfgp = &sock_net((struct sock*)tp)->n_cfg;

	if (unlikely(!snd_cwnd)) {
		US_DEBUG("TH:%u,snd_cwnd is nul, please report this bug.\n",US_GET_LCORE());
		snd_cwnd = 1U;
	}

	if (n_cfgp->sysctl_tcp_max_ssthresh > 0 && tp->snd_cwnd > n_cfgp->sysctl_tcp_max_ssthresh)
		cnt = n_cfgp->sysctl_tcp_max_ssthresh >> 1;		// limited slow start   ??
	else
		cnt = snd_cwnd;									/* exponential increase */

	tp->snd_cwnd_cnt += cnt;
	while (tp->snd_cwnd_cnt >= snd_cwnd) {
		tp->snd_cwnd_cnt -= snd_cwnd;
		delta++;
	}
	tp->snd_cwnd = min(snd_cwnd + delta, tp->snd_cwnd_clamp);	
}


/* Slow start threshold is half the congestion window (min 2) */
u32 tcp_reno_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	return max(tp->snd_cwnd >> 1U, 2U);
}

/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w) */
void tcp_cong_avoid_ai(struct tcp_sock *tp, u32 w)
{
	if (tp->snd_cwnd_cnt >= w) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp)
			tp->snd_cwnd++;
		tp->snd_cwnd_cnt = 0;
	} else {
		tp->snd_cwnd_cnt++;
	}
}

/* RFC2861 Check whether we are limited by application or congestion window
 * This is the inverse of cwnd check in tcp_tso_should_defer
 */
bool tcp_is_cwnd_limited(const struct sock *sk, u32 in_flight)
{	
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 left;

	if (in_flight >= tp->snd_cwnd)
		return true;

	left = tp->snd_cwnd - in_flight;
	if (sk_can_gso(sk) &&
	    left * sock_net(sk)->n_cfg.sysctl_tcp_tso_win_divisor < tp->snd_cwnd &&
	    left * tp->mss_cache < sk->sk_gso_max_size &&
	    left < sk->sk_gso_max_segs)
		return true;
	return left <= tcp_max_tso_deferred_mss(tp);
}


/*
 * TCP Reno congestion control
 * This is special case used for fallback as well.
 */
/* This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	/* In "safe" area, increase. */
	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp);
	/* In dangerous area, increase slowly. */
	else
		tcp_cong_avoid_ai(tp, tp->snd_cwnd);
}

/* Lower bound on congestion window with halving. */
u32 tcp_reno_min_cwnd(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	return tp->snd_ssthresh/2;
}

/* Assign choice of congestion control. */
void tcp_init_congestion_control(struct sock *sk)
{	
	struct inet_connection_sock *icsk = inet_csk(sk);
	//struct tcp_congestion_ops *ca;

#if 0
	/* if no choice made yet assign the current value set as default */
	if (icsk->icsk_ca_ops == &tcp_init_congestion_ops) {
		rcu_read_lock();
		list_for_each_entry_rcu(ca, &tcp_cong_list, list) {
			if (try_module_get(ca->owner)) {
				icsk->icsk_ca_ops = ca;
				break;
			}

			/* fallback to next available */
		}
		rcu_read_unlock();
	}
#endif

	if (icsk->icsk_ca_ops->init)
		icsk->icsk_ca_ops->init(sk);
}


struct tcp_congestion_ops tcp_reno = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "reno",
	//.owner		= THIS_MODULE,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.min_cwnd	= tcp_reno_min_cwnd,
};






