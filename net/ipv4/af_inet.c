/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_INET protocol family socket handler.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Alan Cox, <A.Cox@swansea.ac.uk>
 *
 * Changes (see also sock.c)
 *
 *		piggy,
 *		Karl Knutson	:	Socket protocol table
 *		A.N.Kuznetsov	:	Socket death error in accept().
 *		John Richardson :	Fix non blocking error in connect()
 *					so sockets that fail to connect
 *					don't return -EINPROGRESS.
 *		Alan Cox	:	Asynchronous I/O support
 *		Alan Cox	:	Keep correct socket pointer on sock
 *					structures
 *					when accept() ed
 *		Alan Cox	:	Semantics of SO_LINGER aren't state
 *					moved to close when you look carefully.
 *					With this fixed and the accept bug fixed
 *					some RPC stuff seems happier.
 *		Niibe Yutaka	:	4.4BSD style write async I/O
 *		Alan Cox,
 *		Tony Gale 	:	Fixed reuse semantics.
 *		Alan Cox	:	bind() shouldn't abort existing but dead
 *					sockets. Stops FTP netin:.. I hope.
 *		Alan Cox	:	bind() works correctly for RAW sockets.
 *					Note that FreeBSD at least was broken
 *					in this respect so be careful with
 *					compatibility tests...
 *		Alan Cox	:	routing cache support
 *		Alan Cox	:	memzero the socket structure for
 *					compactness.
 *		Matt Day	:	nonblock connect error handler
 *		Alan Cox	:	Allow large numbers of pending sockets
 *					(eg for big web sites), but only if
 *					specifically application requested.
 *		Alan Cox	:	New buffering throughout IP. Used
 *					dumbly.
 *		Alan Cox	:	New buffering now used smartly.
 *		Alan Cox	:	BSD rather than common sense
 *					interpretation of listen.
 *		Germano Caronni	:	Assorted small races.
 *		Alan Cox	:	sendmsg/recvmsg basic support.
 *		Alan Cox	:	Only sendmsg/recvmsg now supported.
 *		Alan Cox	:	Locked down bind (see security list).
 *		Alan Cox	:	Loosened bind a little.
 *		Mike McLagan	:	ADD/DEL DLCI Ioctls
 *	Willy Konynenberg	:	Transparent proxying support.
 *		David S. Miller	:	New socket lookup architecture.
 *					Some other random speedups.
 *		Cyrus Durgin	:	Cleaned up file for kmod hacks.
 *		Andi Kleen	:	Fix inet_stream_connect TCP race.
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
* @file 			af_inet.c
* @brief			code pieces copied from linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/

#include "types.h"
#include "sock.h"
#include "socket.h"
#include "net.h"
#include "tcp.h"
#include "us_error.h"
#include "glb_var.h"

//int inet_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t size)
int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	//sock_rps_record_flow(sk);
	// We may need to bind the socket. 				//smallboy: tcp_prot  no_autobind == true; ??
	//if (!inet_sk(sk)->inet_num && !sk->sk_prot->no_autobind &&
	//    inet_autobind(sk))
	//	return US_EAGAIN;

	return sk->sk_prot->sendmsg( sk, msg, size);
}

int inet_sendv(struct socket*skt, struct msghdr*msg, size_t size)
{
	struct sock *sk = skt->sk;

	return sk->sk_prot->sendv(sk,msg,size);
}

int inet_recvmsg(struct sock *sk,struct socket*skt)
{	
	int addr_len ;
	int err,ret;
	int target ;
	int cflags;
	char 	*recv_buf = NULL;
	struct msghdr *msg_p = NULL;
	//struct 	us_timer_list	*tp = &skt->recv_callback.timer;
	
	ret = err = 0;
	cflags = skt->recv_callback.cb_arg.ra.cflag;

	if(cflags & CALLBACK_RECV_NOCOPY){
		msg_p = (struct msghdr *)skt->recv_callback.cb_arg.ra.recv_start;
		target = msg_p->msg_controllen;
		if(target != 0)	{	
			err = sk->sk_prot->recvv(skt, msg_p, target,cflags,&addr_len);
		}else{
			err = US_ENOBUFS;
		}
		
		skt->recv_callback.cb(skt,msg_p,err);
	}else{
	US_DEBUG("uuuuuuuuuuuuuuuunknow \n");				
		target = skt->recv_callback.cb_arg.ra.recv_len;
		recv_buf = (char *)skt->recv_callback.cb_arg.ra.recv_start;
		err = sk->sk_prot->recvmsg(skt, recv_buf, target,cflags,&addr_len);

		skt->recv_callback.cb(skt, recv_buf, err);
	}	

	//if(us_timer_pending(tp)){
	//	us_delay_timer(tp,tp->period * 1000);
	//}
	//if (err > 0) {
	//	msg->msg_namelen = addr_len;
	//}
	
	return err;
}

/*
 *	Move a socket into listening state.
 */
int inet_listen(struct socket *skt, int backlog
						,int (*after_accept) (struct socket *a,void *b,  int c))
{	
	struct sock *sk = skt->sk;
	struct net  *pnet = US_PER_LCORE(init_net);
	unsigned char old_state;
	int err;

	//lock_sock(sk);

	err = -EINVAL;
	if (skt->state != SS_UNCONNECTED || skt->type != SOCK_STREAM)
		goto out;

	old_state = sk->sk_state;
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != TCP_LISTEN) {
		/* Check special setups for testing purpose to enable TFO w/o
		 * requiring TCP_FASTOPEN sockopt.
		 * Note that only TCP sockets (SOCK_STREAM) will reach here.
		 * Also fastopenq may already been allocated because this
		 * socket was in TCP_LISTEN state previously but was
		 * shutdown() (rather than close()).
		 */
		if ((pnet->n_cfg.sysctl_tcp_fastopen & TFO_SERVER_ENABLE) != 0 
			&& inet_csk(sk)->icsk_accept_queue.fastopenq == NULL) {
			if ((pnet->n_cfg.sysctl_tcp_fastopen & TFO_SERVER_WO_SOCKOPT1) != 0)
				err = fastopen_init_queue(sk, backlog);
			else if ((pnet->n_cfg.sysctl_tcp_fastopen & TFO_SERVER_WO_SOCKOPT2) != 0)
				err = fastopen_init_queue(sk, ((u32)pnet->n_cfg.sysctl_tcp_fastopen) >> 16);
			else
				err = 0;
			if (err)
				goto out;
		}
		err = inet_csk_listen_start(sk, backlog);
		if (err)
			goto out;
	}
	sk->sk_max_ack_backlog = backlog;
	
	if(after_accept){
		skt->listen_callback.cb = after_accept;
		skt->listen_callback.cb_arg.la.cflag |= CALLBACK_L_LOADED;
		skt->listen_callback.cb_arg.la.cflag |= CALLBACK_L_RELOAD;
		
	}
	
	err = 0;

out:
	//release_sock(sk);			
	return err;
}	

/*
 *	Accept a pending connection. The TCP layer now gives BSD semantics.
 */

int inet_accept(struct sock *sk1, struct socket *skt, int flags)
{	
	int err = US_EINVAL;
	struct socket* newsocket = NULL;
	newsocket = us_socket_alloc(sock_net(sk1));
	if (newsocket == NULL) {
		US_ERR("TH:%u,socket alloc failed here!\n",US_GET_LCORE());
		return US_ENOBUFS;	
	}
		
	struct sock *sk2 = sk1->sk_prot->accept(sk1, flags, &err);
	if(!sk2){
		goto do_err;
	}

	//US_ERR("inet_accept  sk1->ref:%u sk2->ref:%u \n",sk1->sk_refcnt,sk2->sk_refcnt);
	
	sock_graft(sk2, newsocket);			//smallboy: Attention ,parent here;
	
	newsocket->state = SS_CONNECTED;
	newsocket->ops = skt->ops;			//smallboy: Added;
	
	err = US_RET_OK;

	release_sock(sk2);
	skt->listen_callback.cb(newsocket ,NULL,0);	//enter app code;
	
	return err;
do_err:
	us_socket_free(newsocket,sock_net(sk1));
	return err;
}

/*
 *	This does both peername and sockname.
 */
int inet_getname(struct socket *sock, struct sockaddr *uaddr,int *uaddr_len, int peer)
{
	struct sock *sk		= sock->sk;
	struct inet_sock *inet	= inet_sk(sk);
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	//DECLARE_SOCKADDR(struct sockaddr_in *, sin, uaddr);
	
	sin->sin_family = AF_INET;
	if (peer) {
		if (!inet->inet_dport ||
		    (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)) &&
		     peer == 1))
			return -ENOTCONN;
		sin->sin_port = inet->inet_dport;
		sin->sin_addr.s_addr = inet->inet_daddr;
	} else {
		__be32 addr = inet->inet_rcv_saddr;
		if (!addr)
			addr = inet->inet_saddr;
		sin->sin_port = inet->inet_sport;
		sin->sin_addr.s_addr = addr;
	}

	//memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
	memset(sin->__pad, 0, sizeof(sin->__pad));
	*uaddr_len = sizeof(*sin);
	return 0;
}

/*
 *	Connect to a remote host. There is regrettably still a little
 *	TCP 'magic' in here.
 */
int __inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,int addr_len, int flags
							,int (*after_connected) (struct socket *a,void *b , int c))
{
	struct sock *sk = sock->sk;
	int err;
	long timeo;

	if (addr_len < sizeof(uaddr->sa_family))
		return -EINVAL;

	if (uaddr->sa_family == AF_UNSPEC) {
		err = sk->sk_prot->disconnect(sk, flags);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		goto out;
	}

	switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	case SS_CONNECTING:
		err = -EALREADY;
		/* Fall out of switch with err, set for this state */
		break;
	case SS_UNCONNECTED:
		err = -EISCONN;
		if (sk->sk_state != TCP_CLOSE)
			goto out;

		err = sk->sk_prot->connect(sk, uaddr, addr_len);
		if (err < 0)
			goto out;

		sock->state = SS_CONNECTING;

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		err = -EINPROGRESS;
		break;
	}

	timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

	/*
	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		int writebias = (sk->sk_protocol == IPPROTO_TCP) &&
				tcp_sk(sk)->fastopen_req &&
				tcp_sk(sk)->fastopen_req->data ? 1 : 0;

		// Error code is set above 
		if (!timeo || !inet_wait_for_connect(sk, timeo, writebias))
			goto out;

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
	}*/

	/* Connection was closed by RST, timeout, ICMP error
	 * or another process disconnected us.
	 */
	if (sk->sk_state == TCP_CLOSE)
		goto sock_error;

	/* sk->sk_err may be not zero now, if RECVERR was ordered by user
	 * and error was received after socket entered established state.
	 * Hence, it is handled normally after connect() return successfully.
	 */

	sock->state = SS_CONNECTED;
	err = 0;
out:
	return err;

sock_error:
	err = sock_error(sk) ? : -ECONNABORTED;
	sock->state = SS_UNCONNECTED;
	if (sk->sk_prot->disconnect(sk, flags))
		sock->state = SS_DISCONNECTING;
	goto out;
}


int inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,int addr_len, int flags
							,int (*after_connected) (struct socket *a,void *b , int c))
{	
	int err;

	//lock_sock(sock->sk);
	err = __inet_stream_connect(sock, uaddr, addr_len, flags,after_connected);
	//release_sock(sock->sk);
	return err;
}

int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{	
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	unsigned short snum;
	//int chk_addr_ret;
	int err;

	/* If the socket has its own bind function then use it. (RAW) */
	//if (sk->sk_prot->bind) {
	//	err = sk->sk_prot->bind(sk, uaddr, addr_len);
	//	goto out;
	//}

	if(!(sk->sk_type == SOCK_STREAM || sk->sk_type == SOCK_DGRAM)){
		return US_EINVAL;
	}
	
	err = -EINVAL;
	if (addr_len < sizeof(struct sockaddr_in))
		goto out;

	if (addr->sin_family != AF_INET) {
		// Compatibility games : accept AF_UNSPEC (mapped to AF_INET)  only if s_addr is INADDR_ANY.
		
		err = -EAFNOSUPPORT;
		if (addr->sin_family != AF_UNSPEC ||
		    addr->sin_addr.s_addr != htonl(INADDR_ANY))
			goto out;
	}

	//chk_addr_ret = inet_addr_type(net, addr->sin_addr.s_addr);

	/* Not specified by any standard per-se, however it breaks too
	 * many applications when removed.  It is unfortunate since
	 * allowing applications to make a non-local bind solves
	 * several problems with systems using dynamic addressing.
	 * (ie. your servers still start up even if your ISDN link
	 *  is temporarily down)
	 */
	err = -EADDRNOTAVAIL;
	//if (!sysctl_ip_nonlocal_bind &&
	 //   !(inet->freebind || inet->transparent) &&
	 //  addr->sin_addr.s_addr != htonl(INADDR_ANY) &&
	 //   chk_addr_ret != RTN_LOCAL &&
	 //   chk_addr_ret != RTN_MULTICAST &&
	 //   chk_addr_ret != RTN_BROADCAST)
	//	goto out;
	if(!net->n_cfg.sysctl_ip_nonlocal_bind
		&& (addr->sin_addr.s_addr != htonl(INADDR_ANY) ))	//smallboy: No bind local at now;Fix it later;
	{
		goto out;
	}

	snum = ntohs(addr->sin_port);
	err = -EACCES;
	//if (snum && snum < PROT_SOCK &&
	//   !ns_capable(net->user_ns, CAP_NET_BIND_SERVICE))
	//	goto out;

	/*      We keep a pair of addresses. rcv_saddr is the one
	 *      used by hash lookups, and saddr is used for transmit.
	 *
	 *      In the BSD API these are the same except where it
	 *      would be illegal to use them (multicast/broadcast) in
	 *      which case the sending device address is used.
	 */
	//lock_sock(sk);

	/* Check these errors (active socket, double bind). */
	err = -EINVAL;
	if (sk->sk_state != TCP_CLOSE || inet->inet_num)
		goto out_release_sock;

	inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr;
												//smallboy:How to  separate multi address here?										
	//if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
	//	inet->inet_saddr = 0;  /* Use device */

	/* Make sure we are allowed to bind here. */
	if (sk->sk_prot->get_port(sk, snum)) {
		inet->inet_saddr = inet->inet_rcv_saddr = 0;
		err = -EADDRINUSE;
		goto out_release_sock;
	}

	if (inet->inet_rcv_saddr)
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;	
	
	if (snum)
		sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
	
	inet->inet_sport = htons(inet->inet_num);
	inet->inet_daddr = 0;
	inet->inet_dport = 0;

	//sk_dst_reset(sk);
	err = 0;
out_release_sock:
	release_sock(sk);
out:
	return err;
}
/*
 *	The peer socket should always be NULL (or else). When we call this
 *	function we are destroying the object and from then on nobody
 *	should refer to it.
 */
int inet_release(struct socket *sock)
{	
	struct sock *sk = sock->sk;

	if (sk) {
		long timeout;

		//sock_rps_reset_flow(sk);

		/* Applications forget to leave groups before exiting */
		//ip_mc_drop_socket(sk);

		/* If linger is set, we don't return until the close
		 * is complete.  Otherwise we return immediately. The
		 * actually closing is done the same either way.
		 *
		 * If the close is due to the process exiting, we never
		 * linger..
		 */
		timeout = 0;						
		if (sock_flag(sk, SOCK_LINGER))  // && !(current->flags & PF_EXITING)
			timeout = sk->sk_lingertime;  //smallboy: No linger at now;timeout == 0;
		sock->sk = NULL;
		sk->sk_prot->close(sk, timeout);
	}
	return 0;
}

void inet_sock_destruct(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);

	__skb_queue_purge(&sk->sk_receive_queue);
	//__skb_queue_purge(&sk->sk_cache_head);
	//__skb_queue_purge(&sk->sk_error_queue);		//smallboy: Fix it later,what about the others;

	sk_mem_reclaim(sk);

	if (sk->sk_type == SOCK_STREAM && sk->sk_state != TCP_CLOSE) {
		US_LOG("Attempt to release TCP socket in state %d %p\n",sk->sk_state, sk);
		return;
	}
	
	if (!sock_flag(sk, SOCK_DEAD)) {
		US_LOG("Attempt to release alive inet socket %p\n", sk);
		return;
	}

	//WARN_ON(atomic_read(&sk->sk_rmem_alloc));
	//WARN_ON(atomic_read(&sk->sk_wmem_alloc));
	//WARN_ON(sk->sk_wmem_queued);
	//WARN_ON(sk->sk_forward_alloc);
	free(inet->inet_opt);  //smallboy:always be zero;

	//kfree(rcu_dereference_protected(inet->inet_opt, 1));
	//dst_release(rcu_dereference_check(sk->sk_dst_cache, 1));
	//dst_release(sk->sk_rx_dst);
	//sk_refcnt_debug_dec(sk);
}

int inet_shutdown(struct socket *sock, int how)
{
#if 0
	struct sock *sk = sock->sk;
	int err = 0;

	/* This should really check to make sure
	 * the socket is a TCP socket. (WHY AC...)
	 */
	how++; /* maps 0->1 has the advantage of making bit 1 rcvs and
		       1->2 bit 2 snds.
		       2->3 */
	if ((how & ~SHUTDOWN_MASK) || !how)	/* MAXINT->0 */
		return -EINVAL;

	lock_sock(sk);
	if (sock->state == SS_CONNECTING) {
		if ((1 << sk->sk_state) &
		    (TCPF_SYN_SENT | TCPF_SYN_RECV | TCPF_CLOSE))
			sock->state = SS_DISCONNECTING;
		else
			sock->state = SS_CONNECTED;
	}

	switch (sk->sk_state) {
	case TCP_CLOSE:
		err = -ENOTCONN;
		/* Hack to wake up other listeners, who can poll for
		   POLLHUP, even on eg. unconnected UDP sockets -- RR */
	default:
		sk->sk_shutdown |= how;
		if (sk->sk_prot->shutdown)
			sk->sk_prot->shutdown(sk, how);
		break;

	/* Remaining two branches are temporary solution for missing
	 * close() in multithreaded environment. It is _not_ a good idea,
	 * but we have no choice until close() is repaired at VFS level.
	 */
	case TCP_LISTEN:
		if (!(how & RCV_SHUTDOWN))
			break;
		/* Fall through */
	case TCP_SYN_SENT:
		err = sk->sk_prot->disconnect(sk, O_NONBLOCK);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		break;
	}

	/* Wake up anyone sleeping in poll. */
	sk->sk_state_change(sk);
	release_sock(sk);
	return err;
#endif
	return 0;
}


const struct proto_ops inet_stream_ops = {
	.family		   = PF_INET,
	//.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_stream_connect,
	//.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = inet_getname,
	//.poll		   = tcp_poll,
	//.ioctl		   = inet_ioctl,
	.listen		   = inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.sendv		   = inet_sendv,
	//.recvv	   = inet_recvv,
	//.mmap		   = sock_no_mmap,
	//.sendpage	   = inet_sendpage,
	//.splice_read	   = tcp_splice_read,
//#ifdef CONFIG_COMPAT
//	.compat_setsockopt = compat_sock_common_setsockopt,
//	.compat_getsockopt = compat_sock_common_getsockopt,
//	.compat_ioctl	   = inet_compat_ioctl,
//#endif
};




