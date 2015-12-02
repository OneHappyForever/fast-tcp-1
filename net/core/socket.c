/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			socket.c
* @brief			us_* interface for ustack, who's core function is the same with linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/ 


#include "glb_var.h"
#include "tcp.h"
#include "sock.h"
#include "socket.h"
#include "net.h"
#include "us_mem.h"
#include "us_error.h"
#include "us_util.h"

//US_DEFINE_PER_LCORE(us_netio_evb *,evb);
//US_DEFINE_PER_LCORE(us_netio_events *,reload_ev);

US_DECLARE_PER_LCORE(struct proto*, tcp_prot);

extern const struct proto_ops inet_stream_ops;

struct socket *us_socket_alloc(struct net *pnet)
{
#if 0
	u32 socket_id = 0;
	us_objslab 	*us_p = pnet->socket_slab;
	struct socket	*skt = us_memobj_slab_alloc(us_p);
	if(skt){
		socket_id = skt->socket_id;
		memset(skt, 0, sizeof(struct socket));
		skt->socket_id = socket_id;
		skt->state = SS_UNCONNECTED;
	}

	return skt;
#else
	s32 ret ;
	u32 socket_id;	
	struct socket	*sock = NULL;

	ret = us_slab_get(pnet->socket_pool ,(void**)&sock);
	//ret = us_slab_get(US_PER_LCORE(socket_pool),(void**)&sock);
	if(unlikely(ret < 0)){
		sock = NULL;
	}else{
		socket_id = sock->magic_id;  //socket_id
		memset(sock, 0, sizeof(struct socket));
		sock->magic_id = socket_id;
		sock->state = SS_UNCONNECTED;
		//us_init_timer(&sock->dt.list,0,TIMER_TYPE_NONE);
	}

	return sock;
#endif	
}

void us_socket_free(struct socket *sock,struct net*pnet)
{
	if (sock){
		//us_memobj_slab_free(sock);
		us_slab_free(pnet->socket_pool,sock);
		//us_slab_free(US_PER_LCORE(socket_pool),sock);
	}
}

int us_socket_create(struct net *pnet, int family, int type, int protocol,struct socket **res)
{
	s32 err = US_RET_OK;
	s32 skc_id = 0;
	struct socket 		*skt;
	struct sock			*sk;
	struct inet_sock 	*inet;
	struct proto 		*prot_p = NULL;
	
	if(family  !=  PF_INET){
		return US_EAFNOSUPPORT;
	}

	if(!(type == SOCK_STREAM || type == SOCK_DGRAM)){
		return US_EINVAL;
	}

	if(protocol == IPPROTO_IP){
		if(type == SOCK_STREAM){
			protocol = IPPROTO_TCP;
		}else{
			protocol = IPPROTO_UDP;
		}
	}else{
		if( protocol != IPPROTO_TCP){
			return US_EPROTONOSUPPORT;
		}
	}

	skt = us_socket_alloc(pnet);
	if (!skt) {
		US_ERR("socket: no more sockets\n");
		*res = NULL;
		return US_ENFILE;	
	}

	skt->state	= SS_UNCONNECTED;
	
	skt->type	= type;
	if(skt->type == SOCK_STREAM){
		skt->ops = &inet_stream_ops;
		prot_p = US_PER_LCORE(tcp_prot);
		skt->flags	= INET_PROTOSW_ICSK|INET_PROTOSW_PERMANENT;
	}else{
		US_ERR("TH:%d,Not supported at now!\n",US_GET_LCORE());
		err = US_EPROTONOSUPPORT;
		goto fail_out;
	}

	sk = us_sock_alloc(pnet);
	if(!sk) {
		US_ERR("sock: no more socks\n");
		err= US_ENFILE;
		goto fail_out;	
	}
	
	skc_id = sk->sk_id;
	memset(sk,0,sizeof(struct sock));
	sk->sk_id = skc_id;

	sk->sk_family = family;
	sk->sk_prot  =  prot_p;
	sk->sk_prot_creator = prot_p;
	sk->sk_net = pnet;
	sk->sk_no_check = 0;			//smallboy: udp csum related;
	sk->sk_reuse = SK_NO_REUSE;		//smallboy: Fix it here;  SK_CAN_REUSE ?? 
	sk->sk_wmem_alloc = 1;

	inet = inet_sk(sk);
	inet->is_icsk = (skt->type == SOCK_STREAM);
	inet->nodefrag = 0;
	
	inet->pmtudisc = pnet->n_cfg.sysclt_no_pmtu_disc ? IP_PMTUDISC_DONT : IP_PMTUDISC_WANT;
	inet->inet_id = 0;

	sock_init_data(skt, sk);

	sk->sk_destruct	  	= inet_sock_destruct;

	sock_set_flag(sk, SOCK_FASYNC);   ////smallboy:always be fasync here;	

	sk->sk_protocol	   	= protocol;
	sk->sk_userlocks 	= (SOCK_SNDBUF_LOCK|SOCK_RCVBUF_LOCK); //smallboy:No mem adjust at now;Fix it later;
	
	inet->uc_ttl	= -1;
	inet->mc_loop	= 1;		//smallboy: No multicast supported;
	inet->mc_ttl	= 1;
	inet->mc_all	= 1;
	inet->mc_index	= 0;
	//inet->mc_list	= NULL;
	inet->rcv_tos	= 0;


	//if (inet->inet_num) {					//smallboy: Fix it later;
	// It assumes that any protocol which allows the user to assign a number at socket
	// creation time automatically shares.	
	//	inet->inet_sport = htons(inet->inet_num); Add to protocol hash chains.
	//	sk->sk_prot->hash(sk);
	//}

	sk_setup_caps(sk);

	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err){
			//sk_common_release(sk);
			us_sock_free(sk);			//smallboy:single is simple; so no kfree_sock;
			goto fail_out;
		}
	}

	*res = skt;
	sk->sk_socket = skt;
	
	return US_RET_OK;

fail_out:
	us_socket_free(skt,pnet);
	*res = NULL;
	return err;
}

struct socket *us_socket(int family, int type, int protocol)
{
	int retval ;
	struct socket 	*sock = NULL;
	struct net		*pnet = US_PER_LCORE(init_net); 
	retval = us_socket_create(pnet,family, type, protocol, &sock);
	if (retval < 0){
		US_ERRNO = retval;
		return NULL;
	}else{
		US_ERRNO = US_RET_OK;
		return sock;
	}
}

s32 us_bind(struct socket*sock, struct sockaddr __user * umyaddr, int addrlen)
{
	s32 err = US_EINVAL;

	if (addrlen <= 0 || addrlen > sizeof(struct sockaddr_storage))
		return US_EINVAL;
	//if (ulen == 0)
	//	return 0;
	
	if(sock){
		err = sock->ops->bind(sock, umyaddr, addrlen);
	}
	US_ERRNO = err;
	return err;
}

s32 us_getsockname(struct socket*skt,struct sockaddr *name,int *namelen)
{
	s32 err = US_RET_OK;
	if(skt == NULL || name == NULL || namelen == NULL
		|| skt->sk == NULL)
		return US_EINVAL;
	
	err = skt->ops->getname(skt, name, namelen, 0);
	return err;
}

s32 us_getpeername(struct socket*skt,struct sockaddr *name,int *namelen)
{
	s32 err = US_RET_OK;
	if(skt == NULL || name == NULL || namelen == NULL
		|| skt->state != SS_CONNECTED || skt->sk == NULL)
		return US_EINVAL;
	
	err = skt->ops->getname(skt, name, namelen, 1);
	return err;
}


s32 us_listen(struct socket*skt, int backlog
				,int (*after_accept) (struct socket *a,void *b,  int c))	//s32 us_listen(int fd, int backlog)
{		
	int err = 0;
	struct net *pnet = US_PER_LCORE(init_net);
	
	if(skt == NULL || after_accept == NULL){
		return US_EINVAL;
	}
	
	if(backlog > pnet->n_cfg.sysctl_somaxconn)
		backlog = pnet->n_cfg.sysctl_somaxconn;
	if(backlog <= 0)
		backlog	= 1;

	err = skt->ops->listen(skt, backlog ,after_accept);
	if(err >= 0)
		skt->state = SS_CONNECTED ;			//smallboy : Added;
	return err;
}

s32 us_connect(struct socket*sock, struct sockaddr __user *uservaddr, int addrlen, int flags
				,int (*after_connected) (struct socket *a,void *b ,int c)
				,void (*timeout_clean) (unsigned long data))
{
	struct timeval opt;
	struct us_timer_list *tp ;
	us_socket_callback	*cb_p;
	
	s32 err = US_EINVAL;
	s32 ret = 0;
	u32 timeout = 0;
	int  opt_len = sizeof(opt);
	
	if (addrlen <= 0 || addrlen > sizeof(struct sockaddr_storage) || sock->sk == NULL)
		return US_EINVAL;
	
	err = sock->ops->connect(sock, uservaddr, addrlen, flags, after_connected);
	if(err >= 0){
		sock->connect_callback.cb = after_connected;

		flags |= CLALBACK_C_LOADED;
		flags |= CALLBACK_C_RELOAD;
		flags |= MSG_DONTWAIT;
		sock->connect_callback.cb_arg.ca.cflag = flags;

		if(timeout_clean){
			ret = us_getsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char *)&opt,&opt_len);
			if(ret < 0 || opt.tv_sec == 0){
				timeout = CALLBACK_CONN_TIMEOUT_DEFAULT;
			}else{
				timeout = opt.tv_sec;
			}

			US_DEBUG("us_connect timeout:%d \n",timeout);

			cb_p = &sock->connect_callback;
			tp = &cb_p->timer;		

			if(tp->magic != TIMER_MAGIC){					//init once only and no recv timeout here ;
				us_init_timer(tp,0,TIMER_TYPE_USER1);	
				tp->expires = jiffies + timeout*1000;
				tp->data = (unsigned long )sock;
				tp->function = timeout_clean ;//us_recv_callback;
				us_add_timer(tp);
			}else{
				__us_mod_timer(tp,jiffies + timeout*1000);
			}			
		}
	}
	
	return err;
}

s32 us_recv_set(struct socket*skt, char *buf, int len,int flags
							,int (*after_recv) (struct socket *arg,void *arg1, int arg2)
							,void (*timeout_clean) (unsigned long data))
{
	s32 err = US_EINVAL;
	struct sock *sk = NULL;

	if(skt == NULL || skt->state == SS_FREE ||skt->sk == NULL ){			
		return err;
	}
	
	sk = skt->sk;
	if(sk->sk_state == TCP_LISTEN){
		return err;
	}
	//reload callback here;
	err = us_recv_from_set(skt, buf, len, flags,after_recv,timeout_clean);
	return err;
}

s32 us_recvv_set(struct socket*skt, struct msghdr *msg,int flags
							,int (*after_recv) (struct socket *arg,void *arg1, int arg2)
							,void (*timeout_clean) (unsigned long data))
{
	s32 err = US_EINVAL;
	struct sock *sk = NULL;

	if(skt == NULL || skt->state == SS_FREE ||skt->sk == NULL  
		|| msg == NULL || msg->msg_iov == NULL || msg->msg_controllen == 0 
			|| !msghdr_magic_ok(msg)){			
		return err;
	}
	
	sk = skt->sk;
	if(sk->sk_state == TCP_LISTEN){
		return err;
	}

	//reload callback here;
	err = us_recv_from_set(skt,(char *)msg,0,flags|CALLBACK_RECV_NOCOPY,after_recv,timeout_clean);
	return err;
}

static s32 us_recv_from(struct socket*skt, char *buf, int len,int flags)
{
	int ret = 0;
	int addr_len ;
	struct sock *sk = skt->sk;
	
	ret = sk->sk_prot->recvmsg(skt, buf, len,flags,&addr_len);
	return ret;
}

static s32 us_recvv_from(struct socket*skt, struct msghdr *msg,int flags)
{
	int ret = 0;
	int addr_len ;
	struct sock *sk = skt->sk;

	if(msg->msg_controllen == 0)
		return US_ENOBUFS;
	
	ret = sk->sk_prot->recvv(skt, msg, msg->msg_controllen,flags,&addr_len);
	return ret;
}


s32 us_recv(struct socket*skt, char *buf, int len,int flags)
{
	s32 err = US_EINVAL;
	struct sock *sk = NULL;

	if(skt == NULL || skt->state == SS_FREE ||skt->sk == NULL ){			
		return err;
	}
	
	sk = skt->sk;
	if(sk->sk_state == TCP_LISTEN){
		return err;
	}
	//reload callback here;
	err = us_recv_from(skt, buf, len, flags);
	return err;
}

s32 us_recvv(struct socket*skt, struct msghdr *msg,int flags)
{
	s32 err = US_EINVAL;
	struct sock *sk = NULL;

	if(skt == NULL || skt->state == SS_FREE ||skt->sk == NULL ){			
		return err;
	}
	
	sk = skt->sk;
	if(sk->sk_state == TCP_LISTEN){
		return err;
	}
	//reload callback here;
	err = us_recvv_from(skt, msg, flags);
	return err;

}

s32 us_getsockopt(struct socket*skt,int level, int optname,char __user *optval, int __user *optlen)
{
	s32 ret ;
	if(skt == NULL || skt->state == SS_FREE||skt->sk == NULL || optval == NULL || optlen == NULL){
		return US_EINVAL;
	}

	if(level == SOL_SOCKET){
		ret = sock_getsockopt(skt, level, optname, optval,optlen);
	}else{
		ret = skt->ops->getsockopt(skt, level, optname, optval, optlen);
	}

	return ret;
}

s32 us_setsockopt(struct socket*skt,int level, int optname,char __user *optval, int __user optlen)
{
	s32 ret ;

	if(skt == NULL || skt->state == SS_FREE||skt->sk == NULL || optval == NULL || optlen <= 0){
		return US_EINVAL;
	}

	if(level == SOL_SOCKET){
		ret = sock_setsockopt(skt, level, optname, optval,optlen);
	}else{
		ret = skt->ops->setsockopt(skt, level, optname, optval, optlen);
	}

	return ret;
}

s32 us_read_eof(struct socket *skt)
{	
	return test_bit(SOCK_FIN_PENDING, &skt->flags);
}

s32 us_read_ready(struct socket *skt)
{
	return test_bit(SOCK_READ_ACCESS, &skt->flags);
}

/*
//time_out  or  err ;
void us_recv_callback(unsigned long data)		//smallboy:More attention here and the connect;
{
	struct socket *skt = (struct socket*) data;
	if(test_bit(SOCK_CALLBACK_TIMEOUT ,&skt->flags))	{			//Attention about the reload;
		US_LOG("TH:%u,socket:%u recv timeout!\n",US_GET_LCORE(),skt->socket_id);	
		us_close(skt);
	}else{
		US_ERR("TH:%u,socket:%u recv error!\n",US_GET_LCORE(),skt->socket_id);
		us_close(skt);
	}
}*/

s32 us_recv_from_set(struct socket*skt, char *buf,int len,int flags
						,int (*after_recv) (struct socket *arg,void *arg1, int arg2)
						,void (*timeout_clean) (unsigned long data))
{
	int ret;
	struct timeval opt;
	int  opt_len = sizeof(opt);
	struct us_timer_list *tp = NULL;
	struct msghdr *msg = (struct msghdr*)buf;
	u16	timeout = 0;
	us_socket_callback	*cb_p = &skt->recv_callback;
	tp = &cb_p->timer;

	ret = us_getsockopt(skt,SOL_SOCKET,SO_RCVTIMEO,(char *)&opt,&opt_len);

	if(ret < 0 || (opt.tv_sec == 0)){
		timeout = CALLBACK_RECV_TIMEOUT_DEFAULT;
	}else{
		timeout = opt.tv_sec;
	}

	if(!(flags & CALLBACK_RECV_RELOAD)){
		if(!after_recv){
			return US_EINVAL;
		}
	}else{
		goto reload;
	}
		
	if(flags & CALLBACK_RECV_NOCOPY ){
		if(!(msg->msg_controllen > 0)){
			return US_EINVAL;
		}
	}else{
		if( len <= 0){
			return US_EINVAL;
		}
	}

	cb_p->cb_arg.ra.recv_start = (u64)buf;
	cb_p->cb_arg.ra.recv_len   = len;

	if(cb_p->cb == NULL && after_recv == NULL)
		return US_EINVAL;
	
	if(after_recv)
		cb_p->cb = after_recv;

	flags |= MSG_DONTWAIT;
	flags &= ~MSG_OOB;
	flags |= CALLBACK_R_LOADED;
	flags |= CALLBACK_R_RELOAD;
	
	cb_p->cb_arg.ra.cflag = flags;
	//cb_p->cb_arg.ra.flags |=  MSG_DONTWAIT;		//smallboy:Always be nonblock;
	//cb_p->cb_arg.ra.flags &=  ~MSG_OOB;

	if(timeout_clean) {
		if(tp->magic != TIMER_MAGIC){
			us_init_timer(tp,timeout,TIMER_TYPE_USER1);	
			tp->expires = jiffies + timeout*1000;
			tp->data = (unsigned long )skt;
			tp->function = timeout_clean ;				//us_recv_callback
			us_add_timer(tp);
		}else{
			__us_mod_timer(tp,jiffies + timeout*1000);
			tp->period = timeout;
		}
	}else{
		if(us_timer_pending(tp)){
			us_del_timer(tp);
			tp->period  = 0;		//so that we would not reload it uncorrectly;
		}
	}

	return 0;

reload:
	if(timeout_clean) {			//while reload, after_recv == timeout_clean == NULL;
		return EINVAL;
	}else{
		if(us_timer_pending(tp)){
			tp->period   = timeout;
			__us_mod_timer(tp,jiffies + timeout*1000);
		}
		return 0;
	}
}

s32 us_sendto(struct socket*sock, void __user *buff, size_t len, int flags
				, struct sockaddr __user * addr,int addr_len)
{
	s32 err = US_RET_OK;
	if (sock == NULL || sock->state != SS_CONNECTED || addr_len > sizeof(struct sockaddr_storage))
		return US_EINVAL;

	if (len == 0)
		return US_RET_OK;
	
	struct msghdr msg;
	struct iovec iov;
	iov.iov_base = buff;
	iov.iov_len = len;
	msg.msg_name = NULL;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = 0;

	if (addr) {
		msg.msg_name = addr;
		msg.msg_namelen = addr_len;
	}

	msg.msg_flags = flags;
	err = sock_sendmsg(sock, &msg, len);

	return err;
}

s32 us_send(struct socket*sock,void __user *buff, size_t len, int flags)
{
	return us_sendto(sock,buff,len,flags|MSG_DONTWAIT,NULL,0);  //smallboy:Always be nonblocking;
}

//@brief,move skb in msg into the wirte queue of the socket;
s32 us_sendv(struct socket*skt,struct msghdr*msg,int flags)
{
	s32 ret,i;
	struct iovec *iov = NULL;
	msg->msg_flags = flags;
	msg->msg_namelen = 0;
	msg->msg_name = NULL;

	if(!msghdr_magic_ok(msg))
		return US_EINVAL;
	
	if(skt && skt->state == SS_CONNECTED){
		ret = sock_sendv(skt, msg, msg->msg_iovlen);
		if(ret > 0){
			iov = &msg->msg_iov[0];
			for(i= ret; i< msg->msg_controllen;i++){
				memcpy(iov,&msg->msg_iov[i],sizeof(struct iovec));
				memset(&msg->msg_iov[i],0,sizeof(struct iovec));
				iov++;
			}
			msg->msg_iovlen = msg->msg_iovlen - ret;
		}
	}else{
		ret = US_EPIPE;
	}
	
	return ret;
}

//@brief,move skb into write queue of socket to and free the quato then;
//Attention:from could be zero;
s32 us_seg_moveto(struct msghdr*msg, struct socket*from,struct socket*to,int flags)
{
	int ret ;
	//int left;
	int adjust = 0;
	
	if((!msghdr_magic_ok(msg))|| to == NULL || msg->msg_iovlen == 0){
		us_abort(1);
		return US_EINVAL;
	}

	struct iovec 	*iov = &msg->msg_iov[0];
	struct sk_buff 	*skb = (struct sk_buff*)iov->meta_data;

	if(us_socket_valid(from)){   		//from != NULL
		if(skb->sk != from->sk){
			return US_EINVAL;
		}
		//flags = flags|MSG_FORCE_UNLINK ;
		//adjust = 1;
	}else{
		return US_EINVAL;
	}
	
	//left = msg->msg_iovlen;
	ret = us_sendv(to, msg, flags);
	//smallboy: Attention !mem and mbuf adjust here;	
	
	return ret;
}

void us_callback_cancel(struct socket *skt)
{
	skt->listen_callback.cb_arg.la.cflag = 0;
	skt->recv_callback.cb_arg.ra.cflag = 0;
	skt->connect_callback.cb_arg.ca.cflag = 0;
	//us_del_timer(&skt->listen_callback.timer);  //Not be used;
	
	us_del_timer(&skt->recv_callback.timer);
	us_del_timer(&skt->connect_callback.timer);
}

s32 us_close(struct socket*skt)
{	
	struct net*pnet = NULL;
	//US_DEBUG("TH:%u,func:%s,%u skt->id:%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__,skt->magic_id);

	if (us_socket_valid(skt) && (skt->state != SS_FREE) && skt->ops) {
		if(skt->obj_destruct){
			skt->obj_destruct((unsigned long )skt->obj);
			us_socket_obj_unset(skt);
		}

		pnet = sock_net(skt->sk);
		//pnet = US_PER_LCORE(init_net);
		skt->ops->release(skt);

		skt->ops = NULL;
		skt->state = SS_FREE;					//smallboy:Fix it here;  

		us_callback_cancel(skt);
		us_socket_free(skt,pnet);
	}	

	return 0;
}

s32 netio_ev_init(void)
{	/*
	//us_netio_evb	*evb_p = &US_PER_LCORE(evb);
	//us_netio_events	*re_evp= &US_PER_LCORE(reload_ev);
	//memset(evb_p,0,sizeof(us_netio_evb));
	//memset(re_evp,0,sizeof(us_netio_events));

	us_netio_evb *evb_p = (us_netio_evb*)us_zmalloc(NULL,sizeof(us_netio_evb),SMP_CACHE_BYTES);
	us_netio_events *re_evp = (us_netio_events*)us_zmalloc(NULL,sizeof(us_netio_events),SMP_CACHE_BYTES);
	if(!(evb_p != NULL && re_evp != NULL)){
		return US_ENOMEM;
	}

	US_PER_LCORE(evb) = evb_p;
	US_PER_LCORE(reload_ev) = re_evp;
	*/
	return US_RET_OK;
}

int us_socket_test(void)
{
	s32 ret ,ip;
	u16 local_port = 0;	
	struct socket *listener1  = NULL;
	struct socket *connecter1 = NULL;

	ret = inet_pton(AF_INET, "192.168.30.111", &ip);
	if(ret < 0){
		US_ERR("us_app_stub init dest ip failed!\n");
		return ret;
	}

	glb_dest_ip = ip;
	
	ret = inet_pton(AF_INET, "192.168.30.76", &ip);
	if(ret < 0){
		US_ERR("us_app_stub init client ip failed!\n");
		return ret;
	}

	glb_client_ip = ip;
	struct sockaddr_in	*paddr;
	struct sockaddr_in  server;
	struct sockaddr		getaddr;
	int					getaddr_len;
	/*
	local_port = 1;
	do {	
		memset(&server,0,sizeof(struct sockaddr_in));

		server.sin_family	= AF_INET;
		server.sin_port 	= htons(local_port);
		server.sin_addr.s_addr = htonl(INADDR_ANY);

		listener1 = us_socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
		if(listener1 == NULL){
			US_ERR("TH:%u,server1 socket create failed!\n",US_GET_LCORE());
			return US_RET_OK;
		}
		
		if(us_bind(listener1,(struct sockaddr *)&server,sizeof(struct sockaddr))<0){
			US_ERR("TH:%u,server1 socket bind failed!port:%u errono:%d\n",US_GET_LCORE(),local_port,US_ERRNO);
			us_close(listener1);
			return US_RET_OK;
		}

		extern int us_server_request_handle (struct socket *skt,void *arg, int b);

		if(us_listen(listener1,256,us_server_request_handle)<0){
			US_ERR("TH:%u,server1 socket listen failed!\n",US_GET_LCORE());
			us_close(listener1);
			return US_RET_OK;		//smallboy: Fix it here ; replace it here with a  cmd pipe;
		}

		local_port++;
		US_DEBUG("us_bind success on local port:%u \n",local_port);
	}while(true);	
	*/

	/*
	do{
		memset(&server,0,sizeof(struct sockaddr_in));
		server.sin_family	= AF_INET;
		server.sin_port 	= 0;
		server.sin_addr.s_addr = htonl(INADDR_ANY);

		connecter1 = us_socket(AF_INET,SOCK_STREAM,IPPROTO_IP);;	 
		if(NULL == connecter1){
			US_ERR("TH:%u,server1 socket create failed!\n",US_GET_LCORE());
			break;
		}

		if(us_bind(connecter1,(struct sockaddr *)&server,sizeof(struct sockaddr))<0){
			US_ERR("TH:%u,server1 socket bind failed! errono:%d\n",US_GET_LCORE(),US_ERRNO);
			us_close(connecter1);
			break;
		}

		if((ret = us_getsockname(connecter1, &getaddr, &getaddr_len)) < 0){		
			US_ERR("TH:%u us_getsockname for skt failed! errno:%d \n",US_GET_LCORE(),US_ERRNO);
			us_close(connecter1);
			break;
		}else{
			paddr = (struct sockaddr_in*) &getaddr;
			US_LOG("addr:%s,local_port:%d \n",trans_ip(paddr->sin_addr.s_addr),ntohs(paddr->sin_port));
		}
		
	}while(true); */

	
	memset(&server,0,sizeof(struct sockaddr_in));
	
	server.sin_family	= AF_INET;
	server.sin_port 	= htons(80);
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	listener1 = us_socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	if(listener1 == NULL){
		US_ERR("TH:%u,server1 socket create failed!\n",US_GET_LCORE());
		return US_RET_OK;
	}
	
	if(us_bind(listener1,(struct sockaddr *)&server,sizeof(struct sockaddr))<0){
		US_ERR("TH:%u,server1 socket bind failed!port:%u errono:%d\n",US_GET_LCORE(),local_port,US_ERRNO);
		us_close(listener1);
		return US_RET_OK;
	}

	extern int us_server_request_handle (struct socket *skt,void *arg, int b);

	if(us_listen(listener1,256,us_server_request_handle)<0){
		US_ERR("TH:%u,server1 socket listen failed!\n",US_GET_LCORE());
		us_close(listener1);
		return US_RET_OK;		//smallboy: Fix it here ; replace it here with a  cmd pipe;
	}

	/*	
	if((ret= us_listen(listener1,256,us_server_request_handle))<0){
		US_ERR("TH:%u,server1 socket listen failed! errno:%d \n",US_GET_LCORE(),ret);
		us_close(listener1);
		return US_RET_OK;		//smallboy: Fix it here ; replace it here with a  cmd pipe;
	}*/

	/*
	if(us_client_init(10)<0){
		US_ERR("TH:%u,client init failed!\n",US_GET_LCORE());
		return US_RET_OK;
	}*/

	
	
	return US_RET_OK;
}

