/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			socket.h
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/ 


#ifndef _US_SOCKET_H
#define _US_SOCKET_H

#include "types.h"
#include "net.h"
#include "sock.h"
#include "us_timer.h"
#include "glb_var.h"

struct socket;

/* Address to accept any incoming messages. */
#define	INADDR_ANY		((unsigned long int) 0x00000000)


/* Supported address families. */
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_AX25		3	/* Amateur Radio AX.25 		*/
#define AF_IPX		4	/* Novell IPX 			*/
#define AF_APPLETALK	5	/* AppleTalk DDP 		*/
#define AF_NETROM	6	/* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_ATMPVC	8	/* ATM PVCs			*/
#define AF_X25		9	/* Reserved for X.25 project 	*/
#define AF_INET6	10	/* IP version 6			*/
#define AF_ROSE		11	/* Amateur Radio X.25 PLP	*/
#define AF_DECnet	12	/* Reserved for DECnet project	*/
#define AF_NETBEUI	13	/* Reserved for 802.2LLC project*/
#define AF_SECURITY	14	/* Security callback pseudo AF */
#define AF_KEY		15      /* PF_KEY key management API */
#define AF_NETLINK	16
#define AF_ROUTE	AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET	17	/* Packet family		*/
#define AF_ASH		18	/* Ash				*/
#define AF_ECONET	19	/* Acorn Econet			*/
#define AF_ATMSVC	20	/* ATM SVCs			*/
#define AF_RDS		21	/* RDS sockets 			*/
#define AF_SNA		22	/* Linux SNA Project (nutters!) */
#define AF_IRDA		23	/* IRDA sockets			*/
#define AF_PPPOX	24	/* PPPoX sockets		*/
#define AF_WANPIPE	25	/* Wanpipe API Sockets */
#define AF_LLC		26	/* Linux LLC			*/
#define AF_CAN		29	/* Controller Area Network      */
#define AF_TIPC		30	/* TIPC sockets			*/
#define AF_BLUETOOTH	31	/* Bluetooth sockets 		*/
#define AF_IUCV		32	/* IUCV sockets			*/
#define AF_RXRPC	33	/* RxRPC sockets 		*/
#define AF_ISDN		34	/* mISDN sockets 		*/
#define AF_PHONET	35	/* Phonet sockets		*/
#define AF_IEEE802154	36	/* IEEE802154 sockets		*/
#define AF_CAIF		37	/* CAIF sockets			*/
#define AF_ALG		38	/* Algorithm sockets		*/
#define AF_NFC		39	/* NFC sockets			*/
#define AF_VSOCK	40	/* vSockets			*/
#define AF_MAX		41	/* For now.. */

/* Protocol families, same as address families. */
#define PF_UNSPEC	AF_UNSPEC
#define PF_UNIX		AF_UNIX
#define PF_LOCAL	AF_LOCAL
#define PF_INET		AF_INET
#define PF_AX25		AF_AX25
#define PF_IPX		AF_IPX
#define PF_APPLETALK	AF_APPLETALK
#define	PF_NETROM	AF_NETROM
#define PF_BRIDGE	AF_BRIDGE
#define PF_ATMPVC	AF_ATMPVC
#define PF_X25		AF_X25
#define PF_INET6	AF_INET6
#define PF_ROSE		AF_ROSE
#define PF_DECnet	AF_DECnet
#define PF_NETBEUI	AF_NETBEUI
#define PF_SECURITY	AF_SECURITY
#define PF_KEY		AF_KEY
#define PF_NETLINK	AF_NETLINK
#define PF_ROUTE	AF_ROUTE
#define PF_PACKET	AF_PACKET
#define PF_ASH		AF_ASH
#define PF_ECONET	AF_ECONET
#define PF_ATMSVC	AF_ATMSVC
#define PF_RDS		AF_RDS
#define PF_SNA		AF_SNA
#define PF_IRDA		AF_IRDA
#define PF_PPPOX	AF_PPPOX
#define PF_WANPIPE	AF_WANPIPE
#define PF_LLC		AF_LLC
#define PF_CAN		AF_CAN
#define PF_TIPC		AF_TIPC
#define PF_BLUETOOTH	AF_BLUETOOTH
#define PF_IUCV		AF_IUCV
#define PF_RXRPC	AF_RXRPC
#define PF_ISDN		AF_ISDN
#define PF_PHONET	AF_PHONET
#define PF_IEEE802154	AF_IEEE802154
#define PF_CAIF		AF_CAIF
#define PF_ALG		AF_ALG
#define PF_NFC		AF_NFC
#define PF_VSOCK	AF_VSOCK
#define PF_MAX		AF_MAX

#define O_ACCMODE	00000003
#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002
#ifndef O_CREAT
#define O_CREAT		00000100	/* not fcntl */
#endif
#ifndef O_EXCL
#define O_EXCL		00000200	/* not fcntl */
#endif
#ifndef O_NOCTTY
#define O_NOCTTY	00000400	/* not fcntl */
#endif
#ifndef O_TRUNC
#define O_TRUNC		00001000	/* not fcntl */
#endif
#ifndef O_APPEND
#define O_APPEND	00002000
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK	00004000
#endif
#ifndef O_DSYNC
#define O_DSYNC		00010000	/* used to be O_SYNC, see below */
#endif
#ifndef FASYNC
#define FASYNC		00020000	/* fcntl, for BSD compatibility */
#endif
#ifndef O_DIRECT
#define O_DIRECT	00040000	/* direct disk access hint */
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE	00100000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY	00200000	/* must be a directory */
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW	00400000	/* don't follow links */
#endif
#ifndef O_NOATIME
#define O_NOATIME	01000000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC	02000000	/* set close_on_exec */
#endif

/* Flags we can use with send/ and recv. 
   Added those for 1003.1g not all are supported yet
 */
 
#define MSG_OOB			1
#define MSG_PEEK		2
#define MSG_DONTROUTE	4
#define MSG_TRYHARD     4       /* Synonym for MSG_DONTROUTE for DECnet */
#define MSG_CTRUNC		8
#define MSG_PROBE		0x10	/* Do not send. Only probe path f.e. for MTU */
#define MSG_TRUNC		0x20
#define MSG_DONTWAIT	0x40	/* Nonblocking io		 */
#define MSG_EOR         0x80	/* End of record */
#define MSG_WAITALL		0x100	/* Wait for a full request */
#define MSG_FIN         0x200
#define MSG_SYN			0x400
#define MSG_CONFIRM		0x800	/* Confirm path validity */
#define MSG_RST			0x1000
#define MSG_ERRQUEUE	0x2000	/* Fetch message from error queue */
#define MSG_NOSIGNAL	0x4000	/* Do not generate SIGPIPE */
#define MSG_MORE		0x8000	/* Sender will send more */
#define MSG_WAITFORONE	0x10000	/* recvmmsg(): block until 1+ packets avail */
#define MSG_SENDPAGE_NOTLAST 0x20000 /* sendpage() internal : not the last page */
#define MSG_EOF         MSG_FIN

//smallboy;

#define CALLBACK_L_LOADED		0x40000  //(0x1<< 18)
#define CALLBACK_R_LOADED		0x80000	 // (0x1<< 19)
#define CLALBACK_C_LOADED		0x100000 //(0x1<< 20)
#define CALLBACK_RECV_NOCOPY	0x200000 //(0x1<< 21)
#define CALLBACK_RECV_RELOAD	0x400000 //(0x1<< 22)
#define CALLBACK_L_RELOAD		0x800000 //(0x1<< 23)
#define CALLBACK_R_RELOAD		0x1000000 //(0x1<< 24)

#define CALLBACK_C_RELOAD		0x8000000 //(0x1<< 27) 


#define MSG_FASTOPEN		0x20000000	/* Send data in TCP SYN */
#define MSG_CMSG_CLOEXEC 	0x40000000	/* Set close_on_exit for file
					   descriptor received through
					   SCM_RIGHTS */


/* For setsockopt(2) */
#define SOL_SOCKET	1

/* Setsockoptions(2) level. Thanks to BSD these must match IPPROTO_xxx */
#define SOL_IP		0
/* #define SOL_ICMP	1	No-no-no! Due to Linux :-) we cannot use SOL_ICMP=1 */
#define SOL_TCP		6
#define SOL_UDP		17
#define SOL_IPV6	41


#define SO_DEBUG	1
#define SO_REUSEADDR	2
#define SO_TYPE		3
#define SO_ERROR	4
#define SO_DONTROUTE	5
#define SO_BROADCAST	6
#define SO_SNDBUF	7
#define SO_RCVBUF	8
#define SO_SNDBUFFORCE	32
#define SO_RCVBUFFORCE	33
#define SO_KEEPALIVE	9
#define SO_OOBINLINE	10
#define SO_NO_CHECK	11
#define SO_PRIORITY	12
#define SO_LINGER	13
#define SO_BSDCOMPAT	14
#define SO_REUSEPORT	15
#ifndef SO_PASSCRED /* powerpc only differs in these */
#define SO_PASSCRED	16
#define SO_PEERCRED	17
#define SO_RCVLOWAT	18
#define SO_SNDLOWAT	19
#define SO_RCVTIMEO	20
#define SO_SNDTIMEO	21
#endif

/* Security levels - as per NRL IPv6 - don't actually do anything */
#define SO_SECURITY_AUTHENTICATION		22
#define SO_SECURITY_ENCRYPTION_TRANSPORT	23
#define SO_SECURITY_ENCRYPTION_NETWORK		24

#define SO_BINDTODEVICE	25

/* Socket filtering */
#define SO_ATTACH_FILTER	26
#define SO_DETACH_FILTER	27
#define SO_GET_FILTER		SO_ATTACH_FILTER

#define SO_PEERNAME		28
#define SO_TIMESTAMP		29
#define SCM_TIMESTAMP		SO_TIMESTAMP

#define SO_ACCEPTCONN		30

#define SO_PEERSEC		31
#define SO_PASSSEC		34
#define SO_TIMESTAMPNS		35
#define SCM_TIMESTAMPNS		SO_TIMESTAMPNS

#define SO_MARK			36

#define SO_TIMESTAMPING		37
#define SCM_TIMESTAMPING	SO_TIMESTAMPING

#define SO_PROTOCOL		38
#define SO_DOMAIN		39

#define SO_RXQ_OVFL             40

#define SO_WIFI_STATUS		41
#define SCM_WIFI_STATUS	SO_WIFI_STATUS
#define SO_PEEK_OFF		42

/* Instruct lower device to use last 4-bytes of skb data as FCS */
#define SO_NOFCS		43

#define SO_LOCK_FILTER		44

#define SO_SELECT_ERR_QUEUE	45

#define	MAX_SCHEDULE_TIMEOUT	LONG_MAX


typedef unsigned short __kernel_sa_family_t;
typedef __kernel_sa_family_t	sa_family_t;

/*
 *	1003.1g requires sa_family_t and that sa_data is char.
 */
 
struct sockaddr {
	sa_family_t	sa_family;	/* address family, AF_xxx	*/
	char		sa_data[14];	/* 14 bytes of protocol address	*/
};


/*
 * Desired design of maximum size and alignment (see RFC2553)
 */
#define _K_SS_MAXSIZE	128	/* Implementation specific max size */
#define _K_SS_ALIGNSIZE	(__alignof__ (struct sockaddr *))
				/* Implementation specific desired alignment */


struct __kernel_sockaddr_storage {
	__kernel_sa_family_t	ss_family;		/* address family */
	/* Following field(s) are implementation specific */
	char		__data[_K_SS_MAXSIZE - sizeof(unsigned short)];
				/* space to achieve desired size, */
				/* _SS_MAXSIZE value minus size of ss_family */
} __attribute__ ((aligned(_K_SS_ALIGNSIZE)));	/* force desired alignment */


#define sockaddr_storage __kernel_sockaddr_storage

/* Internet address. */
struct in_addr {
	__be32	s_addr;
};

/* Structure describing an Internet (IP) socket address. */
#define __SOCK_SIZE__	16		/* sizeof(struct sockaddr)	*/

struct sockaddr_in {
  __kernel_sa_family_t	sin_family;	/* Address family		*/
  __be16				sin_port;	/* Port number			*/
  struct in_addr		sin_addr;	/* Internet address		*/

  /* Pad to size of `struct sockaddr'. */
  unsigned char		__pad[__SOCK_SIZE__ - sizeof(short int) -
			sizeof(unsigned short int) - sizeof(struct in_addr)];
};

typedef unsigned long 	__kernel_size_t;

struct iovec
{
	void __user *iov_base;		/* BSD uses caddr_t (1003.1g requires void *) */
	__kernel_size_t iov_len; 	/* Must be size_t (1003.1g) */
	void 		*meta_data;		//smallboy:skb;
};


/*
 *	As we do 4.4BSD message passing we use a 4.4BSD message passing
 *	system, not 4.3. Thus msg_accrights(len) are now missing. They
 *	belong in an obscure libc emulation or the bin.
 */
 
struct msghdr {
	void			*msg_name;	/* Socket name			*/
	int				msg_namelen;	/* Length of name		*/
	struct iovec 	*msg_iov;	/* Data blocks			*/
	__kernel_size_t	msg_iovlen;	/* Number of blocks		*/
	void 			*msg_control;	/* Per protocol magic (eg BSD file descriptor passing) */
	__kernel_size_t	msg_controllen;	/* Length of cmsg list */
	unsigned int	msg_flags;
};


#define SOCK_ASYNC_NOSPACE			0
#define SOCK_ASYNC_WAITDATA			1
#define SOCK_NOSPACE				2
#define SOCK_PASSCRED				3
#define SOCK_PASSSEC				4
#define SOCK_EXTERNALLY_ALLOCATED 	5
/////	Added by smallboy;
#define SOCK_FIN_PENDING			6
#define SOCK_READ_ACCESS			7


#define CALLBACK_RECV_TIMEOUT_DEFAULT	(180)
#define CALLBACK_CONN_TIMEOUT_DEFAULT	(12)




/**
 * enum sock_type - Socket types
 * @SOCK_STREAM: stream (connection) socket
 * @SOCK_DGRAM: datagram (conn.less) socket
 * @SOCK_RAW: raw socket
 * @SOCK_RDM: reliably-delivered message
 * @SOCK_SEQPACKET: sequential packet socket
 * @SOCK_DCCP: Datagram Congestion Control Protocol socket
 * @SOCK_PACKET: linux specific way of getting packets at the dev level.
 *		  For writing rarp and other similar things on the user level.
 *
 * When adding some new socket type please
 * grep ARCH_HAS_SOCKET_TYPE include/asm-* /socket.h, at least MIPS
 * overrides this enum for binary compat reasons.
 */
enum sock_type {
	SOCK_STREAM	= 1,
	SOCK_DGRAM	= 2,
	SOCK_RAW	= 3,
	SOCK_RDM	= 4,
	SOCK_SEQPACKET	= 5,
	SOCK_DCCP	= 6,
	SOCK_PACKET	= 10,
};


typedef enum {
	SS_FREE = 0,			/* not allocated		*/
	SS_UNCONNECTED,			/* unconnected to any socket	*/
	SS_CONNECTING,			/* in process of connecting	*/
	SS_CONNECTED,			/* connected to socket		*/
	SS_DISCONNECTING		/* in process of disconnecting	*/
} socket_state;


typedef int (*socket_callback) (struct socket *arg,void *arg1, int arg2);

typedef struct __callback_func_arg{
	unsigned long	arg1;
	unsigned long	arg2;
}callback_func_arg;

typedef struct __us_callback{
	socket_callback	 cb;
	union	{
	    callback_func_arg cb_a;
		struct {
			u32 cflag;
			u32 r1;
			u64 r2;
		}la;
		struct {
			u32 cflag;
			u32 recv_len;
			u64 recv_start;
		}ra;
		struct {
			u32 cflag;
			u32 r1;
			u64 r2;
		}ca;	
	}cb_arg;
	struct 	us_timer_list	timer;
}us_socket_callback;	

struct us_netio_event{
	struct sock 	*sk;
	struct socket 	*skt;
	u16				read_ev;
	u16				write_ev;
	u16				err_ev;
	u16				unknown;
};

struct us_netio_events{
	struct us_netio_event		netio_events[US_MAX_EVENT_BURST];
	s32 						netio_event_index;
};

struct us_netio_evb{
	struct us_netio_events	ev_b[2];
	u32						evb_index;		// 0 or 1;
};

struct linger
{
	int l_onoff;
	int l_linger;
};

struct proto_ops;

/**
 *  struct socket - general BSD socket
 *  @state: socket state (%SS_CONNECTED, etc)
 *  @type: socket type (%SOCK_STREAM, etc)
 *  @flags: socket flags (%SOCK_ASYNC_NOSPACE, etc)
 *  @ops: protocol specific socket operations
 *  @file: File back pointer for gc
 *  @sk: internal networking protocol agnostic socket representation
 *  @wq: wait queue for several uses
 */
struct socket {
	socket_state				state;
	short						type;
	unsigned long				flags;
	int 						magic_id;  //socket_id
	void						*obj;
	void		(*obj_destruct)(unsigned long data); 	
	struct sock					*sk;
	us_socket_callback			recv_callback;
	us_socket_callback			listen_callback;
	us_socket_callback			connect_callback;
	struct us_netio_event		net_ev;
	//struct socket_wq __rcu	*wq;
	const struct proto_ops		*ops;
};

struct proto_ops {
	int		family;
	//struct module	*owner;
	int		(*release)   (struct socket *);
	int		(*bind)	     (struct socket *,struct sockaddr *,int );
	int		(*connect)   (struct socket *,struct sockaddr *,int , int
				,int (*after_connected) (struct socket *a,void *b , int c) );
//	int		(*socketpair)(struct socket *,struct socket *);
	int		(*accept)    (struct sock *,struct socket *, int );
	int		(*getname)   (struct socket *,struct sockaddr *,int *, int );
//	unsigned int (*poll) (struct file *, struct socket *, struct poll_table_struct *);
//	int		(*ioctl)     (struct socket *sock, unsigned int cmd,unsigned long arg);
	int		(*listen)    (struct socket *, int
							,int (*after_accept) (struct socket *a,void *b,  int c));
	int		(*shutdown)  (struct socket *, int );
	int		(*setsockopt)(struct socket *, int ,int , char __user *, unsigned int );
	int		(*getsockopt)(struct socket *, int ,int , char __user *, int __user *);
//#ifdef CONFIG_COMPAT
//	int	 	(*compat_ioctl) (struct socket *sock, unsigned int cmd, unsigned long arg);
//	int		(*compat_setsockopt)(struct socket *sock, int level,int optname, char __user *optval, unsigned int optlen);
//	int		(*compat_getsockopt)(struct socket *sock, int level,int optname, char __user *optval, int __user *optlen);
//#endif
	int		(*sendmsg)   (struct socket *,struct msghdr *, size_t );
	int 	(*sendv)	(struct socket *,struct msghdr *, size_t );	
	/* Notes for implementing recvmsg:
	 * ===============================
	 * msg->msg_namelen should get updated by the recvmsg handlers
	 * iff msg_name != NULL. It is by default 0 to prevent
	 * returning uninitialized memory to user space.  The recvfrom
	 * handlers can assume that msg.msg_name is either NULL or has
	 * a minimum size of sizeof(struct sockaddr_storage).
	 */
	int		(*recvmsg)   ( struct sock *,struct socket * ); //, size_t ,int
//	int 	(*recvv)	(struct sock *,struct socket *);
//	int		(*mmap)	     (struct file *file, struct socket *sock,struct vm_area_struct * vma);
//	ssize_t	(*sendpage)  (struct socket *sock, struct page *page,int offset, size_t size, int flags);
//	ssize_t (*splice_read)(struct socket *sock,  loff_t *ppos,struct pipe_inode_info *pipe, size_t len, unsigned int flags);
//	void	(*set_peek_off)(struct sock *sk, int val);
};



extern int us_socket_create(struct net *net, int family, int type, int protocol,struct socket **res);
extern inline int sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size);
extern struct socket *us_socket(int family, int type, int protocol);
extern s32 us_bind(struct socket*sock, struct sockaddr __user * umyaddr, int addrlen);
extern s32 us_getsockname(struct socket*skt,struct sockaddr *name,int *namelen);
extern s32 us_getpeername(struct socket*skt,struct sockaddr *name,int *namelen);

extern s32 us_listen(struct socket*sock, int backlog
				,int (*after_accept) (struct socket *a,void *b, int c));

extern s32 us_connect(struct socket*sock, struct sockaddr __user *uservaddr, int addrlen, int flags
				,int (*after_connected) (struct socket *a,void *b ,int c)
				,void (*timeout_clean) (unsigned long data));

extern s32 us_recv_set(struct socket*skt, char *buf, int buf_len,int flags
							,int (*after_recv) (struct socket *arg,void *arg1, int arg2)
							,void (*timeout_clean)(unsigned long data));
extern s32 us_recvv_set(struct socket*skt, struct msghdr*msg, int flags
							,int (*after_recv) (struct socket *arg,void *arg1, int arg2)
							,void (*timeout_clean)(unsigned long data));

extern s32 us_recv_from_set(struct socket*skt, char *buf, int len,int flags
						,int (*after_recv) (struct socket *arg,void *arg1, int arg2)
						,void (*timeout_clean) (unsigned long data));

extern s32 us_recv(struct socket*skt, char *buf, int len,int flags);
extern s32 us_sendto(struct socket*sock, void __user *buff, size_t len, int flags
				, struct sockaddr __user * addr,int addr_len);
extern s32 us_send(struct socket*sock,void __user *buff, size_t len, int flags);
extern s32 us_sendv(struct socket*skt,struct msghdr*msg,int flags);
extern s32 us_seg_moveto(struct msghdr*msg, struct socket*from,struct socket*to,int flags);
extern s32 us_read_eof(struct socket *skt);
extern s32 us_read_ready(struct socket *skt);
extern s32 us_getsockopt(struct socket*skt,int level, int optname,char __user *optval, int __user *optlen);
extern s32 us_setsockopt(struct socket*skt,int level, int optname,char __user *optval, int __user optlen);

extern s32 us_close(struct socket*sock);
extern s32 netio_ev_init(void);


extern struct socket *us_socket_alloc(struct net*pnet);
extern void us_socket_free(struct socket *sock,struct net*pnet);

static inline s32 us_callback_l_loaded(struct socket*skt)
{
	return (skt->listen_callback.cb_arg.la.cflag & CALLBACK_L_LOADED);
}

static inline s32 us_callback_l_reloaded(struct socket *skt)
{	
	return ((skt->listen_callback.cb_arg.la.cflag & CALLBACK_L_RELOAD)
			&&(us_callback_l_loaded(skt)));
}

static inline s32 us_callback_c_loaded(struct socket*skt)
{
	return (skt->connect_callback.cb_arg.ca.cflag & CLALBACK_C_LOADED);
}

static inline s32 us_callback_c_reloaded(struct socket*skt)
{
	return ((skt->connect_callback.cb_arg.ca.cflag & CALLBACK_C_RELOAD)
				&&us_callback_c_loaded(skt));
}

static inline s32 us_callback_r_loaded(struct socket*skt)
{
	return (skt->recv_callback.cb_arg.ra.cflag & CALLBACK_R_LOADED);
}

static inline s32 us_callback_r_reloaded(struct socket*skt)
{
	return ((skt->recv_callback.cb_arg.ra.cflag & CALLBACK_R_RELOAD)
				&&(us_callback_r_loaded(skt)));
}

static inline s32 us_callback_r_reload(struct socket*skt)
{
	int ret = 0;
	us_socket_callback	*ca = &skt->recv_callback;
	
	if(!us_callback_r_loaded(skt))
		return US_EPIPE;
	if(us_callback_r_reloaded(skt)){
		ret = 1;
	}else{
		ret = 0;	
	}
	
	skt->recv_callback.cb_arg.ra.cflag |= CALLBACK_R_RELOAD;
	
	while(skt->net_ev.read_ev-- > 0){		
		us_sk_event_insert(skt->sk,US_POLL_IN);
	}
	
	skt->net_ev.read_ev = 0;

	if(ca->timer.period){
		__us_mod_timer(&ca->timer, jiffies + ca->timer.period * 1000);
	}
	
	return ret;	
}

static inline s32 us_callback_r_unload(struct socket *skt)
{
	us_socket_callback	*ca = &skt->recv_callback;
	if(!us_callback_r_loaded(skt))
		return US_EPIPE;
	if(!us_callback_r_reloaded(skt)){
		return 1;
	}else{	
		skt->recv_callback.cb_arg.ra.cflag &= ~CALLBACK_R_RELOAD;
		us_del_timer(&ca->timer);
		return 0;
	}
}

static inline s32 us_callback_c_reload(struct socket*skt)
{
	if(!us_callback_c_loaded(skt))
		return US_EPIPE;
	if(us_callback_c_reloaded(skt)){
		return 1;
	}else{
		skt->connect_callback.cb_arg.ca.cflag |= CALLBACK_C_RELOAD;
		if(skt->net_ev.write_ev > 0){
			us_sk_event_insert(skt->sk,US_POLL_OUT);
		}
		skt->net_ev.write_ev = 0;
		return 0;		
	}
}

static inline s32 us_callback_c_unload(struct socket *skt)
{
	if(!us_callback_c_loaded(skt))
		return US_EPIPE;
	if(!us_callback_c_reloaded(skt)){
		return 1;
	}else{
		skt->connect_callback.cb_arg.ca.cflag &= ~CALLBACK_C_RELOAD;
		return 0;
	}
}

static inline void us_socket_obj_set(struct socket *skt,void *obj
			,void(*destruct)(unsigned long data))
{
	skt->obj = obj;
	skt->obj_destruct = destruct;
}

static inline void us_socket_obj_unset(struct socket*skt)
{
	skt->obj = NULL;
	skt->obj_destruct = NULL;
}

static inline bool us_socket_valid(struct socket*skt)
{
	return (skt && (skt->magic_id == US_SOCKET_MAGIC)) ;

}

#endif
