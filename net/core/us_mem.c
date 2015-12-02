/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_mem.c
* @brief			function for all the mem init;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/

#include "us_mem.h"
#include "us_rte.h"
#include "us_error.h"
#include "skbuff.h"
#include "sock.h"
#include "socket.h"
#include "inet_sock.h"
#include "tcp.h"
#include "inet_timewait_sock.h"
#include "inet_hashtables.h"
#include "us_entry.h"


US_DEFINE_PER_LCORE(us_ring*,ring);
US_DEFINE_PER_LCORE(us_mempool*,sock_pool);
US_DEFINE_PER_LCORE(us_mempool*,socket_pool);
US_DEFINE_PER_LCORE(us_mempool*,sk_head_pool);

US_DEFINE_PER_LCORE(us_mempool*,tcp_metric_pool);
US_DEFINE_PER_LCORE(us_mempool*,sk_req_pool);
US_DEFINE_PER_LCORE(us_mempool*,sk_tw_pool);
US_DEFINE_PER_LCORE(us_mempool*,mbuf_pool_s);
US_DEFINE_PER_LCORE(us_mempool*,ibbucket_pool);

US_DEFINE_PER_LCORE(us_objslabs*,buffer_slab);

US_DEFINE_PER_LCORE(us_mempool*,mbuf_pool_r);   //smallboy: ustack ,for debug info;


US_DEFINE_PER_LCORE(us_objslab*,sk_req_slab);
US_DEFINE_PER_LCORE(us_objslab*,sk_tw_slab);
US_DEFINE_PER_LCORE(us_objslab*,socket_slab);



US_DECLARE_PER_LCORE(struct inet_hashinfo*, tcp_hashinfo);

us_mempool		*mbuf_rp[APP_MAX_IO_LCORES] = {NULL};	
us_ring			*io_ring[APP_MAX_IO_LCORES] = {NULL};

u32	glb_sock_num = 0;
u32	glb_socket_num = 0;
u32	glb_sk_buff_num = 0;
u32	glb_mbuf_num = 0;
u32 glb_r_mbuf_id_max = 0;

volatile s32 glb_us_init_token 	= 18;
volatile u64 glb_us_init_through = 0;

/*
#define US_SOCK_NAME(a)		("SOCKPOOL"#a)
#define US_SOCKET_NAME(a)	("SOCKETPOOL"#a)
#define US_SK_BUFF_NAME(a)	("SK_BUFF_POOL"#a)
#define US_SK_REQ_NAME(a)	("SK_REQ_POOL"#a)
#define US_SK_TW_NAME(a)	("SK_TW_POOL"#a)
#define US_IBBUCKET_NAME(a)	("IBBUCKET_POOL"#a)
#define US_MBUF_S_NAME(a)	("MBUF_SEND_POOL"#a)
#define US_LHASH_NAME(a)	("LHASH_NAME"#a)
#define US_EHASH_NAME(a)	("EHASH_NAME"#a)
#define US_BHASH_NAME(a)	("BHASH_NAME"#a)
#define US_MBUF_R_NAME(a)	("MBUF_RECV_POOL"#a)
#define US_RING_NAME(a)		("IO_RING"#a)
*/


////US_LCORE_MAX  //warning here;
/*char *US_BIP_VEC[24] =  
	{"192.169.39.10","192.169.39.11","192.169.39.12","192.169.39.13","192.169.39.14"
	 ,"192.169.39.15","192.169.39.16","192.169.39.17","192.169.39.18","192.169.39.19","192.169.39.20"
	 ,"192.169.39.21","192.169.39.22","192.169.39.23","192.169.39.24","192.169.39.25","192.169.39.26"
	 ,"192.169.39.27","192.169.39.28","192.169.39.29","192.169.39.30","192.169.39.31","192.169.39.32"
	 ,"192.169.39.33"};
*/
char *US_BIP_VEC[24] =  
	{"192.168.29.10","192.168.29.11","192.168.29.12","192.168.29.13","192.168.29.14"
	 ,"192.168.29.15","192.168.29.16","192.168.29.17","192.168.29.18","192.168.29.19","192.168.29.20"
	 ,"192.168.29.21","192.168.29.22","192.168.29.23","192.168.29.24","192.168.29.25","192.168.29.26"
	 ,"192.168.29.27","192.168.29.28","192.168.29.29","192.168.29.30","192.168.29.31","192.168.29.32"
	 ,"192.168.29.33"};

char *US_SOCK_VEC[US_LCORE_MAX] =
	{"SOCK_POOL0","SOCK_POOL1","SOCK_POOL2","SOCK_POOL3","SOCK_POOL4","SOCK_POOL5","SOCK_POOL6",
		"SOCK_POOL7","SOCK_POOL8","SOCK_POOL9","SOCK_POOL10","SOCK_POOL11","SOCK_POOL12","SOCK_POOL13",
		"SOCK_POOL14","SOCK_POOL15","SOCK_POOL16","SOCK_POOL17","SOCK_POOL18","SOCK_POOL19","SOCK_POOL20",
		"SOCK_POOL21","SOCK_POOL22","SOCK_POOL23"};

char *US_SOCKET_VEC[US_LCORE_MAX] =
	{"SOCKET_POOL0","SOCKET_POOL1","SOCKET_POOL2","SOCKET_POOL3","SOCKET_POOL4","SOCKET_POOL5"
		,"SOCKET_POOL6","SOCKET_POOL7","SOCKET_POOL8","SOCKET_POOL9","SOCKET_POOL10","SOCKET_POOL11"
		,"SOCKET_POOL12","SOCKET_POOL13","SOCKET_POOL14","SOCKET_POOL15","SOCKET_POOL16","SOCKET_POOL17"
		,"SOCKET_POOL18","SOCKET_POOL19","SOCKET_POOL20","SOCKET_POOL21","SOCKET_POOL22","SOCKET_POOL23"};

char *US_SKBUFF_VEC[US_LCORE_MAX] =
	{"SKBUFF_POOL0","SKBUFF_POOL1","SKBUFF_POOL2","SKBUFF_POOL3","SKBUFF_POOL4","SKBUFF_POOL5"
		,"SKBUFF_POOL6","SKBUFF_POOL7","SKBUFF_POOL8","SKBUFF_POOL9","SKBUFF_POOL10","SKBUFF_POOL11"
		,"SKBUFF_POOL12","SKBUFF_POOL13","SKBUFF_POOL14","SKBUFF_POOL15","SKBUFF_POOL16","SKBUFF_POOL17"
		,"SKBUFF_POOL18","SKBUFF_POOL19","SKBUFF_POOL20","SKBUFF_POOL21","SKBUFF_POOL22","SKBUFF_POOL23"};

char *US_TMETRIC_VEC[US_LCORE_MAX] =
	{"TMETRIC_POOL0","TMETRIC_POOL1","TMETRIC_POOL2","TMETRIC_POOL3","TMETRIC_POOL4","TMETRIC_POOL5"
		,"TMETRIC_POOL6","TMETRIC_POOL7","TMETRIC_POOL8","TMETRIC_POOL9","TMETRIC_POOL10","TMETRIC_POOL11"
		,"TMETRIC_POOL12","TMETRIC_POOL13","TMETRIC_POOL14","TMETRIC_POOL15","TMETRICF_POOL16","TMETRIC_POOL17"
		,"TMETRIC_POOL18","TMETRIC_POOL19","TMETRIC_POOL20","TMETRIC_POOL21","TMETRIC_POOL22","TMETRIC_POOL23"};


char *US_REQ_VEC[US_LCORE_MAX] =
	{"REQSOCK_POOL0","REQSOCK_POOL1","REQSOCK_POOL2","REQSOCK_POOL3","REQSOCK_POOL4","REQSOCK_POOL5"
		,"REQSOCK_POOL6","REQSOCK_POOL7","REQSOCK_POOL8","REQSOCK_POOL9","REQSOCK_POOL10","REQSOCK_POOL11"
		,"REQSOCK_POOL12","REQSOCK_POOL13","REQSOCK_POOL14","REQSOCK_POOL15","REQSOCK_POOL16","REQSOCK_POOL17"
		,"REQSOCK_POOL18","REQSOCK_POOL19","REQSOCK_POOL20","REQSOCK_POOL21","REQSOCK_POOL22","REQSOCK_POOL23"};

char *US_TW_VEC[US_LCORE_MAX] = 
	{"TWSOCK_POOL0","TWSOCK_POOL1","TWSOCK_POOL2","TWSOCK_POOL3","TWSOCK_POOL4","TWSOCK_POOL5"
		,"TWSOCK_POOL6","TWSOCK_POOL7","TWSOCK_POOL8","TWSOCK_POOL9","TWSOCK_POOL10","TWSOCK_POOL11"
		,"TWSOCK_POOL12","TWSOCK_POOL13","TWSOCK_POOL14","TWSOCK_POOL15","TWSOCK_POOL16","TWSOCK_POOL17"
		,"TWSOCK_POOL18","TWSOCK_POOL19","TWSOCK_POOL20","TWSOCK_POOL21","TWSOCK_POOL22","TWSOCK_POOL23"};

char *US_IBB_VEC[US_LCORE_MAX] = 
	{"IBBUCKET_POOL0","IBBUCKET_POOL1","IBBUCKET_POOL2","IBBUCKET_POOL3","IBBUCKET_POOL4","IBBUCKET_POOL5"
		,"IBBUCKET_POOL6","IBBUCKET_POOL7","IBBUCKET_POOL8","IBBUCKET_POOL9","IBBUCKET_POOL10","IBBUCKET_POOL11"
		,"IBBUCKET_POOL12","IBBUCKET_POOL13","IBBUCKET_POOL14","IBBUCKET_POOL15","IBBUCKET_POOL16","IBBUCKET_POOL17"
		,"IBBUCKET_POOL18","IBBUCKET_POOL19","IBBUCKET_POOL20","IBBUCKET_POOL21","IBBUCKET_POOL22","IBBUCKET_POOL23"};

char *US_MBUFS_VEC[US_LCORE_MAX] =
	{"MBUFS_POOL0","MBUFS_POOL1","MBUFS_POOL2","MBUFS_POOL3","MBUFS_POOL4","MBUFS_POOL5"
		,"MBUFS_POOL6","MBUFS_POOL7","MBUFS_POOL8","MBUFS_POOL9","MBUFS_POOL10","MBUFS_POOL11"
		,"MBUFS_POOL12","MBUFS_POOL13","MBUFS_POOL14","MBUFS_POOL15","MBUFS_POOL16","MBUFS_POOL17"
		,"MBUFS_POOL18","MBUFS_POOL19","MBUFS_POOL20","MBUFS_POOL21","MBUFS_POOL22","MBUFS_POOL23"};

char *US_MBUFR_VEC[US_LCORE_MAX] =
	{"MBUFR_POOL0","MBUFR_POOL1","MBUFR_POOL2","MBUFR_POOL3","MBUFR_POOL4","MBUFR_POOL5"
		,"MBUFR_POOL6","MBUFR_POOL7","MBUFR_POOL8","MBUFR_POOL9","MBUFR_POOL10","MBUFR_POOL11"
		,"MBUFR_POOL12","MBUFR_POOL13","MBUFR_POOL14","MBUFR_POOL15","MBUFR_POOL16","MBUFR_POOL17"
		,"MBUFR_POOL18","MBUFR_POOL19","MBUFR_POOL20","MBUFR_POOL21","MBUFR_POOL22","MBUFR_POOL23"};

char *US_LHASH_VEC[US_LCORE_MAX] =
	{"LHASHZONE0","LHASHZONE1","LHASHZONE2","LHASHZONE3","LHASHZONE4","LHASHZONE5"
		,"LHASHZONE6","LHASHZONE7","LHASHZONE8","LHASHZONE9","LHASHZONE10","LHASHZONE11"
		,"LHASHZONE12","LHASHZONE13","LHASHZONE14","LHASHZONE15","LHASHZONE16","LHASHZONE17"
		,"LHASHZONE18","LHASHZONE19","LHASHZONE20","LHASHZONE21","LHASHZONE22","LHASHZONE23"};

char *US_BHASH_VEC[US_LCORE_MAX] = 
	{"BHASHZONE0","BHASHZONE1","BHASHZONE2","BHASHZONE3","BHASHZONE4","BHASHZONE5"
		,"BHASHZONE6","BHASHZONE7","BHASHZONE8","BHASHZONE9","BHASHZONE10","BHASHZONE11"
		,"BHASHZONE12","BHASHZONE13","BHASHZONE14","BHASHZONE15","BHASHZONE16","BHASHZONE17"
		,"BHASHZONE18","BHASHZONE19","BHASHZONE20","BHASHZONE21","BHASHZONE22","BHASHZONE23"};
	
char *US_EHASH_VEC[US_LCORE_MAX] =
	{"EHASHZONE0","EHASHZONE1","EHASHZONE2","EHASHZONE3","EHASHZONE4","EHASHZONE5"
		,"EHASHZONE6","EHASHZONE7","EHASHZONE8","EHASHZONE9","EHASHZONE10","EHASHZONE11"
		,"EHASHZONE12","EHASHZONE13","EHASHZONE14","EHASHZONE15","EHASHZONE16","EHASHZONE17"
		,"EHASHZONE18","EHASHZONE19","EHASHZONE20","EHASHZONE21","EHASHZONE22","EHASHZONE23"};

char *US_MHASH_VEC[US_LCORE_MAX] =
	{"TCPMHASHZONE0","TCPMHASHZONE1","TCPMHASHZONE2","TCPMHASHZONE3","TCPMHASHZONE4","TCPMHASHZONE5"
		,"TCPMHASHZONE6","TCPMHASHZONE7","TCPMHASHZONE8","TCPMHASHZONE9","TCPMHASHZONE10","TCPMHASHZONE11"
		,"TCPMHASHZONE12","TCPMHASHZONE13","TCPMHASHZONE14","TCPMHASHZONE15","TCPMHASHZONE16","TCPMHASHZONE17"
		,"TCPMHASHZONE18","TCPMHASHZONE19","TCPMHASHZONE20","TCPMHASHZONE21","TCPMHASHZONE22","TCPMHASHZONE23"};


char *US_RING_VEC[US_LCORE_MAX] =
	{"IO_RING0","IO_RING1","IO_RING2","IO_RING3","IO_RING4","IO_RING5"
		,"IO_RING6","IO_RING7","IO_RING8","IO_RING9","IO_RING10","IO_RING11"};

static void us_sock_mem_init(us_mempool *mp,void *opaque_arg, void *m, unsigned i)
{
	struct sock *sk = m;
	sk->sk_id = ++glb_sock_num;		// All be inited during the master booting;
	
	return ;
}

static void us_socket_mem_init(us_mempool *mp,void *opaque_arg, void *m, unsigned i)
{
	struct socket *sk = m;
	sk->magic_id = US_SOCKET_MAGIC;		// All be inited during the master booting;
	//sk->socket_id = ++glb_socket_num;
	return ;
}

static void us_sk_buff_mem_init(us_mempool *mp,void *opaque_arg, void *m, unsigned i)
{
	struct sk_buff *sk_head = m;
	sk_head->skb_id = ++glb_sk_buff_num;		// All be inited during the master booting;
	
	return ;
}

void us_pktmbuf_init(struct rte_mempool *mp,
		 __attribute__((unused)) void *opaque_arg,
		 void *_m, __attribute__((unused)) unsigned i)
{
	rte_pktmbuf_init(mp,opaque_arg,_m,i);
	struct rte_mbuf *m = _m;

	rte_mbuf_ref_set(m,0);
	rte_mbuf_id_set(m,glb_mbuf_num++);
}

void us_tcpm_block_init(struct rte_mempool *mp,
		 __attribute__((unused)) void *opaque_arg,
		 void *_m, __attribute__((unused)) unsigned i)
{
	rte_pktmbuf_init(mp,opaque_arg,_m,i);
	struct tcp_metrics_block *m = _m;
	m->tcpm_id	= glb_mbuf_num++ ;
}


static s32 us_sock_mempool_init(s32 delta)
{
	u32 i = US_GET_LCORE();
	u32 socket = US_GET_SOCKET(i);
	
	US_PER_LCORE(sock_pool) = US_MEMPOOL_CREATE(
			US_SOCK_VEC[i+delta], US_SOCK_NB_LCORE, sizeof(struct tcp_sock), 65536,
			0, 
			NULL, NULL,
			us_sock_mem_init, NULL,
			socket, MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);

	US_ERRNO = rte_errno;
	if(US_PER_LCORE(sock_pool) == NULL){
		US_ERR("sock mempool init failed for locre: %u:%u :%s  errno:%u \n",i,i+delta,US_SOCK_VEC[i+delta],US_ERRNO);
		return US_ENOMEM;
	}else{
		US_LOG("sock mempool init successfully for locre: %u\n",i);
	}

	return US_RET_OK;
}

static s32 us_sk_head_mempool_init(s32 delta)
{
	u32 i = US_GET_LCORE();
	u32 socket = US_GET_SOCKET(i);
	

	US_PER_LCORE(sk_head_pool) = US_MEMPOOL_CREATE(
			US_SKBUFF_VEC[i+delta], US_SK_BUFF_NB_LCORE, sizeof(struct sk_buff), 65536,
			0, 
			NULL, NULL,
			us_sk_buff_mem_init, NULL,
			socket, MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);
	
	if(US_PER_LCORE(sk_head_pool) == NULL){
		US_ERR("sk_head mempool init failed for locre: %u\n",i);
		return US_ENOMEM;
	}else{
		US_LOG("sk_head mempool init successfully for locre: %u\n",i);
	}
			
	return US_RET_OK;
}

static s32 us_socket_mempool_init(s32 delta)
{
#if 0
	us_objslab	*socket_objslab_p = NULL;
	socket_objslab_p = us_memobj_slab_create(32*8192,sizeof(struct socket),32*8192) ;  //32*8192
	if(socket_objslab_p == NULL){
		US_ERR("us_socket memslab init failed for locre: %u err_no:%d\n",US_GET_LCORE(),US_ERRNO); 
	}else{
		US_LOG("us_socket memslab init successfully for locre: %u slab_water:%d slab_num:%d slab_max:%d\n"
			,US_GET_LCORE(),socket_objslab_p->slab_water,socket_objslab_p->slab_num,socket_objslab_p->slab_max);
	}

	US_PER_LCORE(socket_slab) = socket_objslab_p;
	return US_RET_OK;

#else
	u32 i = US_GET_LCORE();
	u32 socket = US_GET_SOCKET(i);
	
	US_PER_LCORE(socket_pool) = US_MEMPOOL_CREATE(
			US_SOCKET_VEC[i+delta], US_SOCKET_NB_LCORE, sizeof(struct socket), 65536,
			0, 
			NULL, NULL,
			us_socket_mem_init, NULL,
			socket, MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);
	
	if(US_PER_LCORE(socket_pool)  == NULL){
		US_ERR("socket mempool init failed for locre: %u\n",i);
		return US_ENOMEM;
	}else{
		US_LOG("socket mempool init successfully for locre: %u\n",i);
	}

	return US_RET_OK;
#endif	
}

static s32 us_sk_req_mempool_init(s32 delta)
{
#if 0
	us_objslab  *req_objslab_p = NULL;
	req_objslab_p = us_memobj_slab_create(32*8192,sizeof(struct inet_request_sock),32*8192)	;  //32*8192
	if(req_objslab_p == NULL){
		US_ERR("sK_req init failed for locre: %u err_no:%d\n",US_GET_LCORE(),US_ERRNO);	
	}else{
		US_LOG("sK_req init successfully for locre: %u slab_water:%d slab_num:%d slab_max:%d \n"
			,US_GET_LCORE(),req_objslab_p->slab_water,req_objslab_p->slab_num,req_objslab_p->slab_max);
	}

	US_PER_LCORE(sk_req_slab) = req_objslab_p;
	return US_RET_OK;
#else
	u32 i = US_GET_LCORE();
	u32 socket = US_GET_SOCKET(i);

	US_PER_LCORE(sk_req_pool)  = US_MEMPOOL_CREATE(
			US_REQ_VEC[i+delta], US_SK_REQ_NB_LCORE, sizeof(struct inet_request_sock), 96*1024,
			0, 
			NULL, NULL,
			NULL, NULL,
			socket, MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);
	
	if(US_PER_LCORE(sk_req_pool) == NULL){
		US_ERR("sK_req mempool init failed for locre: %u\n",i);
		return US_ENOMEM;
	}else{
		US_LOG("sK_req mempool init successfully for locre: %u\n",i);
	}
	return US_RET_OK;
#endif	
}

static s32 us_sk_tw_mempool_init(s32 delta)
{
#if 0	
	us_objslab  *tw_objslab_p = NULL;
	tw_objslab_p = us_memobj_slab_create(32*8192,sizeof(struct tcp_timewait_sock),32*8192);  //32*8192
	
	if(tw_objslab_p == NULL){
		US_ERR("tw_slab init failed for locre: %u err_no:%d\n",US_GET_LCORE(),US_ERRNO);	
		return US_ENOMEM;
	}else{
		US_LOG("tw_slab init successfully for locre: %u slab_water:%d slab_num:%d slab_max:%d\n"
			,US_GET_LCORE(),tw_objslab_p->slab_water,tw_objslab_p->slab_num,tw_objslab_p->slab_max);
	}

	US_PER_LCORE(sk_tw_slab) = tw_objslab_p;
	return US_RET_OK;
#else
	u32 i = US_GET_LCORE();
	u32 socket = US_GET_SOCKET(i);

	US_PER_LCORE(sk_tw_pool) = US_MEMPOOL_CREATE(
			US_TW_VEC[i+delta], US_SK_TW_NB_LCORE, sizeof(struct tcp_timewait_sock), 64*1024,
			0, 
			NULL, NULL,
			NULL, NULL,
			socket, MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);
	if(US_PER_LCORE(sk_tw_pool) == NULL){
		US_ERR("sk_tw mempool init failed for locre: %u\n",i);
		return US_ENOMEM;
	}else{
		US_LOG("sk_tw mempool init successfully for locre: %u\n",i);
	}
	return US_RET_OK;
#endif
}

static s32 us_ib_bucket_mempool_init(s32 delta)
{
	u32 i = US_GET_LCORE();
	u32 socket = US_GET_SOCKET(i);
	
	US_PER_LCORE(ibbucket_pool) = US_MEMPOOL_CREATE(
			US_IBB_VEC[i+delta], US_IBBUCKET_NB_LCORE, sizeof(struct inet_bind_bucket), 32767,
			0, 
			NULL, NULL,
			NULL, NULL,
			socket, MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);
	if(US_PER_LCORE(ibbucket_pool) == NULL){
		US_ERR("ibbucket mempool init failed for locre: %u\n",i);
		return US_ENOMEM;
	}else{
		US_LOG("ibbucket mempool init successfully for locre: %u\n",i);
	}

	return US_RET_OK;
}

static s32 us_mbuf_s_mempool_init(s32 delta)
{
	u32 i = US_GET_LCORE();
	u32 socket = US_GET_SOCKET(i);
	
	US_PER_LCORE(mbuf_pool_s) = rte_mempool_create(
			US_MBUFS_VEC[i+delta], US_MBUF_S_NB_LCORE, US_MBUF_LENGTH_MAX, 65536,
			sizeof(struct rte_pktmbuf_pool_private), 
			rte_pktmbuf_pool_init, NULL,
			us_pktmbuf_init, NULL,
			socket, MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);
	if(US_PER_LCORE(mbuf_pool_s) == NULL){
		US_ERR("send mbuf_mempool init failed for locre: %u\n",i);
		return US_ENOMEM;
	}else{
		US_LOG("send mbuf_mempool init successfully for locre: %u\n",i);
	}

	return US_RET_OK;
}

s32 us_tcpm_mempool_init(s32 delta)
{
	u32 i = US_GET_LCORE();
	u32 socket = US_GET_SOCKET(i);
	
	US_PER_LCORE(tcp_metric_pool) = rte_mempool_create(
			US_TMETRIC_VEC[i+delta], US_TCP_METRIC_LCORE, sizeof(struct tcp_metrics_block), 65532,
			0, 
			NULL, NULL,
			us_tcpm_block_init, NULL,
			socket, MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);
	if(US_PER_LCORE(tcp_metric_pool) == NULL){
		US_ERR("tcp_metric_pool init failed for locre: %u\n",i);
		return US_ENOMEM;
	}else{
		US_LOG("tcp_metric_pool init successfully for locre: %u\n",i);
	}
	
	return US_RET_OK;
}


static s32 us_buf_slab_init(s32 delata)
{
	u32 i = US_GET_LCORE();					//smallboy: Fixt it later ,for numa aware;
	us_objslabs	*bslab = us_zmalloc(NULL,sizeof(us_objslabs),SMP_CACHE_BYTES);
	if(bslab == NULL) {
		US_ERR("bslab init failed for locre: %u\n",i);
		goto err_out;
	}

/*
	bslab->objslab[0] = us_memobj_slab_create(8192,US_BUF_SIZE_BASE*1,256*1024);
	if(bslab->objslab[0] == NULL){
		US_ERR("bslab 0 init failed for locre: %u\n",i);
		goto err_out;
	}

	bslab->objslab[1] = us_memobj_slab_create(2048,US_BUF_SIZE_BASE*2,128*1024);
	if(bslab->objslab[1] == NULL){
		US_ERR("bslab 1 init failed for locre: %u\n",i);
		goto err_out;
	}

	bslab->objslab[2] = us_memobj_slab_create(1024,US_BUF_SIZE_BASE*3,64*1024);
	if(bslab->objslab[2] == NULL){
		US_ERR("bslab 1 init failed for locre: %u\n",i);
		goto err_out;
	}

	bslab->objslab[3] = us_memobj_slab_create(1024,US_BUF_SIZE_BASE*4,32*1024);
	if(bslab->objslab[3] == NULL){
		US_ERR("bslab 2 init failed for locre: %u\n",i);
		goto err_out;
	}

*/
	US_PER_LCORE(buffer_slab) = bslab;

	return US_RET_OK;
	
err_out:
	return US_ENOMEM;
}

s32 us_lhash_init(s32 delta)
{
	u32 i = US_GET_LCORE();
	u32 socket = US_GET_SOCKET(i);

	struct inet_hashinfo 		*h = NULL;
	const  us_memzone 			*mz = NULL;

	mz = US_MEMZONE_RESERVE(US_LHASH_VEC[i+delta], 
			US_INET_LHTABLE_SIZE *sizeof(struct inet_listen_hashbucket), socket, 0);
	if (mz == NULL){
		US_ERR(" lhash zone init failed for locre: %u\n",i);
		return  US_ENOMEM;
	}

	h = US_PER_LCORE(tcp_hashinfo);
	h->listening_hash =(struct inet_listen_hashbucket*)mz->addr_64;	

	for (i = 0; i< US_INET_LHTABLE_SIZE; i++) {
		US_INIT_HLIST_HEAD(&h->listening_hash[i].head);
	}

	return US_RET_OK;
}

s32 us_ehash_init(s32 delta)
{
	u32 i = US_GET_LCORE();
	u32 socket = US_GET_SOCKET(i);

	struct inet_hashinfo 		*h = NULL;
	const us_memzone 			*mz = NULL;

	mz = US_MEMZONE_RESERVE(US_EHASH_VEC[i+delta], 
			US_INET_EHTABLE_SIZE *sizeof(struct inet_ehash_bucket), socket, 0);
	if (mz == NULL){
		US_ERR(" ehash zone init failed for locre: %u\n",i);
		return  US_ENOMEM;
	}

	h = US_PER_LCORE(tcp_hashinfo);
	h->ehash =(struct inet_ehash_bucket*)mz->addr_64;

	for (i = 0; i< US_INET_EHTABLE_SIZE; i++) {
		US_INIT_HLIST_HEAD(&h->ehash[i].chain);
		US_INIT_HLIST_HEAD(&h->ehash[i].twchain);
	}

	h->ehash_mask = US_INET_EHTABLE_SIZE - 1;
	
	return US_RET_OK;
}

s32 us_bhash_init(s32 delta)
{
	u32 i = US_GET_LCORE();
	u32 socket = US_GET_SOCKET(i);

	struct inet_hashinfo 	*h = NULL;
	const  us_memzone 		*mz = NULL;

	mz = US_MEMZONE_RESERVE(US_BHASH_VEC[i+delta], 
			US_INET_BHASH_SIZE *sizeof(struct inet_bind_bucket), socket, 0);
	if (mz == NULL){
		US_ERR(" bhash zone init failed for locre: %u\n",i);
		return  US_ENOMEM;
	}

	h = US_PER_LCORE(tcp_hashinfo);
	h->bhash =(struct inet_bind_hashbucket *)mz->addr_64;
	for (i = 0; i< US_INET_BHASH_SIZE; i++) {
		US_INIT_HLIST_HEAD(&h->bhash[i].chain);
	}

	return US_RET_OK;
}

s32 us_thash_init(struct net *pnet,s32 delta)
{
	u32 i = US_GET_LCORE();
	u32 socket = US_GET_SOCKET(i);
	struct tcpm_hash_bucket	*th	= NULL;
	const  us_memzone 		*mz = NULL;

	mz = US_MEMZONE_RESERVE(US_MHASH_VEC[i+delta], 
			US_INET_MHTABLE_SIZE *sizeof(struct tcpm_hash_bucket), socket, 0);
	if (mz == NULL){
		US_ERR(" thash zone init failed for locre: %u\n",i);
		return  US_ENOMEM;
	}

	pnet->ipv4.tcp_metrics_hash = (struct tcpm_hash_bucket *)mz->addr_64;
	pnet->ipv4.tcp_metrics_hash_log = ilog2(US_INET_MHTABLE_SIZE);
	pnet->ipv4.tcp_metrics_num = 0;
	
	th = pnet->ipv4.tcp_metrics_hash;
	
	for (i = 0; i< US_INET_MHTABLE_SIZE; i++) {
		US_INIT_HLIST_HEAD(&th[i].chain);
	}

	return US_RET_OK;
}


s32 us_mempool_init(s32 delta)
{
	s32 ret = 0;

	ret = us_sock_mempool_init(delta);
	if(ret < 0){
		US_ERR("mempool for sock init failed!\n");
		return ret;
	}

	ret = us_socket_mempool_init(delta);
	if(ret < 0){
		US_ERR("mempool for socket init failed!\n");
		return ret;
	}

	ret = us_sk_head_mempool_init(delta);
	if(ret < 0){
		US_ERR("mempool for sk_head init failed!\n");
		return ret;
	}

	ret = us_sk_req_mempool_init(delta);
	if(ret < 0){
		US_ERR("mempool for sk_req init failed!\n");
		return ret;
	}

	ret = us_sk_tw_mempool_init(delta);
	if(ret < 0){
		US_ERR("mempool for sk_tw init failed!\n");
		return ret;
	}

	ret = us_ib_bucket_mempool_init(delta);
	if(ret < 0){
		US_ERR("mempool for ib_bucket init failed!\n");
		return ret;
	}
	
	ret = us_mbuf_s_mempool_init(delta);
	if(ret < 0){
		US_ERR("mempool for send mbuf_pool init failed!\n");
		return ret;
	}

	ret = us_tcpm_mempool_init(delta);
	if(ret < 0){
		US_ERR("mempool for tcp_metric_pool init failed!\n");
		return ret;
	}

	ret = us_buf_slab_init(delta);
	if(ret < 0){
		US_ERR("buf slab init failed!\n");
		return ret;
	}
	
	return ret;
}

