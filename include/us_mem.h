/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_mem.h
* @brief			function for all the mem init;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/


#ifndef _US_MEM_H
#define _US_MEM_H

#include "types.h"
#include "net.h"
#include "us_memobj_slab.h"

US_DECLARE_PER_LCORE(us_mempool*,sock_pool);
US_DECLARE_PER_LCORE(us_mempool*,socket_pool);

US_DECLARE_PER_LCORE(us_mempool*,sk_head_pool);			//Not used;

US_DECLARE_PER_LCORE(us_mempool*,tcp_metric_pool);
US_DECLARE_PER_LCORE(us_mempool*,sk_req_pool);
US_DECLARE_PER_LCORE(us_mempool*,sk_tw_pool);
US_DECLARE_PER_LCORE(us_mempool*,mbuf_pool_s);
US_DECLARE_PER_LCORE(us_mempool*,ibbucket_pool);


//smallboy: On ustack ,for dmesg info;
US_DECLARE_PER_LCORE(us_ring*,ring);
US_DECLARE_PER_LCORE(us_mempool*,mbuf_pool_r);

US_DECLARE_PER_LCORE(us_objslab*,sk_req_slab);
US_DECLARE_PER_LCORE(us_objslab*,sk_tw_slab);
US_DECLARE_PER_LCORE(us_objslab*,socket_slab);

extern u32	glb_sock_num ;
extern u32	glb_socket_num ;
extern u32	glb_sk_buff_num ;
extern u32	glb_mbuf_num ;
extern u32  glb_r_mbuf_id_max ;


extern char *US_BIP_VEC[24];  //US_LCORE_MAX

extern char *US_SOCK_VEC[APP_MAX_IO_LCORES];
extern char *US_SOCKET_VEC[APP_MAX_IO_LCORES];

extern char *US_SKBUFF_VEC[APP_MAX_IO_LCORES];

extern char *US_REQ_VEC[APP_MAX_IO_LCORES];

extern char *US_TW_VEC[APP_MAX_IO_LCORES];
extern char *US_IBB_VEC[APP_MAX_IO_LCORES];
extern char *US_MBUFS_VEC[APP_MAX_IO_LCORES];
extern char *US_MBUFR_VEC[APP_MAX_IO_LCORES];
extern char *US_LHASH_VEC[APP_MAX_IO_LCORES];
extern char *US_BHASH_VEC[APP_MAX_IO_LCORES];
extern char *US_EHASH_VEC[APP_MAX_IO_LCORES];
extern char *US_RING_VEC[APP_MAX_IO_LCORES];
extern char *US_MHASH_VEC[APP_MAX_IO_LCORES];


struct net ;

static inline s32 us_slab_get(us_mempool *pool, void ** obj_p)
{
	//return rte_mempool_get_bulk(pool,obj_p,num);
	return rte_mempool_get(pool,obj_p);
}

static inline void us_slab_free(us_mempool *pool,void *obj_p)
{
	rte_mempool_mp_put(pool,obj_p);
}

static inline struct rte_mbuf *us_mbuf_alloc(struct net*pnet)
{
	s32 ret;
	struct rte_mbuf	*r_mp;
	us_mempool	*us_p = pnet->mbuf_s_pool;
	ret = us_slab_get(us_p,(void**)&r_mp);
	//ret = us_slab_get(US_PER_LCORE(mbuf_pool_s),(void**)&r_mp);
	if(ret < 0){
		return NULL;
	}
	return r_mp;
}

static inline void us_mbuf_free(struct rte_mbuf *r_mp)
{
	if(r_mp){
		us_slab_free(US_PER_LCORE(mbuf_pool_s),r_mp);
	}
}


extern void us_pktmbuf_init(struct rte_mempool *mp,
		 __attribute__((unused)) void *opaque_arg,
		 void *_m, __attribute__((unused)) unsigned i) ;

extern s32 us_mempool_init(s32 delta);
extern s32 us_bhash_init(s32 delta);
extern s32 us_ehash_init(s32 delta);
extern s32 us_lhash_init(s32 delta);
extern s32 us_thash_init(struct net *pnet,s32 delta);
extern s32 us_tcpm_mempool_init(s32 delta);

#endif

