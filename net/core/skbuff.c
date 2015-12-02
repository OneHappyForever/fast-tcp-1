/*
 *	Routines having to do with the 'struct sk_buff' memory handlers.
 *
 *	Authors:	Alan Cox <alan@lxorguk.ukuu.org.uk>
 *			Florian La Roche <rzsfl@rz.uni-sb.de>
 *
 *	Fixes:
 *		Alan Cox	:	Fixed the worst of the load
 *					balancer bugs.
 *		Dave Platt	:	Interrupt stacking fix.
 *	Richard Kooijman	:	Timestamp fixes.
 *		Alan Cox	:	Changed buffer format.
 *		Alan Cox	:	destructor hook for AF_UNIX etc.
 *		Linus Torvalds	:	Better skb_clone.
 *		Alan Cox	:	Added skb_copy.
 *		Alan Cox	:	Added all the changed routines Linus
 *					only put in the headers
 *		Ray VanTassle	:	Fixed --skb->lock in free
 *		Alan Cox	:	skb_copy copy arp field
 *		Andi Kleen	:	slabified it.
 *		Robert Olsson	:	Removed skb_head_pool
 *
 *	NOTE:
 *		The __skb_ routines should be called with interrupts
 *	disabled, or you better be *real* sure that the operation is atomic
 *	with respect to whatever list is being frobbed (e.g. via lock_sock()
 *	or via disabling bottom half handlers, etc).
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

/*
 *	The functions in this file will not compile correctly with gcc 2.4.x
 */

/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			skbuff.c
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/  



#include "skbuff.h"
#include "sock.h"
#include "socket.h"
#include "us_mem.h"
#include "ip.h"
#include "tcp.h"


/**
 *	__kfree_skb - private function
 *	@skb: buffer
 *
 *	Free an sk_buff. Release anything attached to the buffer.
 *	Clean the state. This is an internal helper function. Users should
 *	always call kfree_skb
 */

void __kfree_skb(struct sk_buff *skb,bool more)
{	
	if (skb->destructor) {
		skb->destructor(skb);
		skb->destructor = NULL;			//smallboy:Added ;
	}

	if(skb->hdr_len) {
		if(skb->nohdr && more){	
			rte_pktmbuf_free((struct rte_mbuf *)(skb->head));
			
			//US_DEBUG("skb->skb_id:%u mbuf_ref:%u\n",skb->skb_id,rte_mbuf_ref_read(skb->head));
		}

		if(!skb->nohdr){
			us_buf_slab_free(skb->head);
		}
		
	}else{
		us_abort(US_GET_LCORE());
	/*	
		US_ERR("never be there again!\n");
		if(skb->nohdr && more){				//smallboy: A little confusion here;
			rte_pktmbuf_free((struct rte_mbuf *)(skb->head));	//more == 1 ;Yes, we free the mbuf here, right now or dec just 	
		}									//and freed by the driver laterly;
											//For the skb not cloned, more == 0,and it's the duty of the driver
											// who will freed the mbuf at last;											
		if(!skb->nohdr){					//For the "GSO" like method,free the data by itself here;
			//free(skb->head);				//skb->head == null is oK;
			us_buf_slab_free(skb->head);
		}

		us_skb_free(skb);					//any way ,return the skb to the mempool;
	*/	
	}
	//skb_release_all(skb);
	//kfree_skbmem(skb);	
}

/**
 *	kfree_skb - free an sk_buff
 *	@skb: buffer to free
 *
 *	Drop a reference to the buffer and free it if the usage count has
 *	hit zero.
 */
void kfree_skb(struct sk_buff *skb,bool more)
{
	if(skb->users <= 1)	{						//smallboy: If we free the skb,we free the mbuf	//Attention here: If we kfree_skb more than once,and then we
		if(skb->users <= 0){
			us_abort(US_GET_LCORE());
		}
		__kfree_skb(skb,more);					//may make free the mbuf uncorrectly;
	}else{
		skb->users--;
	}

#if 0	
	if (unlikely(!skb))
		return;
	if (likely(atomic_read(&skb->users) == 1))
		smp_rmb();
	else if (likely(!atomic_dec_and_test(&skb->users)))
		return;
	trace_kfree_skb(skb, __builtin_return_address(0));
	__kfree_skb(skb);
#endif	
}

static inline void skb_copy_from_linear_data_offset(const struct sk_buff *skb,
						    const int offset, void *to, const unsigned int len)
{
	memcpy(to, skb->data + offset, len);
}

static inline void skb_split_inside_header(struct sk_buff *skb,struct sk_buff* skb1,
					   const u32 len, const int pos)
{
	skb_copy_from_linear_data_offset(skb, len, skb_put(skb1, pos - len), pos - len);
	// And move data appendix as is. 
	//for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
	//	skb_shinfo(skb1)->frags[i] = skb_shinfo(skb)->frags[i];

	//skb_shinfo(skb1)->nr_frags = skb_shinfo(skb)->nr_frags;
	//skb_shinfo(skb)->nr_frags  = 0;
	skb1->data_len		= skb->data_len;	//zero;
	//skb1->len		   += (pos - len);     // len = n*mss;
	
	//skb->data_len		= 0;
	skb->len		    = len;
	skb_set_tail_pointer(skb, len);

#if 0	
	int i;

	skb_copy_from_linear_data_offset(skb, len, skb_put(skb1, pos - len),
					 pos - len);
	/* And move data appendix as is. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
		skb_shinfo(skb1)->frags[i] = skb_shinfo(skb)->frags[i];

	skb_shinfo(skb1)->nr_frags = skb_shinfo(skb)->nr_frags;
	skb_shinfo(skb)->nr_frags  = 0;
	skb1->data_len		   = skb->data_len;
	skb1->len		   += skb1->data_len;
	skb->data_len		   = 0;
	skb->len		   = len;
	skb_set_tail_pointer(skb, len);
#endif	
}

static inline void skb_split_no_header(struct sk_buff *skb,
				       struct sk_buff* skb1,const u32 len, int pos)
{
#if 0	
	int i, k = 0;
	const int nfrags = skb_shinfo(skb)->nr_frags;

	skb_shinfo(skb)->nr_frags = 0;
	skb1->len		  = skb1->data_len = skb->len - len;
	skb->len		  = len;
	skb->data_len		  = len - pos;

	for (i = 0; i < nfrags; i++) {
		int size = skb_frag_size(&skb_shinfo(skb)->frags[i]);

		if (pos + size > len) {
			skb_shinfo(skb1)->frags[k] = skb_shinfo(skb)->frags[i];

			if (pos < len) {
				/* Split frag.
				 * We have two variants in this case:
				 * 1. Move all the frag to the second
				 *    part, if it is possible. F.e.
				 *    this approach is mandatory for TUX,
				 *    where splitting is expensive.
				 * 2. Split is accurately. We make this.
				 */
				skb_frag_ref(skb, i);
				skb_shinfo(skb1)->frags[0].page_offset += len - pos;
				skb_frag_size_sub(&skb_shinfo(skb1)->frags[0], len - pos);
				skb_frag_size_set(&skb_shinfo(skb)->frags[i], len - pos);
				skb_shinfo(skb)->nr_frags++;
			}
			k++;
		} else
			skb_shinfo(skb)->nr_frags++;
		pos += size;
	}
	skb_shinfo(skb1)->nr_frags = k;
#endif
	us_abort(US_GET_LCORE());
}


/**
 * skb_split - Split fragmented skb to two parts at length len.
 * @skb: the buffer to split
 * @skb1: the buffer to receive the second part
 * @len: new length for skb
 */
void skb_split(struct sk_buff *skb, struct sk_buff *skb1, const u32 len)
{
	int pos = skb_headlen(skb);

	//printf("pos = %u; len = %u \n",pos,len);
	if (len <= pos)	// Split line is inside header. 
		skb_split_inside_header(skb, skb1, len, pos);
	else			// Second chunk has no header, nothing to copy. 
		skb_split_no_header(skb, skb1, len, pos);
}

int skb_try_append(struct sk_buff *skb, int mss_now, char*send_data, int data_len)
{
	int		pad_left = 0;
	u16		pad_len  = 0;
	char 	*tail 	 = NULL;
	struct rte_mbuf 	*r_mp = NULL;
	//struct tcp_skb_cb 	*tcb  = NULL;
	
	if(skb->nohdr){
		r_mp = (struct rte_mbuf *)skb->head ;
		pad_left = mss_now - rte_pktmbuf_data_len(r_mp) + MAX_TCP_HEADER;
		//US_DEBUG("pad_left:%d  mss_now:%d pkt_data_len:%d skb->len:%u skb->tail:%p\n"
		//		,pad_left,mss_now,rte_pktmbuf_data_len(r_mp),skb->len,skb->tail);
		pad_left = pad_left < 0 ? 0 : pad_left;
		if(pad_left == 0)
			return 0;
		pad_left = pad_left < data_len ? pad_left: data_len; 
		pad_len = pad_left;
		
		tail = rte_pktmbuf_append(r_mp ,pad_len);
		memcpy(tail, send_data, pad_len);
		skb->end = skb->end +  pad_len;
		skb_put(skb,pad_len);
	}else{
		pad_left = skb_availroom(skb) ;
		pad_left = pad_left < data_len ? pad_left - 1 : data_len;
		memcpy(skb->tail,send_data ,pad_left);
		skb_put(skb,pad_left);
	}
 
	TCP_SKB_CB(skb)->end_seq += pad_left;

	return pad_left;
}

#if 1
struct sk_buff *alloc_skb(struct sock*sk,unsigned int size,int clone)
{
	char  			*data_p = NULL; 
	struct sk_buff 	*sk_head= NULL;
	struct rte_mbuf *r_mp	= NULL;

	if(size > US_SK_BUFF_LINESIZE_MAX){
		data_p = us_buf_slab_alloc(size + sizeof(struct sk_buff));
		if(data_p == NULL){
			return NULL;
		}else{
			sk_head = us_buf_slab_end(data_p, size + sizeof(struct sk_buff));
			sk_head = (struct sk_buff*)((char *)sk_head - sizeof(struct sk_buff));
			memset(sk_head,0,sizeof(struct sk_buff));
			sk_head->nohdr 		= 0;
			sk_head->truesize 	= (size);						//SKB_TRUESIZE(size); Attention here;
			sk_head->users 		= 1;
			sk_head->cloned 	= clone;
			sk_head->users	   += sk_head->cloned;
			sk_head->head	    = data_p;
			sk_head->data 		= sk_head->head;					//smallboy:Is there any problem;
			sk_head->tail 		= sk_head->data;
			sk_head->hdr_len	= 1;
			sk_head->end   		= (char *)sk_head - US_SKB_OFFSET;
			sk_head->gso_segs 	= 0;
			sk_head->pnet 		= sock_net(sk);
			//sk_head->skb_id		= (u32)sk_head->head;
			sk_head->skb_id		= 0;
			return sk_head;	
		}
	}else{
		r_mp = us_mbuf_alloc(sock_net(sk));
		if(r_mp == NULL){
			return NULL;
		}else{
			rte_pktmbuf_reset(r_mp);
			sk_head = (struct sk_buff*)((char *)r_mp->buf_addr 
								+ (US_MBUF_LENGTH_MAX - US_SKB_OFFSET) - sizeof(struct sk_buff));
			memset(sk_head,0,sizeof(struct sk_buff));
			sk_head->nohdr 	= 1;
			sk_head->head 	= (char*)r_mp;
			sk_head->data 	= rte_pktmbuf_mtod(r_mp,void *);			//smallboy:mbuf is not nonliner;
			sk_head->tail 	= sk_head->data;	
			rte_pktmbuf_append(r_mp , size);	//LF_W;
			sk_head->end 	= rte_pktmbuf_append(r_mp , 0);
			sk_head->truesize 	= (size); 	//SKB_TRUESIZE(size)
			sk_head->users 		= 1; 		// 1 or 2;
			sk_head->cloned 	= clone;	// 0 or 1;			
			sk_head->users 	   += sk_head->cloned;
			sk_head->gso_segs 	= 1;	
			sk_head->hdr_len	= 1;
			sk_head->pnet 		= sock_net(sk);
			sk_head->skb_id		= 0;
			sk_head->skb_id		= rte_mbuf_id_read(r_mp);
			rte_mbuf_ref_set(r_mp, sk_head->users);
			return sk_head;
		}
	}

}
#else
struct sk_buff *alloc_skb(struct sock*sk,unsigned int size,int clone)
{
	char  			*data_p = NULL; 
	struct sk_buff 	*sk_head= NULL;
	struct rte_mbuf *r_mp	= NULL;
	
	if(size > US_SK_BUFF_LINESIZE_MAX){
		//data_p = (char *)malloc(size + (size>>1));			//smallboy: Fix the malloc here;
		//data_p = us_buf_slab_alloc(size);
		//sk_head = us_skb_alloc();
		data_p = us_buf_slab_alloc(size + sizeof(struct sk_buff));
		sk_head = us_buf_slab_end(data_p, size + sizeof(struct sk_buff));
		sk_head = (char *)sk_head - (sizeof(struct sk_buff));
		if((sk_head) && (data_p)){
			sk_head->nohdr = 0;
			sk_head->truesize = (size);//SKB_TRUESIZE(size);
			sk_head->users = 1;
			sk_head->cloned = clone;
			sk_head->users	+= sk_head->cloned;
			sk_head->head = data_p;
			sk_head->data = sk_head->head;					//smallboy:Is there any problem;
			sk_head->tail = sk_head->data;

			sk_head->hdr_len	= 1;
			//sk_head->end =  sk_head->tail + (size);  		// SKB_TRUESIZE(size)
			//sk_head->end =  sk_head->tail + us_buf_slab_truesize(size);  // SKB_TRUESIZE(size)
			sk_head->end   =  (char *)sk_head - US_SKB_OFFSET;
			US_ERR("tail:%p end:%p truesize:%u \n",sk_head->tail,sk_head->end,us_buf_slab_truesize(size));
			
			sk_head->gso_segs = 0;
			sk_head->pnet = sock_net(sk);
			return sk_head;
		}else{
			//free(data_p);
			us_buf_slab_free(data_p);
			//us_skb_free(sk_head);
			return NULL;
		}
	}else{
		r_mp = us_mbuf_alloc();
		sk_head = us_skb_alloc();

		if((sk_head != NULL) && (r_mp != NULL)){

			rte_pktmbuf_reset(r_mp);
			sk_head->nohdr = 1;
			sk_head->head = (char*)r_mp;

			sk_head->data = rte_pktmbuf_mtod(r_mp,void *);			//smallboy:mbuf is not nonliner;

			//US_DEBUG("TH:%u,mbuf_tailrom:%u\n",US_GET_LCORE(),rte_pktmbuf_tailroom(r_mp));
			
			sk_head->tail = sk_head->data;	
			rte_pktmbuf_append(r_mp , size);	//LF_W;
			sk_head->end =	rte_pktmbuf_append(r_mp , 0);

			//US_DEBUG("TH:%u,sk_head->tail:%p,%p,sk_head->end:%p size:%u\n",US_GET_LCORE()
			//			,sk_head->tail,sk_head->data,sk_head->end,size);
			
			sk_head->truesize = (size); //SKB_TRUESIZE(size)
			sk_head->users = 1;			// 1 or 2;
			sk_head->cloned = clone;	// 0 or 1;			

			sk_head->users += sk_head->cloned;
			sk_head->gso_segs = 1;	
			sk_head->pnet = sock_net(sk);
			
			rte_mbuf_ref_set(r_mp, sk_head->users);

			return sk_head;
			
		}else{
	
			us_mbuf_free(r_mp);
			us_skb_free(sk_head);
			return NULL;
		}
	}
}
#endif
int memcpy_toiovec(struct iovec *iov,  char *kdata, int len)  //unsigned
{
	while (len > 0) {
		if (iov->iov_len) {
			int copy = min_t(unsigned int, iov->iov_len, len);
			memcpy(iov->iov_base, kdata, copy);
			kdata += copy;
			len -= copy;
			iov->iov_len -= copy;
			iov->iov_base += copy;
		}
		iov++;
	}

	return 0;
}

/**
 *	skb_copy_datagram_iovec - Copy a datagram to an iovec.
 *	@skb: buffer to copy
 *	@offset: offset in the buffer to start copying from
 *	@to: io vector to copy to
 *	@len: amount of data to copy from buffer to iovec
 *
 *	Note: the iovec is modified during the copy.
 */
int skb_copy_datagram_iovec(const struct sk_buff *skb, int offset,
			    				struct iovec *to, int len)
{
	int start = skb_headlen(skb);
	int copy = start - offset;

	// Copy header.
	if (copy > 0) {
		if (copy > len)
			copy = len;
		if (memcpy_toiovec(to, skb->data + offset, copy))
			goto fault;
		if ((len -= copy) == 0)
			return 0;
		offset += copy;
	}

	if (!len || !copy)
		return 0;

fault:
	return -EFAULT;
}

void skb_moveto_datagram_iovec(const struct sk_buff *skb, int offset ,struct iovec *to)
{
	char buf[1500];
	
	to->iov_base = skb->data + offset; 
	to->iov_len = skb->len -  offset;
	to->meta_data = (void*)skb;

	//memcpy(memcpy_buf,skb->data,skb->len);
	memcpy(buf,skb->data,skb->len);
}

void skb_copy_datagram(const struct sk_buff *skb, int offset,char *to, int len)
{
	int start = skb_headlen(skb);
	int copy = start - offset;

	// Copy header.
	if (copy > 0 && len >0) {
		if (copy > len)
			copy = len;
		memcpy(to,skb->data + offset, copy);
		if ((len -= copy) == 0)
			return ;
	}
}


void skb_retry_get(struct sk_buff *skb)
{
	u32  ref_cnt;
	skb->users++;
	if(skb->nohdr){
		ref_cnt = rte_mbuf_ref_read((struct rte_mbuf *)skb->head);
		rte_mbuf_ref_set((struct rte_mbuf *)skb->head, ref_cnt + 1);
	}
}

void skb_retry_put(struct sk_buff *skb)
{
	u32 ref_cnt;
	skb->users--;
	if (skb->nohdr){
		ref_cnt = rte_mbuf_ref_read((struct rte_mbuf *)skb->head);
		rte_mbuf_ref_set((struct rte_mbuf *)skb->head, ref_cnt - 1);
	}
}

void skb_retry_set(struct sk_buff *skb , s32 num)
{
	if(skb){
		skb->nf_trace = num;
	}
}

void skb_reset_data_header(struct sk_buff *skb)
{
	//if(skb->nohdr){	// We adjust the 	
		//skb->data = rte_pktmbuf_mtod((struct rte_mbuf *)skb->head, char*);
		if (skb->data_header){	
			skb->data = skb->data_header;
			skb->len = skb->tail - skb->data;
		}
	//}
}

/**
 *	skb_put - add data to a buffer
 *	@skb: buffer to use
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer. If this would
 *	exceed the total buffer size the kernel will panic. A pointer to the
 *	first byte of the extra data is returned.
 */
 char *skb_put(struct sk_buff *skb, unsigned int len)  //unsigned
{
	char *tmp = skb_tail_pointer(skb);  //unsigned
	//SKB_LINEAR_ASSERT(skb);
	skb->tail += len;
	skb->len  += len;
	if (unlikely(skb->tail > skb->end)){
		US_DEBUG("TH:%u,skb->tail:%p,skb->end:%p\n",US_GET_LCORE(),skb->tail,skb->end);
		us_abort(US_GET_LCORE());
	}
	//	skb_over_panic(skb, len, __builtin_return_address(0));
	return tmp;
}




