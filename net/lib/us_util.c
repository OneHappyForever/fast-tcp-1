/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_util.c
* @brief			misc function for us_entry.c;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/


#include "types.h"
#include "us_rte.h"
#include "net.h"
#include "skbuff.h"
#include "socket.h"
#include "ip.h"
#include "tcp.h"
#include "icmp.h"
#include "bitops.h"
#include "us_error.h"
#include "glb_var.h"
#include "us_util.h"
#include "us_mem.h"

#include <math.h>
#include <stdlib.h>

US_DEFINE_PER_LCORE(int,us_errno);
US_DECLARE_PER_LCORE(struct inet_hashinfo*, tcp_hashinfo);
US_DECLARE_PER_LCORE(us_objslab *,us_msghdr_slab);

US_DECLARE_PER_LCORE(u32,mmbuf_flush) ;
US_DECLARE_PER_LCORE(u32,mmbuf_num) ;


extern us_nic_port	 us_nic_ports[APP_MAX_NIC_PORTS] ;

static u64 	glb_mon_jiff_probe = 0;
static u64	glb_mon_jiff_debug_mem = 0; 
static u64	glb_mon_jiff_debug_cpu = 0;
static u32	glb_memobj[US_LCORE_MAX][US_MEMPOOL_TYPE*2];


US_DEFINE_PER_LCORE(u32, mmbuf_flush);
US_DEFINE_PER_LCORE(u32, mmbuf_num);
US_DEFINE_PER_LCORE(us_rte_mbuf_a, mmbuf);



//@brief , try to simulate a ilog2 with the libc method;
//@note  , Do not use it frequently;
u32 ilog2(u32	x)
{
	double	ax = log(x);
	double 	a2 = log(2);

	return (u32)ax/a2;
}

s32 us_all_lcore_gone(void)
{
	return (glb_us_init_token >= GLB_US_LCORE_RB);
}

//@bried , used only when start;
s32 us_check_multithread(void)
{
	//s32 i;
	//s32 bits;

	us_spin_ms(2000);
	return 0;
/*
	if(!us_all_lcore_gone()){
		US_DEBUG("glb_us_init_token:%d\n",glb_us_init_token);
		return US_EINVAL;
	}

	for(i=0,bits=0;i< 64;i++){
		bits += test_bit(i,(unsigned long*)&glb_us_init_through);
	}

	return !!(bits < (glb_us_init_token - GLB_US_LCORE_LB -1));	
*/
}

//@brief , for debug;
void us_dump_th()
{
	u32 i;

	US_ERR("##############dump_us_thread:beg#############\n");
	US_ERR("%24s,%24s,%24s,%24s\n","US_TH_ID","US_TH_TYPE","US_STATE","US_PROBE");
	for(i = 0; i< US_LCORE_MAX;i++){
		US_ERR("%24u,%24u,%24u,%24u\n"
			,i
			,glb_thread[i].th_type
			,glb_thread[i].state
			,glb_thread[i].probe);
	}	
	US_ERR("##############dump_us_thread:end#############\n");
}

//@brief , for debug;
void us_abort(u32 lcore)
{
	us_dump_th();
	abort();
}

bool u32_is_1bit(u32 lcore,u32 *bit)
{
	u32 i = 0;
	u32 j = 0;
	while(lcore){
		if(lcore & 0x1){
			i++;
		}
		if(j == 0)
			j++;
		lcore = lcore >> 1;
	}

	*bit = j; 
	
	return i == 1;
}

u32 u32_high_bit(u32 coremask)
{
	u32 i = 31;
	while(coremask){
		if(coremask & 0x80000000){
			break;
		}else{
			i--;
		}
	}
	return i;
}


s32 us_fdir_init(u8 portid)
{
	struct rte_fdir_masks fdirmask = {
		.only_ip_flow = 0,
		.vlan_id = 0,
		.vlan_prio = 0,
		.flexbytes = 0,
		.dst_ipv4_mask = 0xffffffff,
		.src_ipv4_mask = 0,//xffffffff,
		.src_ipv6_mask = 0,//xffff,
		.src_port_mask = 0,//xffff,
		//.dst_port_mask = 0xffff & (~(u16_t)((1<<BGW7_WORKER_PORT_BITS)-1)),
		.dst_port_mask = 0,
	};

	return rte_eth_dev_fdir_set_masks(portid, &fdirmask);
}

s32 us_fdir_add(u8 portid , u8 queue_id ,u32 ip_dst_addr)
{
	s32 ret = 0;
	struct rte_fdir_filter fdirfilter;
	memset(&fdirfilter,0,sizeof(fdirfilter));
	
	fdirfilter.ip_dst.ipv4_addr = ip_dst_addr;
	fdirfilter.l4type = RTE_FDIR_L4TYPE_TCP;
	fdirfilter.iptype = RTE_FDIR_IPTYPE_IPV4;

	if((ret = rte_eth_dev_fdir_add_perfect_filter(portid, &fdirfilter, 0, queue_id, 0)) != 0) {
		US_ERR("set fdir filter for port %d queue %d failed on ret:%d\n", portid, queue_id,ret);
		return ret;
	} else {
		US_LOG("set fdir filter for port %d queue %d succeeded\n", portid, queue_id);
		return US_RET_OK;
	}
}

//@biref  , when malloc a msghdr, format a sk_buff struct at head;
//@input  , head--> the pointer of iovector ;
//@input  , extend_len --> length of the whole buf alloced; 
//@output , return the pointer of this sk_buff;
static struct sk_buff *iobuf_to_skb(char *head, int extend_len)
{
	struct sk_buff *skb = (struct sk_buff*) head;

	memset(skb,0,sizeof(struct sk_buff));
	skb->head		= head;
	
	skb->data		= (char *)(skb + 1);
	skb->tail		= skb->data;
	skb->end		= head + extend_len;

	skb->nohdr		= 0;
	skb->hdr_len	= 1;
	skb->users		= 1;
	skb->used		= 0;
	skb->cloned		= 1;
	skb->users	   += skb->cloned;
	skb->skb_id		= 0;
	//skb->skb_id 	= (u32)head;
	
	return skb;
}

//@brief , when connect out , get a local ip here;
//@note  , ustack elimit the tranditional ip route table, adjust and filling it here so; 
//@note  , Job unfinishted;
u32 get_local_out_ip(u32 lcore)
{
	s32 ret;
	u32 bip;
	if(lcore >= US_LCORE_MAX)
		return 0;

	ret = inet_pton(AF_INET, US_BIP_VEC[lcore], &bip);
	if(ret < 0){
		US_ERR("bip error: wrong ip:%s format for lcore:%u\n",US_BIP_VEC[lcore],lcore);
		return 0;
	}

	//US_LOG("bip connect: ip:%s,%u format for lcore:%u\n",US_BIP_VEC[lcore],bip,lcore);	
	return bip;	
}


//@brief , format a ip head for each mbuf reserved;
//@input , pnet--> the net which hold the mbufs reserved;
//@note  , ipv4 head only here;
void skb_build_ip_head(struct sk_buff *skb,struct net *pnet)
{
	struct ether_hdr 	*ethh;	
	struct iphdr 		*iph;	

	int reserve_size 	= sizeof(struct ether_hdr) ;  //There never be ip option here;
	us_nic_port   *port = pnet->port;	
	struct rte_mbuf *mbuf = (struct rte_mbuf*)skb->head;

	ethh	= (struct ether_hdr*)skb->data;
	skb->mac_header = (char*)ethh;	

	skb_reserve(skb, reserve_size);
	skb->len += reserve_size;
	
	if(port){
		//fill the dst mac with 0xff*6
		rte_memcpy(ethh->d_addr.addr_bytes, port->gw_mac, ETHER_ADDR_LEN);
		//fill the src mac with this port's mac

		rte_memcpy(ethh->s_addr.addr_bytes, port->if_mac, ETHER_ADDR_LEN);
		//fill the proto type with 0x0800
		ethh->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

		mbuf->pkt.vlan_macip.f.l2_len = sizeof(struct ether_hdr);
		mbuf->pkt.vlan_macip.f.l3_len = sizeof(struct iphdr);

		set_iptcp_csum_offload(mbuf);
	}

	skb->network_header = skb->data ;
	
	reserve_size = sizeof(struct iphdr);
	skb_reserve(skb, reserve_size);
	skb->len += reserve_size;
	
	iph = ip_hdr(skb);
	
	iph->version  = 4;
	iph->ihl      = 5;		
	iph->tos      = 0;
	iph->tot_len  = htons(sizeof(struct iphdr));
	iph->frag_off = htons(IP_DF);		
	iph->id		  = 0;
	iph->ttl      = 128;
	iph->protocol = 0;
	iph->daddr    = 0;
	iph->saddr    = 0;	
	iph->check	  = 0;

	//skb->transport_header = (unsigned char*)(iph++);
	skb->transport_header = (char*)(skb->data);
	
}

//@biref , recover the mbuf struct after sendout;
//@input , trim_len--> the mbuf len tried to compenstated ;
void skb_mbuf_format_recover(struct rte_mbuf *mbuf,u16 trim_len)
{
	u32 ref_cnt = rte_mbuf_ref_read(mbuf);
	rte_mbuf_ref_set(mbuf, ref_cnt + 1);
	rte_pktmbuf_append(mbuf, trim_len);
}

//@brief , build the mac_head for each mbuf who's head len is confirmed and send it out then;
//@input , append --> the length of tcp option ;
//@output , (< 0) --> send out failed; ( == 0) send out successfully; 
//@note , be called only when the pkt build is   SYN/ACK , ACK , RST/ACK ;
inline int mbuf_format_and_send(struct sk_buff *skb, u16 append)
{
	s32 ret = 0;
	u32 n = 0;
	struct net *pnet = skb->pnet;
	us_nic_port	*port = pnet->port;
	//struct tcphdr 	*th = (struct tcphdr*)skb->transport_header;
	
	struct rte_mbuf *mbuf 	= (struct rte_mbuf *)skb->head;
	struct ether_hdr *ethh	= (struct ether_hdr *)skb_mac_header(skb);

	rte_memcpy(ethh->d_addr.addr_bytes, port->gw_mac, ETHER_ADDR_LEN);
	rte_memcpy(ethh->s_addr.addr_bytes, port->if_mac, ETHER_ADDR_LEN);

	rte_pktmbuf_trim(mbuf, MAX_TCP_HEADER - skb->len - append);
	skb->mac_len = MAX_TCP_HEADER - skb->len - append;  			//For recover here;

	//fprintf(stderr,"skb_id:%u skb_len:%u eth:%p mbuf:%p after_del:%u len:%u ref:%u mbuf_id:%u src:%u dst:%u\n"
	//			,skb->skb_id,skb->len,ethh,mbuf,(MAX_TCP_HEADER - skb->len - append)
	//			,rte_pktmbuf_data_len(mbuf),rte_mbuf_ref_read(mbuf),rte_mbuf_id_read(mbuf)
	//			,ntohs(th->source),ntohs(th->dest));
	//set_iptcp_csum_offload(mbuf);

	recv_pkt_dump(&mbuf, 1);
	
	n = rte_eth_tx_burst(port->port_id, pnet->send_queue_id , &mbuf, 1);	
	if(n < 1){
		US_ERR("TH:%u ,mbuf_format_and_send :tx_burst failed on skb_id:%u sk_id:%u \n"
				,US_GET_LCORE(),skb->skb_id,skb->sk->sk_id);
		ret = US_ENETDOWN;
	}else{
		ret = US_RET_OK;
		NET_ADD_STATS_BH(skb->pnet,IPSTATS_MIB_OUTPKTS , 1);  //skb->gso_segs == 1;
	}

	skb->used++;  //Never be freed;
	return ret;
}

//@brief , build the mac_head for each mbuf;
//@input , skb-> the pointer to the skb which contains the mbuf;
//@input , port-> the port struct which carries the mac/vlan information;
inline void mbuf_rebuild(struct sk_buff *skb ,us_nic_port * port)
{
	struct ether_hdr *ethh;	
	struct iphdr 	*iph  = (struct iphdr *)skb->data;			
	struct rte_mbuf *mbuf = (struct rte_mbuf *)skb->head;
	
	ethh = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);

	skb->mac_len = (u8 *)iph - (u8*)ethh - sizeof(struct ether_hdr);

	ethh = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, skb->mac_len); 
	/*
	US_DEBUG("TH:%u,ethh: mbuf_id:%u skb->data:%p ethh:%p skb_id:%u mbuf_ref:%u skb_used:%u skb_user:%u skb_hdr:%u "
			"skb->len:%d,skb->mac_len:%d,skb->delta_csum_len:%d,mbuf->plen:%d,mbuf->dlen:%d\n"
			,US_GET_LCORE(),0,skb->data,mbuf->pkt.data,skb->skb_id, rte_mbuf_ref_read(mbuf),skb->used,skb->users,skb->hdr_len
			,skb->len,skb->mac_len,skb->delta_csum_len
			,rte_pktmbuf_pkt_len(mbuf) , rte_pktmbuf_data_len(mbuf) );   // rte_mbuf_id_read(mbuf) */
	
	if (ethh == NULL ){
		us_abort(US_GET_LCORE());
	}
	
	if(skb->delta_csum_len){
		rte_pktmbuf_trim(mbuf,skb->delta_csum_len);
		skb->delta_csum_len = 0;		//trim once only;
	}
	
	//fill the dst mac with 0xff*6
	rte_memcpy(ethh->d_addr.addr_bytes, port->gw_mac, ETHER_ADDR_LEN);
	//fill the src mac with this port's mac

	rte_memcpy(ethh->s_addr.addr_bytes, port->if_mac, ETHER_ADDR_LEN);
	//fill the proto type with 0x0800
	ethh->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

	mbuf->pkt.vlan_macip.f.l2_len = sizeof(struct ether_hdr);
	mbuf->pkt.vlan_macip.f.l3_len = sizeof(struct iphdr);

	set_iptcp_csum_offload(mbuf);

	//rte_pktmbuf_dump(mbuf,rte_pktmbuf_data_len(mbuf));
}

inline	void us_ip_send_flush(unsigned long data)
{
	s32 n = 0;
	struct net *pnet =	US_PER_LCORE(init_net);
	u32 port_id = pnet->port_id;
	u32 queue_id = pnet->send_queue_id;
	
	u32 *mmbuf_flush_p = &US_PER_LCORE(mmbuf_flush);
	u32 *mmbuf_num_p = &US_PER_LCORE(mmbuf_num);

	struct rte_mbuf** mmbuf_p = US_PER_LCORE(mmbuf);

	(*mmbuf_flush_p) = (*mmbuf_flush_p) + 1;
	(*mmbuf_flush_p) = (*mmbuf_flush_p) > 4 ? 4 : (*mmbuf_flush_p) ;

	if((*mmbuf_num_p) > 0){
		n = rte_eth_tx_burst(port_id, queue_id ,  mmbuf_p, (*mmbuf_num_p));
		NET_ADD_STATS_BH(pnet,IPSTATS_MIB_OUTPKTS , (*mmbuf_num_p) - n);
		(*mmbuf_num_p) -= n;

		//if(n > 0){
		//	NET_ADD_STATS_BH(pnet,IPSTATS_MIB_OUTPKTS , (*mmbuf_num_p) - n);
		//	(*mmbuf_num_p) -= n;
		//}else{
		//	NET_ADD_STATS_BH(pnet,IPSTATS_MIB_OUTPKTS , (*mmbuf_num_p) );
		//	(*mmbuf_num_p) = 0;
		//}	
	}

	if(data){	
		us_mod_timer((struct us_timer_list *)data , jiffies + 1);
	}
}

inline s32 skb_to_mbuf(struct sk_buff *skb,struct rte_mbuf*mbuf,struct iphdr*iph_s,
					struct tcphdr 	*th_s,u16  iph_len,u16  th_len,s32 *offset)
{
	s32 ret ;
	u32 left;
	s32 copied;
	s32 adj_len;
	u8	*d_head;
	struct iphdr     *iph_m;
	struct tcphdr 	 *th_m;
	struct ether_hdr *ethh;
	us_nic_port 	 *port;

	port 	= skb->pnet->port;
	left 	= (skb->tail - skb->data ) - *offset;
    copied 	= left > skb->gso_size ? skb->gso_size : left;

	if(copied <= 0){
		ret = 1;
		goto out;
	}
	
	d_head  = (u8*)rte_pktmbuf_append(mbuf ,US_MIN_IPV4_TCP_HEADER  + copied);  //(iph_len + th_len)
	d_head  = (u8*)rte_pktmbuf_mtod(mbuf, void*);

	/*
	US_ERR("d_head:%p append:%u gso_size:%u left:%u mbuf_id:%u pkt_len:%u data_len:%u tail_len:%u head_rom:%u buf_len:%u\n"
				,d_head ,(US_MIN_IPV4_TCP_HEADER  + copied),  skb->gso_size ,left
				,rte_mbuf_id_read(mbuf),rte_pktmbuf_pkt_len(mbuf),rte_pktmbuf_data_len(mbuf)
				,rte_pktmbuf_tailroom(mbuf)
				,RTE_PKTMBUF_HEADROOM
				,mbuf->buf_len); */

	
	d_head += US_MIN_IPV4_TCP_HEADER ; 		//(iph_len + th_len);
	memcpy((u8*)d_head, skb->data + (*offset) , copied);
	
	d_head -= th_len;
	memcpy(d_head,th_s,th_len);
	th_m = (struct tcphdr 	*)d_head;

	th_m->doff = (th_len>>2);
	th_m->seq = htonl(ntohl(th_s->seq) + (*offset) - (iph_len + th_len));
	th_m->psh = 0;

	if(unlikely((*offset) + copied == skb->len)){   //left + (*offset)
		th_m->psh = 1;
		ret = 1;		
	}else{
		ret = 0;
	}

	th_m->check = 0;
	d_head -= iph_len;
	iph_m = (struct iphdr *)d_head;

	memcpy(d_head,iph_s,iph_len);
	iph_m->ihl = iph_len >>2;

	iph_m->tot_len = htons(iph_len + th_len + copied);
	ip_select_ident_more(iph_m, skb->sk, (skb->gso_segs ?: 1) - 1);

	iph_m->check = 0;
	th_m->check =  get_ipv4_psd_sum(iph_m);

	/*
	static s32 do_bad = 1;
	US_DEBUG("skb->len:%u skb->used:%u \n",skb->len ,skb->used);
	
	if(skb->used > 0 && skb->used < 3)
		do_bad = 1;
	
	if( do_bad == 1) {  //ret == 0 &&
		th_m->check = -1;
	}
	
	do_bad++;

	fprintf(stderr,"TH:%u,src:%s,dst:%s,sport:%u,dport:%u,seq:%-12u,ack:%-12u,ipid:%-12u,len:%-12u,data_len:%u SYN:%u;PSH:%u;ACK:%u;FIN:%u;RST:%u; send!!!\n"
			,US_GET_LCORE(),trans_ip(iph_m->saddr),trans_ip(iph_m->daddr)
			,ntohs(th_m->source),ntohs(th_m->dest)
			,ntohl(th_m->seq),ntohl(th_m->ack_seq)
			,iph_m->id,ntohs(iph_m->tot_len),copied,th_m->syn,th_m->psh,th_m->ack,th_m->fin,th_m->rst);	
	
	
	//tcp_drop_local(skb,iph_m,th_m);
	*/

	ethh = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);
	
	adj_len = (u8 *)iph_m - (u8*)ethh - sizeof(struct ether_hdr);
	
	ethh = (struct ether_hdr*)rte_pktmbuf_adj(mbuf, adj_len);

	rte_memcpy(ethh->d_addr.addr_bytes, port->gw_mac, ETHER_ADDR_LEN);
	rte_memcpy(ethh->s_addr.addr_bytes, port->if_mac, ETHER_ADDR_LEN);
	ethh->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	
	mbuf->pkt.vlan_macip.f.l2_len = sizeof(struct ether_hdr);
	mbuf->pkt.vlan_macip.f.l3_len = sizeof(struct iphdr);

	set_iptcp_csum_offload(mbuf);

	*offset += copied;

	//recv_pkt_dump(&mbuf, 1);

out:
	return ret;
}


inline s32 ip_send_out(struct net *pnet,struct rte_mbuf *mbuf,struct sk_buff *skb)
{
	s32 n = 0;
	s32 ret = 0;
	u32 port_id = pnet->port_id;
	u32 queue_id = pnet->send_queue_id;

	u32 mmbuf_num_local = US_PER_LCORE(mmbuf_num);
	u32 *mmbuf_num_p = &US_PER_LCORE(mmbuf_num);
	
	u32 mmbuf_flush_local = US_PER_LCORE(mmbuf_flush);

	struct rte_mbuf** mmbuf_local = US_PER_LCORE(mmbuf);
	
	if(unlikely(skb->nf_trace && (mmbuf_num_local > 0))){
		n = rte_eth_tx_burst(port_id, queue_id ,  mmbuf_local, mmbuf_num_local);
		if(n < mmbuf_num_local){
			(*mmbuf_num_p) -= n;
			ret = US_RET_OK;
			return ret;				//If sendout failed,tcp retrans start; Attention,do not go through here;
			//ret = US_ENETDOWN;
		}else{
			NET_ADD_STATS_BH(skb->pnet,IPSTATS_MIB_OUTPKTS , mmbuf_num_local);
			ret = US_RET_OK;
			(*mmbuf_num_p) = 0;	
		}
		mmbuf_flush_local = 0;	
	}
	
	mmbuf_local[(*mmbuf_num_p)++] = mbuf;
	mmbuf_num_local = (*mmbuf_num_p);
	
	if( (mmbuf_num_local >=  US_MAX_PKT_BURST_OUT - 2) || (mmbuf_flush_local > 2)){
		
		n = rte_eth_tx_burst(port_id, queue_id ,  mmbuf_local, mmbuf_num_local);	
		if(n < mmbuf_num_local){
			(*mmbuf_num_p)  -= n;
			ret = US_RET_OK;
			//ret = US_ENETDOWN;
		}else{
			NET_ADD_STATS_BH(skb->pnet,IPSTATS_MIB_OUTPKTS , mmbuf_num_local);
			ret = US_RET_OK;
			(*mmbuf_num_p)  = 0;
		}
		//mmbuf_flush_local--;
		mmbuf_flush_local = 0;
	}

	US_PER_LCORE(mmbuf_flush) = mmbuf_flush_local;

	return ret;
}

/*
inline s32 ip_out_finish(struct sk_buff *skb)
{	
	s32 ret;
	struct rte_mbuf *mbuf = (struct rte_mbuf*)(skb->head);
	struct net		*pnet = skb->pnet;

	if(skb->nohdr ){
		if( skb->nf_trace ){
			rte_pktmbuf_prepend(mbuf, skb->mac_len);
		}

		mbuf_rebuild(skb , pnet->port);	
		ret = ip_send_out(pnet,mbuf,skb);
		
		recv_pkt_dump(&mbuf, 1);

		
		//n = rte_eth_tx_burst(pnet->port_id, pnet->send_queue_id , &mbuf, 1);	
		//if(n < 1){
		//	US_ERR("TH:%u ,tx_burst failed on skb_id:%u sk_id:%u \n"
		//			,US_GET_LCORE(),skb->skb_id,skb->sk->sk_id);
		//	ret = US_ENETDOWN;
		//}else{
		//	ret = US_RET_OK;
		//	NET_ADD_STATS_BH(skb->pnet,IPSTATS_MIB_OUTPKTS , 1);  //skb->gso_segs == 1;
		//}

		if(skb->users == 1){		//smallboy: More attention about the users,clone,used and nf_trace;
			__kfree_skb(skb,US_MBUF_FREE_BY_OTHER);		//users == 1; not cloned;  or errors here;
		}else{	
			skb->users--;
			skb->used++;
		}
	}else{
		if(skb_can_gso(skb)){
			ip_send_out_batch(skb,pnet);
			ret = US_RET_OK;
		}else{
			ret = US_EPERM;
		}

		if(skb->users == 1){		//smallboy: More attention about the users,clone,used and nf_trace;
			__kfree_skb(skb,US_MBUF_FREE_BY_OTHER);		//users == 1; not cloned;  or errors here;
		}else{	
			skb->users--;
			skb->used++;
		}		
	}

	return ret;
}
*/


inline s32 ip_send_out_batch(struct sk_buff *skb,struct net*pnet)
{
	s32		i;
	u32     n;
	u32     snd_out = 0;
	s32     mbuf_num = 0;
	s32 	offset = 0;
	s32		ret = 0;
	u32  	port_id = pnet->port_id;
	u32		queue_id = pnet->send_queue_id;
	s32		mmbuf_num = US_MAX_PKT_BURST_OUT;
	struct rte_mbuf *mbuf	= NULL;

	if(skb->len < offset){
		//something here;		
		return US_EINVAL ;
	}

	struct iphdr   *iph_s = ip_hdr(skb);
	u32  iph_len		  = iph_s->ihl<<2;
	struct tcphdr   *th_s = (struct tcphdr*)((u8*)iph_s + iph_len);
	u32  th_len			  = th_s->doff<<2;
	
	offset	= th_len + iph_len;
	US_DEBUG("skb->len:%u skb->head:%p offset:%u\n",skb->len,skb->head,offset);

	if(US_PER_LCORE(mmbuf_num) > 0){
		us_ip_send_flush(0);		
	}
	
send_again :
	for(i= 0,ret = 0; i < mmbuf_num && ret == 0; i++){
		mbuf = pnet->mmbuf[i];	
		rte_pktmbuf_reset(mbuf);
		ret = skb_to_mbuf(skb,mbuf,iph_s,th_s,iph_len,th_len,&offset);
		mbuf_num++ ;
	}
	
	if( mbuf_num > 0 ){	
		n = rte_eth_tx_burst(port_id, queue_id, &pnet->mmbuf[0], mbuf_num);
		
		if(unlikely(n < mbuf_num)) {
			IP_ADD_STATS(skb->pnet,IPSTATS_MIB_OUTDISCARDS , mbuf_num - n); 
			return US_ENETDOWN;
		}
		IP_ADD_STATS(skb->pnet,IPSTATS_MIB_OUTPKTS , n); 
		snd_out += n;
	}

	if( ret == 0)		//Not end;
		goto send_again;	

	return US_RET_OK;
}

//@brief, malloc msghdr && body from the buf_slab; buf_size == iov_len *iov_size;
//@input, iov_len: io vector num;(0<iov_len<US_MSGHDR_IOVLEN_MAX) ;
//@input, iov_size: io vector buf size(include the sk_buff head with MAX_TCP_HEADER);
//@output, return the pointer to msghdr alloced if successful; else NULL;
//@note, if iov_size == 0, then msghdr_malloc malloc the msghdr only; it's a reserved way for zero copy recv interface;
//@note , msghdr == msghdr struct + US_MSGHDR_IOVSIZE_MAX* (iovcector struct) + body; 
//@note ,body == struct sk_buff + MAX_TCP_HEADER + buf_real; or body == 0;
struct msghdr *msghdr_malloc(unsigned int iov_len,unsigned int iov_size)
{
	int i;
	int truesize = 0;
	int aft_iov_size = 0;
	struct 	sk_buff *skb   = NULL;
	struct msghdr 	*msg   = NULL; 
	struct iovec 	*iov   = NULL;
	us_objslab		*us_sp = US_PER_LCORE(us_msghdr_slab);

	if(iov_len > US_MSGHDR_IOVLEN_MAX || iov_size > US_MSGHDR_IOVSIZE_MAX ||iov_size <0){
		return NULL;
	}

	msg = us_memobj_slab_alloc(us_sp);
	if(msg == NULL){
		US_ERR("msg alloc failed!\n");
		return msg;
	}
	
	memset(msg, 0 , sizeof(struct msghdr));
	msg->msg_control = (void*)US_MSGHDR_MAGIC;
	
	msg->msg_iov = (struct iovec *)(msg + 1);
	
	iov = msg->msg_iov;
	aft_iov_size = (iov_size > 0) ? (iov_size + sizeof(struct sk_buff) + MAX_TCP_HEADER) : 0;

	if(aft_iov_size == 0){
		for(i=0 ;i< iov_len; i++){
			iov->iov_base = NULL;
			iov->iov_len  = 0;
			iov->meta_data = 0;
			msg->msg_iovlen++;
			iov++;
		}
	}else{
		for(i=0 ;i< iov_len; i++){
			iov->iov_base = (char *) us_buf_slab_alloc(aft_iov_size);
			if(iov->iov_base == NULL ){
				US_ERR("iov alloc failed!\n");
				goto err_out;
			}else{
				truesize = us_buf_slab_truesize(aft_iov_size) ;
				iov->iov_len = truesize - sizeof(struct sk_buff) - MAX_TCP_HEADER;
				
				skb = iobuf_to_skb(iov->iov_base , truesize); 
				skb_reserve(skb,MAX_TCP_HEADER);

				//iov->iov_base = skb->data;				
				iov->meta_data = skb;
				
				msg->msg_iovlen++;
				iov++;
			}
		}
	}

	msg->msg_namelen = iov_size;
	msg->msg_controllen = msg->msg_iovlen;
	msg->msg_iovlen = 0;

	return msg;

err_out:
	iov = msg->msg_iov;
	
	for(i=0; i< msg->msg_iovlen;i++){
		skb = iov->meta_data;
		__kfree_skb(skb, US_MBUF_FREE_BY_STACK);
		iov++;

		//US_ERR("free buf_to_skb:%u \n", ((struct sk_buff*)(iov->meta_data))->skb_id);
	}

	us_memobj_slab_free(msg);
	return NULL;	
}

//@brief ,when there is a msghdr, realloc all the body(iovector) for it;
//@input ,msg: the pointer to msghdr which would hold all the body then;
//@input ,new_iov_len && new_iov_size --> the same with msghdr_alloc;
//@output, if err ,return the err_no; else return new_iov_len;
//@note , one can msghdr_realloc a msg only when it is none(no body);
s32 msghdr_realloc(struct msghdr *msg, int new_iov_len, int new_iov_size)
{
	int i;
	int iov_len ;
	int iov_size ;
	int truesize = 0;
	int aft_iov_size = 0;
	struct sk_buff  *skb   = NULL;
	struct iovec 	*iov   = NULL;
	//us_objslab		*us_sp = US_PER_LCORE(us_msghdr_slab);

	if(msg == NULL ||  !msghdr_magic_ok(msg)){
		return US_EINVAL;
	}
	
	iov_len = msg->msg_controllen ;
	if(new_iov_len != 0)
		iov_len = new_iov_len;

	iov_size = msg->msg_namelen;
	if(new_iov_size != 0)
		iov_size = new_iov_size;		 
	
	if(iov_len > US_MSGHDR_IOVLEN_MAX || iov_size > US_MSGHDR_IOVSIZE_MAX ||iov_size <0){
		//US_DEBUG("func:%s,%u \n",__FUNCTION__,__LINE__);
		return US_EINVAL;
	}
	
	iov = msg->msg_iov;
	for(i=0 ;i< msg->msg_controllen; i++){
		if(iov->iov_base != NULL || iov->iov_len != 0 
			|| iov->meta_data != NULL ) {
			//US_DEBUG("func:%s,%u \n",__FUNCTION__,__LINE__);
			return US_EINVAL;
		}
		iov++;
	}

	iov = msg->msg_iov;
	msg->msg_iovlen = 0;
	
	aft_iov_size = (iov_size > 0) ? (iov_size + sizeof(struct sk_buff) + MAX_TCP_HEADER) : 0;

	if(aft_iov_size == 0){
		for(i=0 ;i< iov_len; i++){
			iov->iov_base = NULL;
			iov->iov_len  = 0;
			iov->meta_data = 0;
			msg->msg_iovlen++;
			iov++;
		}
	}else{
		for(i=0 ;i< iov_len; i++){
			iov->iov_base = (char *) us_buf_slab_alloc(aft_iov_size);
			if(iov->iov_base == NULL ){
				US_ERR("iov alloc failed!\n");
				goto err_out;
			}else{
				truesize = us_buf_slab_truesize(aft_iov_size) ;
				iov->iov_len = truesize - sizeof(struct sk_buff) - MAX_TCP_HEADER;
				
				skb = iobuf_to_skb(iov->iov_base , truesize); 
				skb_reserve(skb,MAX_TCP_HEADER);

				//iov->iov_base = skb->data;				
				iov->meta_data = skb;
				
				msg->msg_iovlen++;
				iov++;
			}
		}
	}

	msg->msg_namelen = iov_size;
	msg->msg_controllen = msg->msg_iovlen;
	msg->msg_iovlen = 0;

	return msg->msg_controllen;

err_out:
	iov = msg->msg_iov;
	
	for(i=0; i<msg->msg_iovlen;i++){
		skb = iov->meta_data;
		__kfree_skb(skb, US_MBUF_FREE_BY_STACK);
		iov++;

		//US_ERR("free buf_to_skb:%u \n", ((struct sk_buff*)(iov->meta_data))->skb_id);
	}

	return US_ENOMEM;	
}

//@brief, clear the msghdr and give the body back into the buf_slab;
//@input, msg--> the pointer to the msghdr being freed;
//@input, if(flag == US_MSGHDR_FREE_ALL) ; free the msghdr into the msghdr struct salb in the mean time;
void msghdr_free(struct msghdr *msg, int flag)
{
	int i;
	struct iovec   *iov;
	struct sk_buff *skb;
	if(msg){
		iov = &msg->msg_iov[0];
		for(i= 0; i< msg->msg_iovlen ;i++){
			if(iov->meta_data == NULL){
				us_buf_slab_free(iov->iov_base);
			}else{
				skb = (struct sk_buff*)iov->meta_data;
				skb->cached = 0;
				__kfree_skb(skb, US_MBUF_FREE_BY_STACK);
			}
			iov->iov_len = 0;
			iov++;
		}

		msg->msg_iovlen = 0;
		if(flag & US_MSGHDR_FREE_ALL) {
			msg->msg_iov = NULL;
			msg->msg_controllen = 0;
			us_memobj_slab_free(msg);
		}
	}
}

//@brief , try to find an available body in the msg and reserve;
//@input , msg->the pointer to the msghdr being scanned;
//@input , len: when called, *len is the buf_size which we are trying to got from the msghdr;
//@output, when success, return the start pointer of the buf available; else NULL;
//@output, when failed, *len hold the max buf_size availeble within the msghdr;
//@note , when append successfully, skb is reserved also;
//@note , us_send() try to append data into the skb available also,but the data is copied once here;
void *msghdr_append(struct msghdr *msg ,int *len)
{
	int i = 0;
	int want = *len;
	int left = 0;
	int msg_iovindex = 0;
	int msg_updated = 0;
	char *data = NULL;
	struct sk_buff *skb = NULL;
	if(!msghdr_magic_ok(msg)){
		*len = US_EINVAL;
		return NULL;
	}

	msg_iovindex = (msg->msg_iovlen == 0) ? msg->msg_iovlen : (msg->msg_iovlen - 1);
	for(i= msg_iovindex; i< msg->msg_controllen && msg_updated < 2; i++,msg_updated++){
		skb = msg->msg_iov[i].meta_data;
		left = msg->msg_iov[i].iov_len - skb->len;
		if(left >= want){
			data = skb_tail_pointer(skb);
			skb_put(skb,want);
			//msg->msg_iovlen = i + 1;
			return data;
		}else{
			*len = left;
			msg->msg_iovlen = i + 1;
		}
	}

	return NULL;
}

//@brief, return the iov_len of the msghdr;
s32 msghdr_iov_len(struct msghdr *msg )
{
	if(msg == NULL || !msghdr_magic_ok(msg))
		return 	US_EINVAL;
	
	return msg->msg_iovlen;
}

//@brief , get data pointer of the iovector within a msg whiched indexed by index;
//@input , msg->the pointer to msghdr operated on;
//@input , index of the vector being opreated;
//@input , when success, *len hold the data len while return is the data head pointer;
//@output, return NULL if failed while *len hold the errno;		   

void *msghdr_get_data(struct msghdr*msg, int index, int *len)
{
	//char *data ;
	struct sk_buff *skb;
	struct iovec   *iov;
	if(index < 0 || index > US_MSGHDR_IOVLEN_MAX){
		*len = US_EINVAL;
		return NULL;
	}		

	iov = &msg->msg_iov[index];
	if(iov && iov->iov_base != NULL && iov->iov_len > 0 && iov->meta_data!= NULL){
	 	skb = (struct sk_buff *) iov->meta_data;
		*len = skb->len;
		return skb->data;
	}else{
		*len = US_EFAULT;
		return NULL;
	}
	
}

//@brief ,try to trim some data area from the iovector dedicated; 
//@input ,msg->the pointer to the msghdr operated;
//@input ,index->indexed the iovector operated; 
//@input ,len --> the data len left after trim;
//@output, 0-->success; <0 --> failed;
s32 msghdr_trim_data(struct msghdr*msg, int index, int len)
{
	struct sk_buff	*skb = NULL;
	struct iovec *iov = NULL;
	if(msg == NULL || !msghdr_magic_ok(msg))
		return 	US_EINVAL;	
	if(index < 0 || (index > msg->msg_iovlen - 1) || len < 0)
		return 	US_EINVAL;	

	iov = &msg->msg_iov[index];
	if(iov->meta_data!= NULL && iov->iov_base!= NULL){
		skb = (struct sk_buff*)iov->meta_data;
		return skb_trim(skb,len);
	}else{
		return US_EFAULT;
	}	
}

//@brief ,try to append data area into the iovector dedicated;
//@input ,len: the length try to append;
//@output,return the data head pointer when success,else NULL;
void *msghdr_append_data(struct msghdr*msg, int index, int len)
{
	return NULL;
}

//@brief , reserve some data area at the head of iovector dedicated;
//@input , len: the length try to cut off from the head of iovector;
//@output, return the new data head pointer when success; else NULL;
void *msghdr_pull_data(struct msghdr*msg, int index, int len)
{
	return NULL;
}

/*
struct msghdr *msghdr_format(void *data, int len)
{
	struct msghdr *msg = NULL;
	if(len < sizeof(struct msghdr) + sizeof(struct iovec)){
		return NULL;
	}

	msg = (struct msghdr *) data;
	msg->msg_control = (void*)US_MSGHDR_MAGIC;
	msg->msg_iov = (struct iovec *) (((char *)msg) + sizeof(struct msghdr));
	msg->msg_iov[0].iov_base = msg->msg_iov + sizeof(struct iovec);
	msg->msg_iov[0].iov_len = len - sizeof(struct iovec) - sizeof(struct msghdr);
	
	msg->msg_controllen = msg->msg_iov[0].iov_len;
	msg->msg_iovlen = 1;

	return msg;
}*/


//@brief, for debug;
void us_mon_mem_dump(void)
{
	u32 i = 0;
	u32 tid = 0;
	
	fprintf(stderr,"TH:%u,********************************\n",US_GET_LCORE());
	fprintf(stderr,"%-12s,%-12s,%-12s,%-12s,%-12s,%-12s,%-12s,%-12s,%-12s\n"
		,"tcpm:tcpm","sock:sock","socket:socket","reqsock:reqsock","tw_sock:tw_sock","bbucket:bbucket"
		,"mbuf_r:mbuf_r","mbuf_s:mbuf_s","io_ring:io_ring");
	
	for(tid = 0; tid < US_LCORE_MAX; tid++){
		if(glb_thread[tid].th_type == US_THREAD_USTACK ){  // && tid == GLB_US_LCORE_LB
			for(i=0; i<US_MEMPOOL_TYPE*2 ; i += 2){
				fprintf(stderr,"%u:%-10u    ",glb_memobj[tid][i],glb_memobj[tid][i+1]);
			}
			fprintf(stderr,"\n");
		}
	}
	fprintf(stderr,"TH:%u,********************************\n",US_GET_LCORE());
}

//@brief, for debug;
void us_mon_cpu_dump(void)
{
	u32 tid = 0;

	u64 time_base = 0;
	u64	mon_us_server_old = 0;
	u64	mon_us_server = 0;	
	u64	mon_us_server_max = 0;
	
	fprintf(stderr,"TH:%u,*******USTACK:****APP:******US_TIMER:*******\n",US_GET_LCORE());
	
	for(tid = 0; tid < US_LCORE_MAX; tid++){
		if(glb_thread[tid].th_type == US_THREAD_USTACK ){	 //&& tid == GLB_US_LCORE_LB	//For debug;
			time_base = cycles - glb_thcpu[tid].old_tt;
			fprintf(stderr,"TH:%u,***US_STACK :%8u    US_APP :%8u    US_TIMER:%8u		IDLE:%8u\n"
						,tid
						,(u32)(glb_thcpu[tid].ustack*100/time_base)
						,(u32)(glb_thcpu[tid].uapp*100/time_base)
						,(u32)(glb_thcpu[tid].utimer*100/time_base)
						,(u32)(glb_thcpu[tid].uidle*100/time_base));

			glb_thcpu[tid].new_tt = cycles;

			
			mon_us_server_old = glb_thcpu[tid].usser_num_old;
			mon_us_server = glb_thcpu[tid].usser_num;
			mon_us_server_max = glb_thcpu[tid].usser_num_max;
			
			mon_us_server_max = mon_us_server_max > (mon_us_server - mon_us_server_old) ?
									mon_us_server_max:(mon_us_server - mon_us_server_old);

			fprintf(stderr,"TH:%u,***us_server/s:%lu	us_server/s(max):%lu\n"
					,tid,(mon_us_server - mon_us_server_old)
					,mon_us_server_max);

			glb_thcpu[tid].usser_num_old = mon_us_server;
			glb_thcpu[tid].usser_num_max = mon_us_server_max;
				
		}
	}
	fprintf(stderr,"TH:%u,********************************\n",US_GET_LCORE());
}

//@brief, for debug;
void th_probe(void)
{
#define US_MON_DEAD_RETRY	(5)
	s32 i;
	s8  tmp;
	us_th_info *th_infp;

	if(jiffies - glb_mon_jiff_probe > US_MON_QUANTUM){
		glb_mon_jiff_probe = jiffies;
		for(i=0;i<US_LCORE_MAX;i++){
			th_infp = &glb_thread[i]; 
			if(th_infp->th_type == US_THREAD_RECEIVER
				|| th_infp->th_type == US_THREAD_USTACK){

				th_infp->probe += (th_infp->cyc_new == th_infp->cyc_old);

				if(th_infp->probe > US_MON_DEAD_RETRY){
					US_ERR("US_THREAD :%d is dead!\n",i);
					us_abort(i);
				}

				tmp = th_infp->probe - (th_infp->cyc_new != th_infp->cyc_old);
				th_infp->probe = tmp > 0 ? tmp : 0;								
				th_infp->cyc_old = th_infp->cyc_new;
			}
		}
	}
}


void us_check_lcore(void)
{
	u32 lcore = US_GET_LCORE();
	if (!rte_lcore_is_enabled(lcore)) {	
		US_ERR("lcore :%u is offline! Abort!\n",lcore);
		glb_thread[lcore].state = US_THREAD_ABORT;
		us_abort(US_GET_LCORE());
	}
}


//@brief, for debug;
void debug_print_msg(struct msghdr *msg,char *func)
{
	int i = 0;
	struct sk_buff  *skb = NULL;
	struct iovec   *iov_test = &msg->msg_iov[0];
	for(i = 0; i< msg->msg_iovlen;i++,iov_test++){
		skb = iov_test->meta_data;
		US_DEBUG("func:%s msg->iovlen:%u msg->msg_controlen:%u skb:%p\n"
				,__FUNCTION__,msg->msg_iovlen,msg->msg_controllen,skb);
		if(!skb) {
			//US_DEBUG("func:%s, skb->id:%u skb->len:%u sk->id:%u \n"
			//		,func,skb->skb_id,skb->len,skb->sk->sk_id);
			us_abort(2);
		}
	}
}

//smallboy:For debug,not safe for multiprocess env;
s8 *trans_ip(u32 ip)
{
	static u8 i = 0;
	static s8 g_print_ip_buf[5][20];		
	
	i = (i+1)%5;
	memset(g_print_ip_buf[i],0,20);
	sprintf(g_print_ip_buf[i],"%d.%d.%d.%d",
	((unsigned char *)&ip)[0],\
	((unsigned char *)&ip)[1],\
	((unsigned char *)&ip)[2],\
	((unsigned char *)&ip)[3]);
	return g_print_ip_buf[i];
}

//@brief ,for debug only;
void memobj_dump_all(void)
{
	us_ring *ring_p = US_PER_LCORE(ring);
	us_mempool* mbuf_pool_rp = US_PER_LCORE(mbuf_pool_r);
	us_mempool* sock_poolp = US_PER_LCORE(sock_pool);
	us_mempool* socket_poolp = US_PER_LCORE(socket_pool);

	//us_objslab* socket_slabp = US_PER_LCORE(socket_slab);
	//us_mempool* sk_head_poolp = US_PER_LCORE(sk_head_pool);

	us_mempool* tcp_metirc_poolp = US_PER_LCORE(tcp_metric_pool);
	us_mempool* sk_req_poolp = US_PER_LCORE(sk_req_pool);
	
	//us_objslab* sk_req_slabp = US_PER_LCORE(sk_req_slab);
	//us_objslab* sk_tw_slabp = US_PER_LCORE(sk_tw_slab);

	us_mempool* sk_tw_poolp = US_PER_LCORE(sk_tw_pool);
	us_mempool* mbuf_pool_sp = US_PER_LCORE(mbuf_pool_s);
	us_mempool* ibbucket_poolp = US_PER_LCORE(ibbucket_pool);

	u32 lcore = US_GET_LCORE();
	if(glb_thread[lcore].th_type == US_THREAD_USTACK){
		//glb_memobj[lcore][0] = rte_mempool_free_count(sk_head_poolp); 
		//glb_memobj[lcore][1] = rte_mempool_count(sk_head_poolp);

		glb_memobj[lcore][0] = rte_mempool_free_count(tcp_metirc_poolp); 
		glb_memobj[lcore][1] = rte_mempool_count(tcp_metirc_poolp);

		glb_memobj[lcore][2] = rte_mempool_free_count(sock_poolp); 
		glb_memobj[lcore][3] = rte_mempool_count(sock_poolp);

		glb_memobj[lcore][4] = rte_mempool_free_count(socket_poolp); 
		glb_memobj[lcore][5] = rte_mempool_count(socket_poolp);

		//glb_memobj[lcore][4] = socket_slabp->slab_used; 
		//glb_memobj[lcore][5] = socket_slabp->slab_num;

		glb_memobj[lcore][6] = rte_mempool_free_count(sk_req_poolp); 
		glb_memobj[lcore][7] = rte_mempool_count(sk_req_poolp);

		//glb_memobj[lcore][6] = sk_req_slabp->slab_used;
		//glb_memobj[lcore][7] = sk_req_slabp->slab_num;

		glb_memobj[lcore][8] = rte_mempool_free_count(sk_tw_poolp); 
		glb_memobj[lcore][9] = rte_mempool_count(sk_tw_poolp);

		//glb_memobj[lcore][8] = sk_tw_slabp->slab_used; 
		//glb_memobj[lcore][9] = sk_tw_slabp->slab_num;

		glb_memobj[lcore][10] = rte_mempool_free_count(ibbucket_poolp); 
		glb_memobj[lcore][11] = rte_mempool_count(ibbucket_poolp);

		glb_memobj[lcore][12] = rte_mempool_free_count(mbuf_pool_rp); 
		glb_memobj[lcore][13] = rte_mempool_count(mbuf_pool_rp);

		glb_memobj[lcore][14] = rte_mempool_free_count(mbuf_pool_sp); 
		glb_memobj[lcore][15] = rte_mempool_count(mbuf_pool_sp);

		glb_memobj[lcore][16] = rte_ring_free_count(ring_p); 
		glb_memobj[lcore][17] = rte_ring_count(ring_p);
		
		//rte_mempool_dump(sock_pool);
		//rte_mempool_dump(socket_pool);
		//rte_mempool_dump(sk_req_pool);
		//rte_mempool_dump(ibbucket_pool);
		//rte_mempool_dump(sk_tw_pool);
		//rte_mempool_dump(mbuf_pool);
		//rte_mempool_dump(sk_head_pool);
	}
}

//@brief ,for debug only;
void dmesg_all(const char *caller,int line)
{
	if(glb_thread[US_GET_LCORE()].th_type == US_THREAD_USTACK){
		us_ring	*ring_p = US_PER_LCORE(ring);
		us_mempool* mbuf_pool_rp = US_PER_LCORE(mbuf_pool_r);
		us_mempool* sock_poolp = US_PER_LCORE(sock_pool);
		us_mempool* socket_poolp = US_PER_LCORE(socket_pool);
		us_mempool* sk_head_poolp = US_PER_LCORE(sk_head_pool);
		us_mempool* sk_req_poolp = US_PER_LCORE(sk_req_pool);
		us_mempool* sk_tw_poolp = US_PER_LCORE(sk_tw_pool);
		us_mempool* mbuf_pool_sp = US_PER_LCORE(mbuf_pool_s);
		us_mempool* ibbucket_poolp = US_PER_LCORE(ibbucket_pool);

		
		fprintf(stderr,"\n\n%24s:%u \n",caller,line);
		fprintf(stderr,"%24s:%u:%u \n","ring",rte_ring_free_count(ring_p),rte_ring_count(ring_p));
		fprintf(stderr,"%24s:%u:%u \n","sock",rte_mempool_free_count(sock_poolp), rte_mempool_count(sock_poolp));
		fprintf(stderr,"%24s:%u:%u \n","socket",rte_mempool_free_count(socket_poolp), rte_mempool_count(socket_poolp));
		fprintf(stderr,"%24s:%u:%u \n","reqsocks",rte_mempool_free_count(sk_req_poolp), rte_mempool_count(sk_req_poolp));
		fprintf(stderr,"%24s:%u:%u \n","bindsocks",rte_mempool_free_count(ibbucket_poolp), rte_mempool_count(ibbucket_poolp));
		fprintf(stderr,"%24s:%u:%u \n","twsocks",rte_mempool_free_count(sk_tw_poolp), rte_mempool_count(sk_tw_poolp));
		fprintf(stderr,"%24s:%u:%u \n","mbuf_s",rte_mempool_free_count(mbuf_pool_sp), rte_mempool_count(mbuf_pool_sp));
		fprintf(stderr,"%24s:%u:%u \n","mbuf_r",rte_mempool_free_count(mbuf_pool_rp), rte_mempool_count(mbuf_pool_rp));
		fprintf(stderr,"%24s:%u:%u \n","sk_head",rte_mempool_free_count(sk_head_poolp), rte_mempool_count(sk_head_poolp));

		//rte_mempool_dump(sock_pool);
		//rte_mempool_dump(socket_pool);
		//rte_mempool_dump(sk_req_pool);
		//rte_mempool_dump(ibbucket_pool);
		//rte_mempool_dump(sk_tw_pool);
		//rte_mempool_dump(mbuf_pool);
		//rte_mempool_dump(sk_head_pool);
	}
}


//@brief ,for debug only;
void dmesg_snmp_ipstats(struct ipstats_mib	*ip_stat)
{
	if(glb_thread[US_GET_LCORE()].th_type == US_THREAD_USTACK && US_GET_LCORE() == GLB_US_LCORE_LB){		
		fprintf(stderr,"***************TH:%u IP_STATS**************\n",US_GET_LCORE());
	}
}

//@brief ,for debug only;
void dmesg_snmp_tcpstats(struct tcp_mib	*tcp_stat)
{	
	if(glb_thread[US_GET_LCORE()].th_type == US_THREAD_USTACK ){	
		fprintf(stderr,"***************TH:%u TCP_STATS**************\n",US_GET_LCORE());
		fprintf(stderr,
				"%s:%-16lu,%s:%-16lu,%s:%-16lu,%s:%-16lu\n"
				"%s:%-16lu,%s:%-16lu,%s:%-16lu,%s:%-16lu\n"
				"%s:%-16lu,%s:%-16lu,%s:%-16lu,%s:%-16lu\n"
				"%s:%-16lu,%s:%-16lu,%s:%-16lu\n"
				
				,"RTOALGORITHM",tcp_stat->mibs[TCP_MIB_RTOALGORITHM]
				,"RTOMIN      ",tcp_stat->mibs[TCP_MIB_RTOMIN] 
				,"RTOMAX      ",tcp_stat->mibs[TCP_MIB_RTOMAX] 
				,"MAXCONN     ",tcp_stat->mibs[TCP_MIB_MAXCONN] 
				,"ACTIVEOPENS ",tcp_stat->mibs[TCP_MIB_ACTIVEOPENS] 			//OK
				,"PASSIVEOPENS",tcp_stat->mibs[TCP_MIB_PASSIVEOPENS]			//OK
				,"ATTEMPTFAILS",tcp_stat->mibs[TCP_MIB_ATTEMPTFAILS]			//OK
				,"ESTABRESETS ",tcp_stat->mibs[TCP_MIB_ESTABRESETS]				//OK
				,"CURRESTAB   ",tcp_stat->mibs[TCP_MIB_CURRESTAB]				//OK
				,"INSEGS      ",tcp_stat->mibs[TCP_MIB_INSEGS]					//OK
				,"OUTSEGS     ",tcp_stat->mibs[TCP_MIB_OUTSEGS]					//OK
				,"RETRANSSEGS ",tcp_stat->mibs[TCP_MIB_RETRANSSEGS]				//OK
				,"INERRS      ",tcp_stat->mibs[TCP_MIB_INERRS]					//OK
				,"OUTRSTS     ",tcp_stat->mibs[TCP_MIB_OUTRSTS]					//OK
				,"CSUMERRORS  ",tcp_stat->mibs[TCP_MIB_CSUMERRORS]);			//OK	
	}
}

//@brief ,for debug only;
void dmesg_snmp_netstats(struct linux_mib	*net_stat )
{
	if(glb_thread[US_GET_LCORE()].th_type == US_THREAD_USTACK && US_GET_LCORE() == GLB_US_LCORE_LB){		
		fprintf(stderr,"***************TH:%u NET_STATS**************\n",US_GET_LCORE());
	}
}

//@brief ,for debug only;
void dmesg_snmp_all(void)
{
	struct net *pnet =  US_PER_LCORE(init_net);
	
	//struct ipstats_mib	*ip_stat = pnet->mib.ip_statistics[0];
	struct tcp_mib	*tcp_stat = pnet->mib.tcp_statistics[0];
	//struct linux_mib	*net_stat = pnet->mib.net_statistics[0];
	
	//dmesg_snmp_ipstats(ip_stat);
	dmesg_snmp_tcpstats(tcp_stat);
	//dmesg_snmp_netstats(net_stat);

}

//@brief ,for debug only;
void us_debug_tcp_sock_info(void)
{
	u32 i = 0;
	u32 j = 0;
	u32 lcore = US_GET_LCORE();
	if(glb_thread[lcore].th_type != US_THREAD_USTACK)
		return;

	if(lcore != GLB_US_LCORE_LB)
		return ;
	
	struct net *pnet = US_PER_LCORE(init_net);
	us_session_stat	*sstat_p = &pnet->session_info;
	
	struct inet_hashinfo *hash_info_p = US_PER_LCORE(tcp_hashinfo);
	
	struct sock *sk;
	struct inet_ehash_bucket *head ;  
	struct inet_listen_hashbucket *ilb;
	struct listen_sock *lopt;
	struct request_sock *req, **prev;
	const struct inet_connection_sock *icsk;

	memset(sstat_p,0,sizeof(us_session_stat));
	
	for(i = 0; i< US_INET_EHTABLE_SIZE;i++){
		head = &hash_info_p->ehash[i];
		if(head){
			sk_for_each(sk, &head->chain) {
				sstat_p->sessions[sk->sk_state]++;
			}
		}
	}

	for(i = 0; i< US_INET_EHTABLE_SIZE;i++){
		head = &hash_info_p->ehash[i];
		if(head){
			sk_for_each(sk, &head->twchain) {
				sstat_p->sessions[sk->sk_state]++;
			}
		}
	}

	for(i = 0; i< US_INET_LHTABLE_SIZE;i++){
		ilb = &hash_info_p->listening_hash[i];
		if(ilb){
			sk_for_each(sk, &ilb->head) {	
				sstat_p->sessions[sk->sk_state]++;
				icsk = inet_csk(sk);
				lopt = icsk->icsk_accept_queue.listen_opt;
				for(j = 0; j< lopt->nr_table_entries ;j++){
					for(prev = &lopt->syn_table[j];(req = *prev) != NULL;prev = &req->dl_next ){
						sstat_p->sessions[TCP_SYN_RECV]++;	
					}
				}			
			}
		}
	}

	US_DEBUG("***********************TH:%u****last:%lu S*********************\n"
		,US_GET_LCORE(),(jiffies - start_jiffies)/1000);

	fprintf(stderr,"TCP_ESTABLISHED:%8u TCP_SYN_RECV :%8u   TCP_FIN_WAIT1 :%8u  TCP_FIN_WAIT2:%8u\n"
			       "TCP_SYN_SENT   :%8u TCP_TIME_WAIT:%8u   TCP_LISTEN    :%8u  TCP_CLOSE    :%8u\n"
			       "TCP_LAST_ACK   :%8u TCP_CLOSING  :%8u   TCP_CLOSE_WAIT:%8u  \n"
			  ,sstat_p->sessions[TCP_ESTABLISHED],sstat_p->sessions[TCP_SYN_RECV]
			  ,sstat_p->sessions[TCP_FIN_WAIT1],sstat_p->sessions[TCP_FIN_WAIT2]
			  ,sstat_p->sessions[TCP_SYN_SENT],sstat_p->sessions[TCP_TIME_WAIT]
			  ,sstat_p->sessions[TCP_LISTEN],sstat_p->sessions[TCP_CLOSE]
			  ,sstat_p->sessions[TCP_LAST_ACK],sstat_p->sessions[TCP_CLOSING]
			  ,sstat_p->sessions[TCP_CLOSE_WAIT]);


}

//@brief ,for debug only;
void us_debug_th_info(struct tcp_info *th_info )
{
	US_LOG("state :%-8u,ca_state:%-8u,retransmits:%-8u,probes :%-8u,backoff  :%-8u,options :%-8u,snd_wscale:%-8u,rcv_wscale:%-8u\n"
				,th_info->tcpi_state,th_info->tcpi_ca_state,th_info->tcpi_retransmits,th_info->tcpi_probes,th_info->tcpi_backoff
				,th_info->tcpi_options,th_info->tcpi_snd_wscale,th_info->tcpi_rcv_wscale);

	US_LOG("rto   :%-8u,ato     :%-8u,snd_mss    :%-8u,rcv_mss:%-8u,unacked  :%-8u,sacked  :%-8u,lost      :%-8u,retrans   :%-8u\n"
				,th_info->tcpi_rto,th_info->tcpi_ato,th_info->tcpi_snd_mss,th_info->tcpi_rcv_mss,th_info->tcpi_unacked
				,th_info->tcpi_sacked,th_info->tcpi_lost,th_info->tcpi_retrans);

	US_LOG("pmtu  :%-8u,rcv_rtt :%-8u,rtt        :%-8u,rttvar :%-8u,rcv_space:%-8u,snd_cwnd:%-8u,advmss   :%-8u,fackets   :%-8u\n"
				,th_info->tcpi_pmtu,th_info->tcpi_rcv_rtt,th_info->tcpi_rtt,th_info->tcpi_rttvar,th_info->tcpi_rcv_space
				,th_info->tcpi_snd_cwnd,th_info->tcpi_advmss,th_info->tcpi_fackets);
	
	US_LOG("reordering    :%-16u,r_ssresh     :%-16u,s_ssresh      :%-16u,total_retrans:%-16u \n"
				,th_info->tcpi_reordering,th_info->tcpi_rcv_ssthresh,th_info->tcpi_snd_ssthresh,th_info->tcpi_total_retrans);

	US_LOG("last_data_sent:%-16u,last_ack_sent:%-16u,last_data_recv:%-16u,last_ack_recv:%-16u \n"
				,th_info->tcpi_last_data_sent,th_info->tcpi_last_ack_sent,th_info->tcpi_last_data_recv,th_info->tcpi_last_ack_recv);
	
}


void th_state_debug(void)
{
	if(jiffies - glb_mon_jiff_debug_mem  > US_MON_DEBUG_MEN_QUANTUM/10){
		glb_mon_jiff_debug_mem = jiffies;
		us_mon_mem_dump();
	}

	if(jiffies - glb_mon_jiff_debug_cpu  > (US_MON_DEBUG_MEN_QUANTUM/10)){
		glb_mon_jiff_debug_cpu = jiffies;
		us_mon_cpu_dump();
	}
	
}


