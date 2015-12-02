/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_stub.c
* @brief			a little test here;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/

//@note , when write a app using the us_* interface, include us_entry.h is enough;

#include "us_entry.h"

s32 glb_server_fd = -1;
u32	glb_dest_ip = 0;
u32	glb_client_ip = 0;

US_DECLARE_PER_LCORE(us_objslab *,us_server_slab);
US_DECLARE_PER_LCORE(us_objslab *,us_msghdr_slab);

extern us_nic_port	 us_nic_ports[APP_MAX_NIC_PORTS];

//extern int us_server_request_handle (struct socket *skt,void *arg,unsigned int b);
//extern int us_client_init(u32 delay);
//extern int us_proxy_client_request_handle(struct socket *skt, void *arg, unsigned int b);

extern int us_server_stub_init(void);
extern int us_socket_test(void);
extern int us_proxy_stub_init(void);
extern int us_slab_stub_test(void);

int icmp_v4_proxy(struct rte_mbuf *mbuf,struct iphdr *iph)
{
	u32 lcore;
	s32 icmp_len; 
	s32 ret ;
	u16 tot_len ;
	
	struct ether_hdr	*ethdr	= rte_pktmbuf_mtod(mbuf,struct ether_hdr *);	
	struct icmphdr		*icmph =(struct icmphdr*)((u8*)iph) + ((iph->ihl)<<2);
	tot_len 			= iph->tot_len;
	icmp_len			= (s32)(ntohs(tot_len) - (iph->ihl*4));
	
	mbuf->pkt.vlan_macip.f.l2_len = sizeof(*ethdr);
	mbuf->pkt.vlan_macip.f.l3_len = iph->ihl << 2;

	if( (icmp_len >= 8) && icmp_check_sum_correct((u16*)icmph, icmp_len) ){
		if(icmph->type == ICMP_ECHO){
			//US_DEBUG_LINE();
			lcore = US_GET_LCORE();
			iph->daddr = glb_dest_ip;
			iph->saddr = us_nic_ports[0].if_ipv4_bip[lcore];
			iph->check = 0;
			iph->ttl--;
			swap_mac(ethdr);
			
			icmph->checksum = 0;
			icmph->checksum = icmp_check_sum((u8*)icmph,icmp_len);
			set_ipv4_csum_offload(mbuf);
			//recv_pkt_dump(&mbuf, 1);

			goto send_out;
		}else if(icmph->type == ICMP_ECHOREPLY){
			//US_DEBUG_LINE();
			iph->daddr = glb_client_ip;
			iph->saddr = us_nic_ports[0].if_ipv4_vip[0];
			iph->check = 0;
			iph->ttl--;
			swap_mac(ethdr);

			icmph->checksum = 0;
			icmph->checksum = icmp_check_sum((u8*)icmph,icmp_len);
			set_ipv4_csum_offload(mbuf);
			//recv_pkt_dump(&mbuf, 1);
			
		}else{
			goto failed_out;
		}
	}else{
		goto failed_out;
	}
send_out:
		
	ret = rte_eth_tx_burst(us_nic_ports[0].port_id, 0,&mbuf, 1);
	if (ret < 1){
		goto failed_out;
	}

	return US_RET_OK;
failed_out:
	rte_pktmbuf_free(mbuf);
	return US_EINVAL;
	
}

#if 0
static int rcv_pkt_ipv4_process_test(struct rte_mbuf	*mbuf)
{	//US_DEBUG_LINE();
	struct ether_hdr	*ethdr = rte_pktmbuf_mtod(mbuf,struct ether_hdr *);	
	struct iphdr  *iph = (struct iphdr*)(ethdr + 1);
	if(iph->protocol == IPPROTO_ICMP){
		icmp_v4_proxy(mbuf,iph);
	}else {
		goto free_mbuf;
	}
free_mbuf:
	rte_pktmbuf_free(mbuf);
	return US_RET_OK;
}
#endif

s32 us_app_stub_init(void)
{	
	US_DEBUG("tcp_sock len:%u \n",sizeof(struct tcp_sock));
	US_DEBUG("tcp_sock len:%u \n",sizeof(struct inet_request_sock));
	US_DEBUG("tcp_sock len:%u \n",sizeof(struct tcp_timewait_sock));

	
	us_objslab * us_sp = us_memobj_slab_create(2, 
				sizeof(struct msghdr) + sizeof(struct iovec)*US_MSGHDR_IOVLEN_MAX, 8);
	if(us_sp == NULL){
		US_ERR("TH:%u,msghdr slab cache create failed!\n",US_GET_LCORE());
		return US_ENOMEM;
	}	

	US_PER_LCORE(us_msghdr_slab) = us_sp;
	//us_slab_stub_test();
	//us_socket_test();
	//us_server_stub_init();
	us_proxy_stub_init();

	//if(us_client_init(10)<0){
	//	US_ERR("TH:%u,client init failed!\n",US_GET_LCORE());
	//	return US_RET_OK;
	//}

	return US_RET_OK;
}

