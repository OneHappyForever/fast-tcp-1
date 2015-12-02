#include "us_entry.h"

#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <error.h>

//#include <gperftools/profiler.h>

//#include <arpa/inet.h>
US_DECLARE_PER_LCORE(us_tvec_base_t,Tb);

US_DECLARE_PER_LCORE(struct net*,init_net);
US_DECLARE_PER_LCORE(struct proto*,tcp_prot);

//US_DECLARE_PER_LCORE(us_netio_evb*,evb);
//US_DECLARE_PER_LCORE(us_netio_events*,reload_ev);

US_DEFINE_PER_LCORE(us_objslab *,us_msghdr_slab);

us_session_stat glb_session_info[US_LCORE_MAX];

extern us_ring	*io_ring[APP_MAX_IO_LCORES];

pthread_barrier_t glb_barrier;

u32	glb_thread_num = 4;
u32 glb_dump_off = 0;

char debug_name[] = "debug.lcore_xx.pcap";

static struct rte_eth_conf port_conf = {
	.rxmode = {
		//.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 1, /**< IP checksum offload enabled */
		.hw_ip_checksum = 1, 
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
		.mq_mode		= ETH_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IPV4 | ETH_RSS_IPV4_TCP, //ETH_RSS_IPV4,
		},
	},
	.txmode = {
		.mq_mode = ETH_DCB_NONE,
	},
	.fdir_conf = {
		.mode = RTE_FDIR_MODE_PERFECT,
		.pballoc 	= RTE_FDIR_PBALLOC_64K,
		.status 	= RTE_FDIR_NO_REPORT_STATUS,
	},
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0, /* Use PMD default values */
	.tx_rs_thresh = 0,	 /* Use PMD default values */
	.txq_flags = 0x0,
};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
};

enum US_PORT_STATE{
	PORT_INIT 	= 0,
	PORT_UP 	= 1,
	PORT_DOWN	= 2,
};


int	glb_dump_fd[US_LCORE_MAX]	= {-1};
US_DEFINE_PER_LCORE(us_rte_mbuf_a,mbuf_array);

volatile u32 	rev_finished[APP_MAX_IO_LCORES] = {0};
volatile u64	ring_ent_all[APP_MAX_IO_LCORES]	= {0};

static struct rte_eth_link 	rte_link;


int us_driver_init(void)
{
	if (rte_ixgbe_pmd_init() < 0) {
		US_ERR("rte_ixgbe_pmd_init failed\n");
		return -1;
	}

	if (rte_eal_pci_probe() < 0) {
		US_ERR("rte_eal_pci_probe failed\n");
		return -1;
	}

	return 0;
}


//smallboy: only one port is ready at now; it's not our job ;
s32 us_nic_port_init(void)
{
	s32 ret ,i ,j, ip_mask,gw_ip,vip1,vip2,bip;

	ret = inet_pton(AF_INET, "255.255.255.0", &ip_mask);
	if(ret < 0){
		US_ERR("ip mask error: wrong ip format\n");
		return ret;
	}

	ret = inet_pton(AF_INET, "192.168.29.1", &gw_ip);
	//ret = inet_pton(AF_INET, "192.169.39.1", &gw_ip);
	if(ret < 0){
		US_ERR("gw_ip error: wrong ip format\n");
		return ret;
	}

	
	ret = inet_pton(AF_INET, "192.168.29.2", &vip1);
	//ret = inet_pton(AF_INET, "192.169.39.3", &vip1);
	if(ret < 0){
		US_ERR("vip error: wrong ip format\n");
		return ret;
	}

	ret = inet_pton(AF_INET, "192.168.29.4", &vip2);
	//ret = inet_pton(AF_INET, "192.169.39.4", &vip2);
	if(ret < 0){
		US_ERR("vip error: wrong ip format\n");
		return ret;
	}

	bip = vip1;

	/*
	
	for(i=0;i<APP_MAX_NIC_PORTS;i++){
		//memset(&us_nic_ports[i],0,sizeof(us_nic_port));
		//us_nic_ports[i].port_id = i+1;

		memset(us_nic_ports[i].gw_mac,0xff,6);
		us_nic_ports[i].if_ipv4_mask = ip_mask;
		us_nic_ports[i].gw_ipv4_addr = gw_ip;
		us_nic_ports[i].if_ipv4_vip_num = 1;
		//us_nic_ports[i].if_ipv4_bip_num = 1;
		us_nic_ports[i].if_ipv4_vip[0] = vip1;
		//us_nic_ports[i].if_ipv4_bip[0] = bip;
		us_nic_ports[i].socket_id	= 1;		//Now be socket 1 here;	

		ret = us_fdir_init(us_nic_ports[i].port_id);
		if(ret < 0) {
			US_ERR("set fdir mask for port %d failed: %d %s\n"
						, us_nic_ports[i].port_id, ret, strerror(-ret));
			return ret;
		}

		//us_fdir_add(us_nic_ports[i].port_id, 0 ,vip);		//

		us_fdir_add(us_nic_ports[i].port_id, 0 ,vip1);
		us_fdir_add(us_nic_ports[i].port_id, 1 ,vip2);

		for(j=0;j<US_LCORE_MAX;j++){
			if(glb_thread[j].th_type == US_THREAD_RECEIVER){
				US_LOG("inet_pton:%s\n",US_BIP_VEC[j]);
				ret = inet_pton(AF_INET, US_BIP_VEC[j], &bip);
				if(ret < 0){
					US_ERR("bip error: wrong ip format for ip:%s\n",US_BIP_VEC[j]);
					return ret;
				}
				us_nic_ports[i].if_ipv4_bip[j]=bip;
				us_nic_ports[i].if_ipv4_bip_num++;

				us_fdir_add(us_nic_ports[i].port_id, glb_thread[j].queue_recv_id ,bip);   //glb_thread[j].queue_recv_id
			}
		}
	}*/
	
	i = 1;
	
	memset(us_nic_ports[i].gw_mac,0xff,6);
	us_nic_ports[i].if_ipv4_mask = ip_mask;
	us_nic_ports[i].gw_ipv4_addr = gw_ip;
	us_nic_ports[i].if_ipv4_vip_num = 1;
	//us_nic_ports[i].if_ipv4_bip_num = 1;
	
	//us_nic_ports[i].if_ipv4_vip[0] = vip1;
	us_nic_ports[i].if_ipv4_vip[0] = vip1;  //vip2;
	
	//us_nic_ports[i].if_ipv4_bip[0] = bip;
	us_nic_ports[i].socket_id	= 1;		//Now be socket 1 here;	

	ret = us_fdir_init(us_nic_ports[i].port_id);
	if(ret < 0) {
		US_ERR("set fdir mask for port %d failed: %d %s\n"
					, us_nic_ports[i].port_id, ret, strerror(-ret));
		return ret;
	}

	//us_fdir_add(us_nic_ports[i].port_id, 0 ,vip);		//

	us_fdir_add(us_nic_ports[i].port_id, 0 ,vip1);
	//us_fdir_add(us_nic_ports[i].port_id, 1 ,vip2);

	for(j=0;j<US_LCORE_MAX;j++){
		if(glb_thread[j].th_type == US_THREAD_USTACK){
			US_LOG("inet_pton:%s ,lcore:%u\n",US_BIP_VEC[j],j);
			ret = inet_pton(AF_INET, US_BIP_VEC[j], &bip);
			if(ret < 0){
				US_ERR("bip error: wrong ip format for ip:%s\n",US_BIP_VEC[j]);
				return ret;
			}
			us_nic_ports[i].if_ipv4_bip[j]=bip;
			us_nic_ports[i].if_ipv4_bip_num++;

			us_fdir_add(us_nic_ports[i].port_id, glb_thread[glb_thread[j].io_ring].queue_recv_id ,bip);   //glb_thread[j].queue_recv_id
		}
	}
	
	return US_RET_OK;
}

s32 us_nic_dev_init(void)
{
#if 0	
	s32 ret ,i ,j;
	static struct ether_addr 	ports_eth_addr;

	for(i = 0; i<APP_MAX_NIC_PORTS ;i++){
		ret = rte_eth_dev_configure(us_nic_ports[i].port_id
					, APP_MAX_RX_QUEUES_PER_NIC_PORT
					, APP_MAX_TX_QUEUES_PER_NIC_PORT
					, &port_conf);
		if( ret < 0){
			US_ERR("us_nic_port %d dev config failed!\n",i);
			return ret;
		}else{
			US_LOG("dev_port :%d init success, RX_QUEUE_NUM:%d TX_QUEUE_NUM:%d \n"
				,i ,APP_MAX_RX_QUEUES_PER_NIC_PORT,APP_MAX_TX_QUEUES_PER_NIC_PORT);
		}

		for( j = 0;j < APP_MAX_TX_QUEUES_PER_NIC_PORT;j++){
			ret = rte_eth_tx_queue_setup(us_nic_ports[i].port_id, j, 1024
					,rte_lcore_to_socket_id(j ), &tx_conf);
			if(ret < 0){
				US_ERR("TX_QUEUE %d init failed !\n",j);
				return ret;
			}else{
				US_LOG("TX_QUEUE %d init on socket:%d !\n",j,rte_lcore_to_socket_id(j + GLB_US_LCORE_LB));
			}
		}

		for(j = 0; j < APP_MAX_RX_QUEUES_PER_NIC_PORT; j++){
			mbuf_rp[j]	= rte_mempool_create(US_MBUFR_VEC[j], 
					US_MBUF_R_NB_LCORE, 1792 , 0,            // No local cache here;
					sizeof(struct rte_pktmbuf_pool_private),
					rte_pktmbuf_pool_init, NULL,
					us_pktmbuf_init, NULL,
					rte_lcore_to_socket_id(j), MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);
			
			if(ret < 0){
				US_ERR("mbuf_recv %d init failed !\n",j);
				return ret;
			}else{
				US_LOG("mbuf_recv %d init on socket:%d !\n",j,rte_lcore_to_socket_id(j));
			}

			ret = rte_eth_rx_queue_setup(us_nic_ports[i].port_id, j, 1024
						, rte_lcore_to_socket_id(j), &rx_conf, mbuf_rp[j]);
			if (ret < 0){
				US_ERR("RX_QUEUE %d init failed !\n",j);
				return ret;
			}else{
				US_LOG("RX_QUEUE %d init on socket:%d !\n",j,rte_lcore_to_socket_id(j));
			}

			
			io_ring[j] = rte_ring_create(US_RING_VEC[j],US_IO_RING_NB_LCORE
									,rte_lcore_to_socket_id(j), RING_F_SP_ENQ | RING_F_SC_DEQ);	
			if(io_ring[j] == NULL){
				US_ERR("io_ring %d init failed!\n", j);
				return US_EINVAL;
			}else{
				US_LOG("io_ring %d init on socket :%d!\n",j,rte_lcore_to_socket_id(j));
			}
		}

		ret = rte_eth_dev_start(us_nic_ports[i].port_id);
		if (ret < 0){
			US_ERR("rte_eth_dev_start failed! err=%d, port=%d\n",ret, us_nic_ports[i].port_id);
			return ret;
		}

		US_LOG("us_nic_ports index:%d port_id:%d \n",i,us_nic_ports[i].port_id);

		//rte_eth_link_get_nowait(us_nic_ports[i].port_id, &rte_link);
		rte_eth_link_get(us_nic_ports[i].port_id, &rte_link);
		
		if (rte_link.link_status) {
			US_LOG(" Link Up - speed %u Mbps - %s\n",(unsigned) rte_link.link_speed,
						(rte_link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n"));

			rte_eth_macaddr_get(us_nic_ports[i].port_id, &ports_eth_addr);

			memcpy(us_nic_ports[i].if_mac ,&ports_eth_addr ,6);

			US_LOG(" Link Up - speed %u Mbps - %s\n", (uint32_t) rte_link.link_speed,
			       	(rte_link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n"));

			US_LOG("\t Port %d MAC: %02x %02x %02x %02x %02x %02x\n",us_nic_ports[i].port_id,
					us_nic_ports[i].if_mac[0], us_nic_ports[i].if_mac[1], us_nic_ports[i].if_mac[2],
					us_nic_ports[i].if_mac[3], us_nic_ports[i].if_mac[4], us_nic_ports[i].if_mac[5]);

		} else {
			US_ERR(" Link Down\n");
			return US_EINVAL;
		}

		rte_eth_promiscuous_enable(us_nic_ports[i].port_id);		
	}

	return US_RET_OK;
#else
	s32 ret ,i ,j;
	static struct ether_addr 	ports_eth_addr;

	u32 r_que,t_que;
	for(i = 0,r_que=0,t_que=0; i< US_LCORE_MAX ;i++){
		if(glb_thread[i].th_type == US_THREAD_USTACK){
			t_que++;
		}else if(glb_thread[i].th_type == US_THREAD_RECEIVER){
			r_que++;
		}
	}

	US_ERR("t_que:%u r_que:%u \n",t_que,r_que);

	//for(i = 0; i<APP_MAX_NIC_PORTS ;i++)
	//i = 1;
	i = 1;
	{
		ret = rte_eth_dev_configure(us_nic_ports[i].port_id
					, t_que 							//APP_MAX_RX_QUEUES_PER_NIC_PORT
					, r_que							//APP_MAX_RX_QUEUES_PER_NIC_PORT
					, &port_conf);
		if( ret < 0){
			US_ERR("us_nic_port %d dev config failed!\n",i);
			return ret;
		}else{
			US_LOG("dev_port :%d init success, RX_QUEUE_NUM:%d TX_QUEUE_NUM:%d \n"
				,i ,t_que,r_que);
		}

		t_que =  r_que = 0;
		
		for(j = 0; j< US_LCORE_MAX; j++){			
			if(glb_thread[j].th_type == US_THREAD_USTACK){	
				ret = rte_eth_tx_queue_setup(us_nic_ports[i].port_id, t_que, 1024
							,rte_lcore_to_socket_id(j ), &tx_conf);
				if( ret < 0){
					US_ERR("TX_QUEUE %d on lcore:%u init failed !\n",t_que,j);
					return ret;
				}else{
					US_LOG("TX_QUEUE %d init on socket:%d for lcore:%u!\n"
							,t_que,rte_lcore_to_socket_id(j),j);
				}
				glb_thread[j].queue_send_id = t_que;
				glb_thread[j].port_id = i;
				t_que++;
			}else if(glb_thread[j].th_type == US_THREAD_RECEIVER){
				mbuf_rp[j]	= rte_mempool_create(US_MBUFR_VEC[j], 
					US_MBUF_R_NB_LCORE, US_MBUF_LENGTH_MAX , 8192,            //1792; No local cache here;
					sizeof(struct rte_pktmbuf_pool_private),
					rte_pktmbuf_pool_init, NULL,
					us_pktmbuf_init, NULL,
					rte_lcore_to_socket_id(j), MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);

				if(mbuf_rp[j] == 0 ) {
					US_ERR("mbuf_recv %d init on lcore:%u failed !\n",r_que,j);
					return ret;
				}else{
					US_LOG("mbuf_recv %d init on socket:%d for lcore:%u!\n",r_que,rte_lcore_to_socket_id(j),j);
				}

				ret = rte_eth_rx_queue_setup(us_nic_ports[i].port_id, r_que, 1024
						, rte_lcore_to_socket_id(j), &rx_conf, mbuf_rp[j]);
				if (ret < 0){
					US_ERR("RX_QUEUE %d on lcore:%u init failed ret:%d!\n",r_que,j,ret);
					return ret;
				}else{
					US_LOG("RX_QUEUE %d on lcore:%u init on socket:%d !\n",r_que,j,rte_lcore_to_socket_id(j));
				}

				glb_thread[j].queue_recv_id = r_que;
				glb_thread[j].port_id = i;

				io_ring[j] = rte_ring_create(US_RING_VEC[j],US_IO_RING_NB_LCORE
									,rte_lcore_to_socket_id(j), RING_F_SP_ENQ | RING_F_SC_DEQ);	
				if(io_ring[j] == NULL){
					US_ERR("io_ring %d init failed!\n", j);
					return US_EINVAL;
				}else{
					US_LOG("io_ring %d init on socket :%d!\n",j,rte_lcore_to_socket_id(j));
				}

				r_que++;
			}
		}

		ret = rte_eth_dev_start(us_nic_ports[i].port_id);
		if (ret < 0){
			US_ERR("rte_eth_dev_start failed! err=%d, port=%d\n",ret, us_nic_ports[i].port_id);
			return ret;
		}

		US_LOG("us_nic_ports index:%d port_id:%d \n",i,us_nic_ports[i].port_id);

		//rte_eth_link_get_nowait(us_nic_ports[i].port_id, &rte_link);
		rte_eth_link_get(us_nic_ports[i].port_id, &rte_link);
		
		if (rte_link.link_status) {
			US_LOG(" Link Up - speed %u Mbps - %s\n",(unsigned) rte_link.link_speed,
						(rte_link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n"));

			rte_eth_macaddr_get(us_nic_ports[i].port_id, &ports_eth_addr);

			memcpy(us_nic_ports[i].if_mac ,&ports_eth_addr ,6);

			US_LOG(" Link Up - speed %u Mbps - %s\n", (uint32_t) rte_link.link_speed,
			       	(rte_link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n"));

			US_LOG("\t Port %d MAC: %02x %02x %02x %02x %02x %02x\n",us_nic_ports[i].port_id,
					us_nic_ports[i].if_mac[0], us_nic_ports[i].if_mac[1], us_nic_ports[i].if_mac[2],
					us_nic_ports[i].if_mac[3], us_nic_ports[i].if_mac[4], us_nic_ports[i].if_mac[5]);

		} else {
			US_ERR(" Link Down\n");
			return US_EINVAL;
		}

		rte_eth_promiscuous_enable(us_nic_ports[i].port_id);		
	}

	return US_RET_OK;


#endif
}

s32 us_cpu_topology(void)  //arg here for cfg file;
{
	int i = 0;

	glb_thread_num = 0;
	for(i = 0 ;i< US_LCORE_MAX; i++){
		switch(i){
		case 0:
			glb_thread[i].io_ring = 0;
			glb_thread[i].th_type = US_THREAD_RECEIVER;
			glb_thread_num++;
			break;
		//case 3:
		//	glb_thread[i].io_ring = 3;
		//	glb_thread[i].th_type = US_THREAD_RECEIVER;
		//	glb_thread_num++;
		//	break;
		////case 0:
		//	glb_thread[i].io_ring = 1;
		//	glb_thread[i].th_type = US_THREAD_USTACK;
		//	glb_thread_num++;
		//	break;
		case 1:
			glb_thread[i].io_ring = 0;
			glb_thread[i].th_type = US_THREAD_USTACK;
			glb_thread_num++;
			break;
		case 2:
			glb_thread[i].th_type = US_THREAD_MON;
			glb_thread_num++;
			break;	
		default:
			glb_thread[i].th_type = US_THREAD_UNKNOW;
			break;
		}
	}

	return 0;

}

int us_cfg_init()
{
	s32 i ;
	s32 ret = US_RET_OK;

	for(i=0;i<APP_MAX_NIC_PORTS;i++){
		memset(&us_nic_ports[i],0,sizeof(us_nic_port));
		us_nic_ports[i].port_id = i;
	}

	us_cpu_topology();

	if((ret = us_nic_dev_init())<0){
		return ret;
	}

	if((ret = us_nic_port_init())<0){
		return ret;
	}

	return US_RET_OK;
}

static void sig_stop(int signo)
{
	u32 lcore;
	int *fd ;
	us_th_info	*th_infp;
	lcore = US_GET_LCORE();
	th_infp = &glb_thread[lcore];
	fd = &glb_dump_fd[lcore];
	
	if(US_TH_FLAG_DUMP_TEST(th_infp->th_flag)){
		if((*fd) > 0){
			close(*fd);
			*fd = -1;
			US_LOG("thread:%d close dump_fd on signal!\n",lcore);
		}
		exit(0);
	}else{
		exit(0);
	}
}

static void sig_dump(int signo)
{
	glb_dump_off = 1 - glb_dump_off ;
	US_DEBUG("debug_dump_pkt_off:%d \n",glb_dump_off);
}



static s8 tcpdump_file_hdr[]={	0xd4,0xc3,0xb2,0xa1,
								0x02,0x00,0x04,0x00,
								0x00,0x00,0x00,0x00,
								0x00,0x00,0x00,0x00,
								0xff,0xff,0x00,0x00,
								0x01,0x00,0x00,0x00};


static int pkt_dump_init(void)
{
	s32 ret;
	u32 lcore;

	lcore = US_GET_LCORE();
	
	debug_name[sizeof(debug_name)-8] = (lcore/10)+48; //'0'
	debug_name[sizeof(debug_name)-7] = (lcore%10)+48;
		
	glb_dump_fd[lcore] = open(debug_name,O_RDWR|O_CREAT|O_TRUNC|O_NONBLOCK);
	if (glb_dump_fd[lcore] < 0) {
		US_ERR("can not create pcap file for debug lcore:%d!\n",lcore);
		return -1;
	}

	ret = write(glb_dump_fd[lcore], tcpdump_file_hdr, sizeof(tcpdump_file_hdr));
    if(ret < sizeof(tcpdump_file_hdr)){	
		US_ERR("write pcap file header failed on lcore:%d!\n",lcore);
		close(glb_dump_fd[lcore]);
		glb_dump_fd[lcore] = -1;
		return -1;
    }

	return glb_dump_fd[lcore];
}

void app_init(void)
{
	signal(SIGINT,sig_stop);
	signal(SIGUSR1,sig_dump);
	time_init();
}


s32 us_env_init(int argc, char **argv)
{
	s32 ret = 0;
	ret = rte_eal_init(argc, argv);		// Init EAL 
	if (ret < 0)
		return US_EINVAL;

	//glb_thread_num = GLB_US_LCORE_RB/2 + 1;//

	ret = us_driver_init();
	if(ret < 0)
		return US_EINVAL;
	
	ret = us_cfg_init();
	if(ret < 0)
		return US_EINVAL;
	
	app_init();

	return US_RET_OK;
}

void mon_run(void)
{
	static u64 time_tik = 0;

	u32 lcore = US_GET_LCORE();

	US_LOG("mon_run on lcore %u \n",lcore);	
	glb_thread[lcore].th_type = US_THREAD_MON;	
	us_check_lcore();

	US_LOG("lcore(MON) :%u is waiting!\n",lcore);

	pthread_barrier_wait(&glb_barrier);
	glb_thread[lcore].state = US_THREAD_RUNING; 

	US_LOG("lcore(MON) :%u is running!\n",lcore);

	if(glb_server_fd < 0){
		glb_server_fd = open(US_SERVER_TEST_FILE,O_RDWR  ,O_TRUNC);
		if(glb_server_fd < 0){
			US_ERR("TH:%u, glb_server_fd file open failed! errno:%d\n",US_GET_LCORE(),errno);
		}
	}


	US_PER_LCORE(ring) = NULL;
	
	while(1){
		if ((time_tik & 0x7) == 0){
			time_update();
			th_state_debug();
			//th_probe();
			//cycles = rte_get_hpet_cycles();
		}
		
		time_tik++;
	}
}

inline void receiver_run(u32 port_id,u32 queue_id,u32 lcore)
{
	s32 ret ;
	u32 k;
	u32 nb_mbufs = 0;
	u64 temp_cycles = 0;
	static u64 local_cycles = 0;
	static u32 nb_water  = 0;
	//struct rte_mbuf**	mbuf_p = US_PER_LCORE(mbuf_array);

	struct rte_mbuf*	mbuf_p[US_MAX_PKT_BURST];

	temp_cycles = rte_rdtsc(); 
	nb_mbufs = rte_eth_rx_burst(port_id	,queue_id , &mbuf_p[0],US_MAX_PKT_BURST);

	if(likely( nb_mbufs > 0))  {
		ret = rte_ring_sp_enqueue_bulk(io_ring[lcore], (void **)&mbuf_p[0], nb_mbufs);
		if (unlikely(ret < 0)) {
			for(k = 0 ;k< nb_mbufs; k++){
				US_ERR("should not be here! lcore:%u io_ring:%u\n",US_GET_LCORE(),lcore);
				rte_pktmbuf_free(mbuf_p[k]);
				us_abort(US_GET_LCORE());
				//while(1);
			}
		}else{
			nb_water += nb_mbufs;
			if(nb_water > (US_MAX_PKT_BURST/2 - 1) || local_cycles > 256){
				local_cycles = 0;
				ring_ent_all[lcore] += nb_mbufs;
			}

			//ring_ent_all[lcore] += nb_mbufs;
		}
	}

	local_cycles += rte_rdtsc() - temp_cycles;

}

void recv_run() //s32 delta
{
	u32 queue_id ;
	u32 port_id ;
	
	s32 lcore = US_GET_LCORE();
	US_LOG("recver_run on lcore %d \n",lcore);

	//glb_thread[lcore].th_type = US_THREAD_RECEIVER;
	us_check_lcore();

	US_LOG("lcore(RECV) :%u is waiting!\n",lcore);
	pthread_barrier_wait(&glb_barrier);
	glb_thread[lcore].state = US_THREAD_RUNING; 

	queue_id = glb_thread[lcore].queue_recv_id;
	port_id	= glb_thread[lcore].port_id;

	//us_timer_init();
	//us_timer_test();

	//US_PER_LCORE(ring) = io_ring[lcore + delta];
	
	US_PER_LCORE(ring) = io_ring[lcore];

	US_LOG("lcore(RECV) :%u is running port:%u,recv_queue:%u!\n",lcore,port_id,queue_id);
	while(1) {
		if(rev_finished[lcore ] < 4){
			receiver_run(port_id,queue_id,lcore);
		}
		//timer_loop(100);
	}
}

void idle_run(void)
{	
	static u64  idle_num = 0;

	u32 lcore = US_GET_LCORE();
	glb_thread[lcore].th_type = US_THREAD_UNKNOW;
	
	us_check_lcore();

	US_LOG("lcore(IDLE) :%u is waiting!\n",lcore);
	//pthread_barrier_wait(&glb_barrier);
	glb_thread[lcore].state = US_THREAD_RUNING; 

	US_PER_LCORE(ring) = NULL;
	US_LOG("lcore(IDLE) :%u is running!\n",lcore);
	while(1){
		idle_num++;
	}
}

static inline int rcv_pkt_ipv4_process(struct rte_mbuf	*mbuf, struct ether_hdr *ethdr, struct net*pnet)
{
	int ret = US_RET_OK;
	//struct ether_hdr *ethdr;
	
	struct sk_buff   *skb_p;
	struct netns_ipv4	*n_ipv4 = &pnet->ipv4;

	//ethdr = rte_pktmbuf_mtod(mbuf,struct ether_hdr*);
	if(unlikely(!is_unicast_ether_addr(&ethdr->d_addr))){
		if(is_multicast_ether_addr(&ethdr->d_addr)){
			IP_INC_STATS_BH(pnet, IPSTATS_MIB_INMCASTPKTS);
		}else{
			IP_INC_STATS_BH(pnet, IPSTATS_MIB_INBCASTPKTS);
		}
		ret = EPROTONOSUPPORT;
		goto err_out;
	}

	if (unlikely(!is_ipv4_csum_correct_offload(mbuf))){
		IP_INC_STATS_BH(pnet, IPSTATS_MIB_CSUMERRORS);
		ret = US_EFAULT;
		goto err_out;
	}

	/*
	static s32 got_mac = 0;
	if(unlikely(got_mac == 0)){
		extern us_nic_port	 us_nic_ports[APP_MAX_NIC_PORTS];
		u32 if_id = 0;
		mac_copy(us_nic_ports[if_id].gw_mac, ethdr->s_addr.addr_bytes);
	}*/

	skb_p = mbuf_to_skb(pnet,mbuf,ethdr);
	//if (skb_p == NULL) {
	//	ret = US_ENOMEM;
	//	goto err_out;
	//}

	if(n_ipv4->pre_route_in){
		ret = n_ipv4->pre_route_in(skb_p);
		if(ret < 0){
			goto free_mbuf;
		}else if(ret == 0){
			goto err_out;
		}
	}

	IP_INC_STATS_BH(pnet, IPSTATS_MIB_INPKTS);

	if(likely(skb_p->protocol == IPPROTO_TCP)){
		ret = tcp_v4_rcv(skb_p);
		if (ret != US_RET_OK){
			goto free_mbuf;
		}
	}else if(skb_p->protocol == IPPROTO_UDP){
		goto free_mbuf;
	}else if(skb_p->protocol == IPPROTO_ICMP){
		ret = icmp_v4_recv(skb_p);
		if (ret != US_RET_OK)
			goto free_mbuf;
	}else {	
		goto free_mbuf;
	}

	return ret;
free_mbuf:

	//kfree_skb(skb_p);
	kfree_skb(skb_p,US_MBUF_FREE_BY_STACK);  //smallboy:Attention here;
	return US_RET_OK;

err_out:
	return ret;
}

void us_gw_init(void)
{
	int ret;
	struct ether_hdr 	*ethh;
	struct arphdr 		*arph; 
	struct rte_mbuf		*mbuf;

	mbuf = rte_pktmbuf_alloc_noreset(US_PER_LCORE(mbuf_pool_s));
	if (mbuf == 0){
		return ;
	}else{
		rte_pktmbuf_reset(mbuf);
	}

	/*
	struct rte_mbuf	*mlast = rte_pktmbuf_lastseg(mbuf);
	US_DEBUG("TH:%u, ether_hdr:%u,tailromm:%u,%u,%u,%u,%u\n"
				,US_GET_LCORE(),sizeof(struct ether_hdr)
				,rte_pktmbuf_tailroom(mlast)
				,rte_pktmbuf_tailroom(mbuf)
				,mbuf->buf_len
				,rte_pktmbuf_headroom(mbuf)
				,mbuf->pkt.data_len);*/

	ethh = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);	
	rte_pktmbuf_append(mbuf, sizeof(struct ether_hdr));   //ETHER_HDR_LEN

	/*
	US_DEBUG("TH:%u,ethh:%p ,gw_mac:%p,if_ma:%p,ADDR_LEN:%u,%u\n"
			,US_GET_LCORE(),ethh,us_nic_ports[0].gw_mac,us_nic_ports[0].if_mac,ETHER_ADDR_LEN);
	*/		
	
	memcpy(ethh->d_addr.addr_bytes, us_nic_ports[1].gw_mac , ETHER_ADDR_LEN);
	memcpy(ethh->s_addr.addr_bytes,us_nic_ports[1].if_mac , ETHER_ADDR_LEN);

	ethh->ether_type = htons(ETHER_TYPE_ARP);
	rte_pktmbuf_append(mbuf, sizeof(struct arphdr));
	
	arph = (struct arphdr*)(ethh + 1);	
	arph->ar_hrd = htons(0x01);
	arph->ar_pro = htons(0x0800);
	arph->ar_hln = 0x06;
	arph->ar_pln = 0x04;
	arph->ar_op = htons(0x01);	//request id

	memcpy(arph->src_mac, us_nic_ports[1].if_mac, ETHER_ADDR_LEN);
	memcpy(arph->src_ip, &(us_nic_ports[1].if_ipv4_vip[0]), 4);

	memset(arph->dest_mac ,0, ETHER_ADDR_LEN);
	memcpy(arph->dest_ip, &(us_nic_ports[1].gw_ipv4_addr), 4);

	//recv_pkt_dump(&mbuf, 1);
	ret = rte_eth_tx_burst(us_nic_ports[1].port_id , 0, &mbuf, 1);
	if (ret < 0) {
		US_LOG("&&&&&&&&&&&&&&&&&&&&&&&&&");
		rte_pktmbuf_free(mbuf);
		while(1);
	}
}

static int rcv_pkt_unknow_process(struct rte_mbuf *mbuf)
{
	if (!us_nic_ports[1].flags) {			//smallboy:no lock ,oho bug;
		us_gw_init();
	}

	return US_RET_OK;
}

void recv_pkt_dump(struct rte_mbuf **mbuf_array , u32 num_nb)
{
	int i;

	if(glb_dump_off){
		struct rte_mbuf *mbuf = NULL;
		//struct ether_hdr *ethh = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);
		static char pkt_buf [2048];
		pcap_pkthdr_t  *pcap_hdr_p = (pcap_pkthdr_t *)&pkt_buf[0];

	 	for(i = 0 ;i< num_nb; i++){
			mbuf = mbuf_array[i];
			//ethh = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);
			//pcap_hdr_p->len = rte_pktmbuf_data_len(mbuf);       //len has been 4bytes aligned!s
			pcap_hdr_p->len = mbuf->pkt.data_len;
	        pcap_hdr_p->caplen = pcap_hdr_p->len ;

			memcpy(pcap_hdr_p+1,mbuf->pkt.data ,pcap_hdr_p->len);
			//memcpy(pcap_hdr_p+1, ethh ,pcap_hdr_p->len);

			pcap_hdr_p->tv_sec = (u32)Ts.tv_sec;
	        pcap_hdr_p->tv_usec = (u32)Ts.tv_nsec/1000;

			write(glb_dump_fd[US_GET_LCORE()], pcap_hdr_p, sizeof(pcap_pkthdr_t) + pcap_hdr_p->len);
	 	}
	}
}


static int rcv_pkt_arp_process(struct rte_mbuf	*mbuf)
{	
	s32 ret = 0;
	u32 ip_mask = 0;
	int diff_mac;
	u32 if_id = 1;

	struct ether_hdr *ethh = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);
	struct arphdr *arph = (struct arphdr *)(ethh+1);

	u8* l2_dest_mac_p = (u8*) ethh;
	u8* l2_src_mac_p = (u8*) ethh + 6;

	u32 sip = read_not_aligned_word((u8*)arph->src_ip);
	u32 dip = read_not_aligned_word((u8*)arph->dest_ip);	

	ip_mask = us_nic_ports[if_id].if_ipv4_mask;
	
	if(((dip & ip_mask) == (us_nic_ports[if_id].if_ipv4_vip[0] & ip_mask))){		
		if( arph->ar_op == htons(ARPOP_REPLY) ){
            if (sip == us_nic_ports[if_id].gw_ipv4_addr){
				mac_copy(us_nic_ports[if_id].gw_mac, l2_src_mac_p);
				us_nic_ports[if_id].flags = 1;
            }else{
				goto err_out;			
            }
		}else if (arph->ar_op == htons(ARPOP_REQUEST)){
			/**when get a arp request, we first swap the src ip and dest ip of pkt*/
			swap_arp_ip((u16*)arph->src_ip, (u16*)arph->dest_ip);
			/** then write dest_mac with src mac of pkt*/
			mac_copy(arph->dest_mac, arph->src_mac);
			mac_copy(l2_dest_mac_p, l2_src_mac_p);
			/** change the arp option to arp reply*/
			arph->ar_op =  htons(ARPOP_REPLY);

			/**read the dev's mac, and write it to src mac*/
			mac_copy(l2_src_mac_p, us_nic_ports[if_id].if_mac);
			mac_copy(arph->src_mac, us_nic_ports[if_id].if_mac);	

			if (glb_dump_fd[US_GET_LCORE()] > 0){
				recv_pkt_dump(&mbuf, 1);
			}

			//rte_pktmbuf_dump(mbuf,64);
			ret = rte_eth_tx_burst(us_nic_ports[if_id].port_id, 0,&mbuf, 1);
			if (ret < 1){
				return US_ENETDOWN;
			}	

			us_nic_ports[if_id].flags = 1;
			
			return US_RET_OK;
		}else{
			goto err_out;
		}
	}else if(dip == sip 
				&& arph->ar_op == htons(ARPOP_REQUEST)) {	
		US_DEBUG();		
		diff_mac =  different_mac( l2_src_mac_p, us_nic_ports[if_id].gw_mac);
		if(diff_mac){
			mac_copy( us_nic_ports[if_id].gw_mac, l2_src_mac_p );
			us_nic_ports[if_id].flags = 1;
		}
		return US_RET_OK;
	}else {
		goto err_out;
	}	

err_out:
	return US_EPROTONOSUPPORT;
}

//@brief , ICMP for ping test only;
//@note  , unfinished job;
int icmp_v4_recv(struct sk_buff *skb)
{	
	s32 ret;
	u32 tmp_addr;
	s32 icmp_len;
	struct iphdr  		*iph;
	struct icmphdr 		*icmph;
	struct rte_mbuf 	*mbuf;
	struct ether_hdr	*ethdr;
	
	if (!skb->nohdr){
		return US_EINVAL;
	}

	mbuf = (struct rte_mbuf*)skb->head;
	ethdr =(struct ether_hdr*)skb->mac_header;
	
	iph   = (struct iphdr*)skb->network_header;
	icmph = (struct icmphdr*)skb->transport_header;

	icmp_len = ntohs(iph->tot_len ) - (iph->ihl*4);

	mbuf->pkt.vlan_macip.f.l2_len = sizeof(*ethdr);
	mbuf->pkt.vlan_macip.f.l3_len = iph->ihl << 2;
	
	if(icmp_len >= 8 ){ 
		if (icmph->type == ICMP_ECHO){
			if(icmp_check_sum_correct((u16*)icmph, icmp_len)){
				icmph->type = ICMP_ECHOREPLY;

				/**update icmp check sum*/

				/* Exchange ip addresses */
				tmp_addr = iph->saddr;
				iph->saddr = iph->daddr;
				iph->daddr = tmp_addr;

				/**update ip ttl*/
				iph->id++;
				iph->ttl--;
				iph->check = 0;
				swap_mac(ethdr);	
				icmp_update_checksum_echo_to_reply(icmph);
				//iph->check = get_ipv4_cksum(iph);
				set_ipv4_csum_offload(mbuf);						

				//rte_pktmbuf_dump(mbuf,rte_pktmbuf_data_len(mbuf));
				recv_pkt_dump(&mbuf, 1);
				
				ret = rte_eth_tx_burst(us_nic_ports[0].port_id, 0, &mbuf, 1);
				if (ret < 1){
					return US_ENETDOWN;
				}

				skb->nohdr = 0;
				skb->head = NULL;

				kfree_skb(skb,US_MBUF_FREE_BY_OTHER);   //smallboy:Attention here;
				//disp_int_stats();
				
				return US_RET_OK;
			}else{
				return US_EBADF;
			}
		}else {
			return US_EPROTONOSUPPORT;
		}
	}else {
		return US_EBADF;
	}
}

static inline s32  idle_loop(u64 *local_cycle_p, u32 lcore,u32 io_ring_no, s32 ring_ent_local , u64 adjust_w)
{
	s32  ring_ent    = 0;
	u64  local_cycle = *local_cycle_p;
	u64  tmp_cycle1	 = 0;
	u64  tmp_cycle2  = rte_rdtsc(); //rte_rdtsc() ;
	u64	 re_cycle    = 0;

recycle :
	tmp_cycle1 = tmp_cycle2;
	tmp_cycle2 = rte_rdtsc() ;  //rte_rdtsc() ;	
	re_cycle  += tmp_cycle2 - tmp_cycle1;
	
	ring_ent += ring_ent_all[io_ring_no ] - ring_ent_local;

	if(local_cycle > adjust_w){							//timer_loop  128 us;
		*local_cycle_p = 0;

		if(unlikely(glb_thcpu[lcore].new_tt != glb_thcpu[lcore].old_tt)){
			glb_thcpu[lcore].old_tt = glb_thcpu[lcore].new_tt;
			glb_thcpu[lcore].ustack = 0;
			glb_thcpu[lcore].utimer = 0;
			glb_thcpu[lcore].uapp 	= 0;
			glb_thcpu[lcore].uidle 	= 0;
		}

		glb_thcpu[lcore].uidle += local_cycle;	
		return 0;	
	}
	
	if(ring_ent > (US_MAX_PKT_BURST/2) ||  re_cycle > 4096 ){  			// pkt_loop;  4 us;	
		*local_cycle_p = local_cycle ;
		ring_ent = ring_ent < (US_MAX_PKT_BURST ) ? ring_ent: (US_MAX_PKT_BURST - 1);
		return ring_ent ;
	}else{											

		local_cycle += tmp_cycle2 - tmp_cycle1;
		goto recycle; 
	}
}

static inline s32	pkt_loop(us_ring *io_rp,u32 io_ring_no,u32 recv_num,struct net *pnet)
{
	u32 i;
	s32 ret = US_RET_OK;

	struct ether_hdr 	*ethh = NULL;
	//if(unlikely((recv_num == 0))){ 
	//	return US_EINVAL;
	//}

	struct rte_mbuf*	mbuf_recv_p[US_MAX_PKT_BURST];	
	
	ret = rte_ring_sc_dequeue_bulk(io_rp ,(void**)&mbuf_recv_p[0],recv_num);
	if(unlikely(ret == US_ENOENT)){
		return US_ENOENT;
	}

	rev_finished[io_ring_no] +=  recv_num;
	
	for(i = 0; i < recv_num ; i++){
		ethh = rte_pktmbuf_mtod( mbuf_recv_p[i], struct ether_hdr*);
		recv_pkt_dump(&mbuf_recv_p[i], 1);
		if( likely(ethh->ether_type ==  US_ETHER_TYPE_IPv4)) {
			if(rcv_pkt_ipv4_process(mbuf_recv_p[i], ethh, pnet)<0){
			//if(rcv_pkt_ipv4_process_test(mbuf_recv_p[i]) < 0){	
				goto free_mbuf;
			}
		}else if(ethh->ether_type == US_ETHER_TYPE_ARP){
			if(rcv_pkt_arp_process(mbuf_recv_p[i]) < 0){
				goto free_mbuf;
			}
		}else {
			rcv_pkt_unknow_process(mbuf_recv_p[i]);
			goto free_mbuf;
		}
		continue;
free_mbuf:
		rte_pktmbuf_free(mbuf_recv_p[i]);
	}

	rev_finished[io_ring_no] -= i; 
	return US_RET_OK;
}

static s32 us_inet_init(s32 delta)
{
	s32 ret;	
	s32 l_core = US_GET_LCORE();
	
	if ((ret = us_mempool_init( delta))<0) {  
		US_ERR("us_mem init for lcore:%d failed!\n",l_core);
		return ret;
	}else{
		US_LOG("us_mem init for lcore:%d over!\n",l_core);
	}

	if((ret = us_check_multithread()) != US_RET_OK){
		US_ERR("ustack init abort on locre:%u\n",l_core);
		return ret;
	}

	US_LOG("ustack init for lcore:%d over!\n",l_core);
	
	us_timer_init();

	if((ret = net_init(delta)) < 0){
		US_ERR("TH:%d,net_init failed!\n",l_core);
		return ret;
	}

	if((ret = ip_init()) < 0){
		US_ERR("TH:%d,ip_init failed!\n",l_core);
		return ret;
	}

	if((ret = tcp_init(delta)) < 0){
		US_ERR("TH:%d,tcp_init failed!ret:%d\n",l_core,ret);
		return ret;
	}

	if((ret = netio_ev_init()) < 0){
		US_ERR("TH:%d,netio_ev_init failed!ret:%d\n",l_core,ret);
	}
	
	return US_RET_OK;
}

int timer_loop(int budget)
{
	run_timer(&US_PER_LCORE(Tb),budget);
	return 0;
}

static int event_err_process(struct sock*sk,struct socket*skt)
{
	if(skt == NULL){
		US_ERR("TH:%u,BAD SOCKET ERROR!\n",US_GET_LCORE());
		return -1;
	}

	US_ERR("TH:%u,SOCKET ERROR!\n",US_GET_LCORE());
	
	us_close(skt);
	return 0;
}

static int event_read_process(struct sock*sk,struct socket*skt,u32 *sk_id_p)
{
	s32	ret = US_RET_OK;
	u32	read_flag = (TCPF_ESTABLISHED | TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2 
					| TCPF_CLOSE_WAIT | TCPF_CLOSING);

	*sk_id_p = sk->sk_id;
	if((!sock_flag(sk, SOCK_DEAD)) && skt && skt->state > SS_UNCONNECTED ){
		
		if(sk->sk_state == TCP_LISTEN){
			if(us_callback_l_reloaded(skt))	{		 //smallboy : ???	
				ret = skt->ops->accept(sk, skt ,0);  //smallboy: listen callback arg;
			}
			return ret;				
		}

		if((1 << sk->sk_state) & read_flag){
			if(skt == NULL){
				return US_ECHILD;			//smallboy: Child event before ,retry it later;
			}
			
			if(us_callback_r_reloaded(skt)){	
				ret = skt->ops->recvmsg(sk,skt);
			}else{
				if(us_callback_r_loaded(skt)){	
					skt->net_ev.read_ev++;	
				}
			}
		
			return ret;
		}else{
			return US_EAGAIN;
		}			
	}

	return ret;
}

static int event_write_process(struct sock*sk,struct socket*skt,u32 *skid)
{
	*skid = sk->sk_id;
	if((!sock_flag(sk, SOCK_DEAD)) && skt  && skt->state > SS_UNCONNECTED ){
		//US_DEBUG("TH:%u,func;%s\n",US_GET_LCORE(),__FUNCTION__);
		if(us_callback_c_reloaded(skt)){
			skt->connect_callback.cb(skt ,NULL, 0);
		}else if(us_callback_c_loaded(skt)){
			skt->net_ev.write_ev++;
		}
	}
	
	return 0;
}

int event_loop(struct us_netio_evb	*evb_p,struct us_netio_events	*reload_ev)
{
	u32 sockk_id = 0;
	bool delay_task = false;
	struct us_netio_events *evv_p = &evb_p->ev_b[evb_p->evb_index&(0x1)];

	struct us_netio_event	*ev_p = NULL;
	struct sock		*sk = NULL;
	struct socket	*skt = NULL;
	s32 i,j,ret,e_num;

	e_num = 0;

	for(i=0,ev_p = &(evv_p->netio_events[0]);i<evv_p->netio_event_index;i++,ev_p++){
		sk = ev_p->sk;
		if(ev_p->err_ev>0){
			event_err_process(sk,sk->sk_socket);
			ev_p->err_ev = 0;
			e_num++;
			continue;					//overlook the other event;
		}
		
		while(ev_p->read_ev > 0){		//LF_W ;only one here;
			ret = event_read_process(sk,sk->sk_socket,&sockk_id);
			if(ret < 0){
				if(ret == US_ECHILD){
					reload_ev->netio_events[reload_ev->netio_event_index++] = *ev_p;  //copy mem not pointer;					
					delay_task = true;
				}else{
					if(ret != US_EAGAIN){
						US_ERR("TH:%u,READ SIG EXEC FAILED FOR SK->ID:%u,%d\n",US_GET_LCORE(),sockk_id,ret);
						//snmp here;
					}
				}
				ev_p->read_ev = 0;
				break;
			}
			e_num++;
			ev_p->read_ev-- ;
		}
		
		if(ev_p->write_ev > 0){
			ret = event_write_process(sk,sk->sk_socket,&sockk_id);
			if(ret < 0){
				US_ERR("TH:%u,WRITE SIG EXEC ERROR FOR SK->ID:%u,%d\n",US_GET_LCORE(),sockk_id,ret);
				ev_p->write_ev = 0;
				break;
			}
			ev_p->write_ev = 0;
			e_num++;
		}		
	}
	
	evv_p->netio_event_index = 0;
	evb_p->evb_index++;

	if(unlikely(delay_task) ){
		for(j=0,ev_p=&(reload_ev->netio_events[0]);j<reload_ev->netio_event_index;j++,ev_p++){		
			sk = ev_p->sk;
			skt = ev_p->skt;
			if(ev_p->err_ev>0){		
				event_err_process(sk,skt);
				ev_p->err_ev = 0;
				continue;
			}

			while(ev_p->read_ev > 0){
				ret = event_read_process(sk,skt,&sockk_id);
				if(ret < 0){
					US_ERR("TH:%u,READ SIG EXEC LOST FOR SK->ID:%u\n",US_GET_LCORE(),sockk_id);
					ev_p->read_ev = 0;
					break;
				}
				ev_p->read_ev--;
			}		
		}
		
		reload_ev->netio_event_index = 0; 	//reexec once,clear all;
	}
	
	return e_num;
}

void ustack_run() //s32 delta
{	
	int ret = 0;
	int ring_ent = 0;
	u64	ring_ent_local = 0;
	u64	time_base = 0;
	u64	time_base_all = 0;
	us_ring	*io_rp = NULL;
	u32 io_ring_no = 0;
	
	s32 lcore = US_GET_LCORE();
	US_LOG("ustack_run on lcore %d \n",lcore);  //smallboy: fix it later;

	us_check_lcore();
	pkt_dump_init();
	
	ret = us_inet_init(0);  //delta
	if(ret < 0) {
		US_ERR("us_inet_init failed on locre:%d\n",lcore);
		return ;
	}

	
	ret = us_app_stub_init();
	if(ret < 0){
		US_ERR("us_app_stub init failed on lcore:%d\n",lcore);
		return ;
	}

	us_timer_test();

	US_LOG("lcore(USTACK) :%d is waiting!\n",lcore);
	pthread_barrier_wait(&glb_barrier);
	
	glb_thread[lcore].state = US_THREAD_RUNING;
	glb_thread[lcore].th_flag |= US_TH_FLAG_DUMP;

	//US_PER_LCORE(ring) = io_ring[lcore + delta];
	//US_PER_LCORE(mbuf_pool_r) = mbuf_rp[lcore + delta];
	io_ring_no = glb_thread[lcore].io_ring;
	io_rp = io_ring[io_ring_no];

	US_PER_LCORE(ring) = io_ring[io_ring_no];
	US_PER_LCORE(mbuf_pool_r) = mbuf_rp[io_ring_no];

	//dmesg_all(__FUNCTION__,__LINE__);
	
	US_LOG("lcore(USTACK) :%d is running!\n",lcore);

	//us_netio_evb	*evb_p = US_PER_LCORE(evb);
	//us_netio_events	*reload_ev = US_PER_LCORE(reload_ev);	

	glb_thcpu[lcore].usser_num = 0;

	u64 local_cycle = 0;
	u64 tmp_mid_cycle = 0;
	struct net 	*pnet = US_PER_LCORE(init_net); 

	struct us_netio_evb 	evb ;
	struct us_netio_events re_ev;
	
	memset(&evb,0,sizeof(struct us_netio_evb));
	memset(&re_ev,0,sizeof(struct us_netio_events));

	struct us_netio_evb	*evb_p = &evb;
	struct us_netio_events	*reload_ev = &re_ev;
	pnet->evb_p	= &evb;
	
#if 1
	while(1) {
		ret = idle_loop(&local_cycle,lcore,io_ring_no ,ring_ent_local , 1024 * 1024);		

		if(ret ){
			time_base = rte_rdtsc() ; //rte_rdtsc(); //cycles;
			pkt_loop(io_rp,io_ring_no, ret,pnet);   //ring_ent
			ring_ent_local += ret;

			tmp_mid_cycle = rte_rdtsc() ;//rte_rdtsc();
			glb_thcpu[lcore].ustack += tmp_mid_cycle - time_base;  //cycles;

			time_base = tmp_mid_cycle;  //cycles
			event_loop(evb_p,reload_ev);
			
			glb_thcpu[lcore].uapp += rte_rdtsc() - time_base ;//rte_rdtsc() - time_base;
			//time_base = cycles;
		}else{
			time_base = rte_rdtsc();// rte_rdtsc();	
			timer_loop(100);

			tmp_mid_cycle = rte_rdtsc() ;// rte_rdtsc();
			glb_thcpu[lcore].utimer +=	tmp_mid_cycle - time_base;

			time_base = tmp_mid_cycle;
			event_loop(evb_p,reload_ev);
			
			tmp_mid_cycle = rte_rdtsc() ;//rte_rdtsc();
			glb_thcpu[lcore].uapp += tmp_mid_cycle - time_base;	

			time_base = tmp_mid_cycle;
			pkt_loop(io_rp,io_ring_no, 1,pnet); 
			ring_ent_local += 1;
			glb_thcpu[lcore].ustack += rte_rdtsc() - time_base ;// rte_rdtsc() - time_base;

			//time_base = cycles;
		}
	}
#else
	while(1) {
		//receiver_run(1,0,0);
		ring_ent = ring_ent_all[io_ring_no ] - ring_ent_local;
		ring_ent = ring_ent < (US_MAX_PKT_BURST>>1)? ring_ent: ((US_MAX_PKT_BURST>>1)-1);

		if(unlikely(glb_thcpu[lcore].new_tt != glb_thcpu[lcore].old_tt)){
			glb_thcpu[lcore].old_tt = glb_thcpu[lcore].new_tt;
			glb_thcpu[lcore].ustack = 0;
			glb_thcpu[lcore].utimer = 0;
			glb_thcpu[lcore].uapp 	= 0;
			glb_thcpu[lcore].uidle 	= 0;
		}

		time_base_all = cycles;
		
		time_base = cycles;
		ret = pkt_loop(io_rp,io_ring_no,ring_ent);
		ring_ent_local += ring_ent;
		glb_thcpu[lcore].ustack += cycles - time_base;

		time_base = cycles;
		ret = event_loop(evb_p,reload_ev); //evb_p,reload_ev
		glb_thcpu[lcore].uapp += cycles - time_base;

		time_base = cycles;	
		timer_loop(100);
		glb_thcpu[lcore].utimer +=  cycles - time_base;

		glb_thcpu[lcore].uidle += cycles - time_base_all;
		
	}
#endif
	//ProfilerStop() ;				//gprof-tool work not so well under multi-thread;
}

#ifdef INTEL_HT
int main_loop(void * arg)
{
	u32 l_core = US_GET_LCORE();
	
	switch(glb_thread[l_core].th_type){
	case US_THREAD_USTACK:
			ustack_run();
		break;
		
	case US_THREAD_RECEIVER:
			recv_run();
		break;
		
	case US_THREAD_MON:
			mon_run();
		break;
		
	default:
			idle_run();
		break;
	}

	return 0;
}
#else
/*
int main_loop(void * arg)
{
	u32 l_core = US_GET_LCORE();

	
	switch(l_core){
	case 0:
	case 2:	
	case 4:
			recv_run(0);
		break;
		
	case 6:
			mon_run();
		break;

	case 1:
	case 3:
	case 5:
			//ProfilerStart("part.prof") ;
			ustack_run(-1);
			//ProfilerStop() ;
		break;
		
	default:
			idle_run();
		break;
	}

	return 0;
}*/
#endif


static s32 us_env_run(int argc, char **argv)
{
	u32 l_core;
	pthread_barrier_init(&glb_barrier,NULL, glb_thread_num ); 
	
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
	
	RTE_LCORE_FOREACH_SLAVE(l_core){
		if (rte_eal_wait_lcore(l_core) < 0)
			return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	if((ret = us_env_init(argc,argv))<0){
		US_ERR("us environment init failed!\n");
		return -1;
	}else{
		argc -= ret;
		argv += ret;
	}

	us_env_run(argc,argv);

	return 0; //never be there;
}
