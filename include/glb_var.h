/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			glb_var.h
* @brief			some global vars here;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/


#ifndef _US_GLB_VAR_H
#define _US_GLB_VAR_H

#include "types.h"
#include "time.h"
#include "us_mem.h"
#include "net.h"
#include "defines.h"

typedef struct __us_th_info{
	u8		th_type	:3;
	u8		th_flag :5;
	u8		state;
	s8		probe;
	u8		io_ring;
	u8		queue_recv_id;
	u8		queue_send_id;
	u8		port_id;
	u8		r2;
	u64		cyc_old;
	u64     cyc_new;
}us_th_info;

typedef struct __us_cpu_idle{
	u64		old_tt;		//WORKER write;
	u64		new_tt;		//MON write;
	u64		ustack;
	u64 	uapp;		
	u64		utimer;
	u64		uidle;
	u64 	usser_num;
	u64		usser_num_old;
	u64		usser_num_max;
}us_cpu_idle;

typedef struct __us_nic_port
{
	u8	port_id;
	u8	flags;
	u8  state;
	u8  socket_id;
	u8  if_mac[6];			
	u8  gw_mac[6];	// None lock here; Error here,but is not our job at now;Fix it later;
	u32 gw_ipv4_addr;
	u32 if_ipv4_mask;
	u16	if_ipv4_vip_num;
	u16	if_ipv4_bip_num;
	u32 if_ipv4_vip[APP_IF_VIP_MAX_NUM];
	u32 if_ipv4_bip[APP_IF_BIP_MAX_NUM];
}us_nic_port;


extern	volatile u64		jiffies;  //ms
extern  volatile u64		cycles;	  //hpte;
extern  u64					start_jiffies;

//extern 	struct us_timespec 	Ts;
extern 	struct 	 timespec	Ts;

US_DECLARE_PER_LCORE(struct net*,init_net);


//extern  us_session_stat glb_session_info[US_LCORE_MAX];

extern  char debug_name[];

extern s32  glb_server_fd ;
extern u32	glb_dest_ip ;
extern u32	glb_client_ip ;
extern u32  glb_dump_off ;
extern u32  glb_debug_trace ;

extern us_nic_port	us_nic_ports[APP_MAX_NIC_PORTS] ;
extern us_cpu_idle  glb_thcpu[US_LCORE_MAX] ;
extern us_th_info	glb_thread[US_LCORE_MAX];
extern us_mempool	*mbuf_rp[APP_MAX_IO_LCORES] ;
extern us_th_info	glb_thread[US_LCORE_MAX];

extern volatile s32 glb_us_init_token 	;
extern volatile u64 glb_us_init_through ;


#define US_SERVER_TEST_FILE	"index.html"
#endif
