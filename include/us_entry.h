/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_entry.h
* @brief			;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/

#ifndef _US_ENTRY_H
#define _US_ENTRY_H

#include "types.h"
#include "defines.h"
#include "bitops.h"
#include "list.h"
#include "ip.h"
#include "tcp.h"
#include "icmp.h"
#include "socket.h"
#include "skbuff.h"
#include "arp.h"
#include "net.h"
#include "us_rte.h"
#include "us_error.h"
#include "us_mem.h"
#include "us_time.h"
#include "us_timer.h"
#include "us_util.h"

struct sk_buff;
struct net;
struct tcp_info;
struct msghdr;
struct us_objslab_head;

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */ 


typedef struct pcap_pkthdr {
        //struct timeval ts;        /* time stamp */  //8 bytes on tilera
        u32 tv_sec; 
  		u32 tv_usec;
        u32 caplen;     /* length of portion present */
        u32 len;         /* length this packet (off wire) */
}pcap_pkthdr_t;


#define US_TH_FLAG_DUMP_BIT		(5)
#define US_TH_FLAG_DUMP			(0x1UL<<US_TH_FLAG_DUMP_BIT)
#define US_TH_FLAG_DUMP_TEST(a)	((a)&US_TH_FLAG_DUMP)		

extern void mon_run(void);	
extern s32 	us_app_stub_init(void);
extern int 	timer_loop(int budget);
extern int 	icmp_v4_recv(struct sk_buff *skb);
extern void recv_pkt_dump(struct rte_mbuf **mbuf_array , u32 num_nb);

#endif
