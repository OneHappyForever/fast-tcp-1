/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			glb_var.h
* @brief			some global defination here;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/


#ifndef _US_DEFINES_H
#define _US_DEFINES_H


#ifndef CONFIG_NET_NS
#define CONFIG_NET_NS
#endif

#define __LITTLE_ENDIAN_BITFIELD
#define __user	
#define __force

#define BITS_PER_LONG			64
#define SMP_CACHE_BYTES			64		//smallboy: Fix it later ;sandybrige;

#ifdef __BIG_ENDIAN
#undef __BIG_ENDIAN				///* __LITTLE_ENDIAN */  smallboy:maybe info from kernel;Fix it later;
#endif

#define US_MBUF_FREE_BY_OTHER	(0)
#define US_MBUF_FREE_BY_STACK	(1)

#define US_SK_BUFF_LINESIZE_MAX	(1628)	//1460-20-20+MAX_TCP_HEADER 
#define US_MBUF_LENGTH_MAX		(2048)  //less than 2048 but enough;

#define US_MIN_IPV4_TCP_HEADER	(128) // 20+60+16; //smallboy;
#define US_SKB_OFFSET			(32)  // 256 = 224 + 32; 224 =sizeof(sk_buff);

#define US_SKB_CLONE			(1)
#define US_SKB_NOT_CLONE		(0)

#define US_DECLARE_PER_LCORE	RTE_DECLARE_PER_LCORE
#define US_DEFINE_PER_LCORE		RTE_DEFINE_PER_LCORE
#define US_PER_LCORE			RTE_PER_LCORE 

#define US_GET_LCORE			rte_lcore_id
#define US_GET_SOCKET(a)		rte_lcore_to_socket_id(a)

#define US_MEMZONE_RESERVE		rte_memzone_reserve	
#define US_MEMPOOL_CREATE		rte_mempool_create
//#define US_ERRNO				rte_errno

#define US_BUF_SLAB_SIZE		(4) 		// 2^x!!
#define US_BUF_SIZE_BASE		(4096)		// 2^12 == 4096
#define US_BUF_SIZE_BASE_POW	(12)		

#define US_MSGHDR_IOVLEN_MAX	(16)
#define US_MSGHDR_IOVSIZE_MAX	(US_BUF_SIZE_BASE*US_BUF_SLAB_SIZE)

#define US_MSGHDR_FREE_ALL		(0x1 << 0)
#define US_MSGHDR_FREE_DATA		(0x0 << 0)

#define US_MSGHDR_MAGIC			(0x531278UL)
#define US_SOCKET_MAGIC			(0x3278153UL)

#define us_malloc				rte_malloc
#define us_free					rte_free
#define us_zmalloc				rte_zmalloc

#define us_jhash_3words			rte_jhash_3words
#define us_jhash_2words  		rte_jhash_2words

#define US_MON_QUANTUM				(10)  //ms;
#define US_MON_DEBUG_MEN_QUANTUM	(10000) //ms;

#ifndef INTEL_HT
#define INTEL_HT
#endif

#ifdef INTEL_HT
#define US_LCORE_MAX			(24)
#define GLB_US_LCORE_RB 		(24)	//coremask range;
#define GLB_US_LCORE_LB 		(12)

#else
#define US_LCORE_MAX			(12)
#define GLB_US_LCORE_RB 		(12)	//coremask range;
#define GLB_US_LCORE_LB 		(1)
#endif

#define US_MAX_PKT_BURST_OUT	(32)	
#define US_MAX_PKT_BURST		(256)
#define US_MAX_EVENT_BURST		(US_MAX_PKT_BURST*2)

#define US_INET_LHTABLE_SIZE	(1024)
#define US_INET_BHASH_SIZE   	(64*1024)
#define US_INET_EHTABLE_SIZE	(256*1024)
#define US_INET_MHTABLE_SIZE	(US_INET_BHASH_SIZE)	

#define US_SOCK_NB_LCORE		(128*1024)
#define US_SOCKET_NB_LCORE		(US_SOCK_NB_LCORE)
#define US_SK_TW_NB_LCORE		(1024*1024)  	//(512*1024)

#define US_SK_BUFF_NB_LCORE		(65537)  		//(128*1024*64) 
#define US_MBUF_R_NB_LCORE		(512*1024)  	//(8192*512)

#define US_TCP_METRIC_LCORE		(128*1024)
#define US_SK_REQ_NB_LCORE		(256*1024)

#define US_IBBUCKET_NB_LCORE	(65536)
#define US_MBUF_S_NB_LCORE		(65536*4)
#define US_IO_RING_NB_LCORE		(8192*16)


#define MD5_DIGEST_WORDS 		4
#define MD5_MESSAGE_BYTES 		64

#define US_ETHER_TYPE_IPv4		(0x008)   //
#define US_ETHER_TYPE_ARP		(0x608)   //

#define APP_MAX_NIC_PORTS					2
#define APP_MAX_IO_LCORES 					24    
#define APP_MAX_RX_QUEUES_PER_NIC_PORT		(APP_MAX_IO_LCORES)
#define APP_MAX_TX_QUEUES_PER_NIC_PORT 		(APP_MAX_IO_LCORES)
#define APP_MAX_APP_LCORES					(APP_MAX_IO_LCORES)

#define APP_IF_VIP_MAX_NUM					(256)
#define APP_IF_BIP_MAX_NUM					(256)		// >= US_LCORE_MAX

#define US_MEMPOOL_TYPE						(9)   //Be in accord with the mempool above;


#define US_ERR(msg...)\
	do{\
		fprintf(stderr,"US_ERR:"msg);\
	}while(0)

#define US_LOG(msg...)\
	do{\
		fprintf(stdout,"US_LOG:"msg);\
		fflush(stdout);\
	}while(0)	

#define US_DEBUG(msg...)\
	do{\
		fprintf(stderr,"US_DEBUG:"msg);;\
	}while(0)	
//fprintf(stderr,"US_DEBUG:"msg);
#define US_DEBUG_LINE()\
	do{\
		fprintf(stderr,"US_DEBUG:TH:%u FUNC:%s,line:%d\n",US_GET_LCORE(),__FUNCTION__,__LINE__);\
	}while(0)	

//syslog(6,"BGW:ERROR:"msg);

enum {
  IPPROTO_IP = 0,		// Dummy protocol for TCP		
  IPPROTO_ICMP = 1, 	// Internet Control Message Protocol	
  IPPROTO_IGMP = 2, 	// Internet Group Management Protocol	
  IPPROTO_IPIP = 4, 	// IPIP tunnels (older KA9Q tunnels use 94) 
  IPPROTO_TCP = 6,		// Transmission Control Protocol	
  IPPROTO_EGP = 8,		// Exterior Gateway Protocol		
  IPPROTO_PUP = 12, 	// PUP protocol 			
  IPPROTO_UDP = 17, 	// User Datagram Protocol		
  IPPROTO_IDP = 22, 	// XNS IDP protocol 		
  IPPROTO_DCCP = 33,		// Datagram Congestion Control Protocol 
  IPPROTO_RSVP = 46,		// RSVP protocol			
  IPPROTO_GRE = 47, 		// Cisco GRE tunnels (rfc 1701,1702)	

  IPPROTO_IPV6	 = 41,		// IPv6-in-IPv4 tunnelling		

  IPPROTO_ESP = 50, 		// Encapsulation Security Payload protocol 
  IPPROTO_AH = 51,			// Authentication Header protocol		
  IPPROTO_BEETPH = 94,		// IP option pseudo header for BEET 
  IPPROTO_PIM	 = 103, 	// Protocol Independent Multicast	

  IPPROTO_COMP	 = 108, 	// Compression Header protocol 
  IPPROTO_SCTP	 = 132, 	// Stream Control Transport Protocol	
  IPPROTO_UDPLITE = 136,	// UDP-Lite (RFC 3828)			

  IPPROTO_RAW	 = 255, 	// Raw IP packets			
  IPPROTO_MAX
};

//// the same with:usr/include/bits/siginfo.h:243

#define __US_SI_POLL	(0)				// smallboy: Fix it later ; #define __SI_POLL	(2 << 16) in kernel;

/*
 * SIGPOLL si_codes
 */							
#define US_POLL_IN	(__US_SI_POLL|1)	/* data input available */
#define US_POLL_OUT	(__US_SI_POLL|2)	/* output buffers available */
#define US_POLL_MSG	(__US_SI_POLL|3)	/* input message available */
#define US_POLL_ERR	(__US_SI_POLL|4)	/* i/o error */
#define US_POLL_PRI	(__US_SI_POLL|5)	/* high priority input available */
#define US_POLL_HUP	(__US_SI_POLL|6)	/* device disconnected */
#define US_NSIGPOLL	6


#endif
