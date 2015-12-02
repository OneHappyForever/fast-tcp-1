/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			icmp.h
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/


#ifndef _US_ICMP_H
#define _US_ICMP_H

#include "types.h"

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO			8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/* Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net			*/
#define ICMP_REDIR_HOST		1	/* Redirect Host		*/
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/



struct icmphdr {
  u8		type;
  u8		code;
  u16		checksum;
  union {
	struct {
		u16	id;
		u16	sequence;
	} echo;
	u32	gateway;
	struct {
		u16	__unused;
		u16	mtu;
	} frag;
  } un;
};

static inline void icmp_update_checksum_echo_to_reply(struct icmphdr *ic)
{
	ic->checksum = ic->checksum + htons(0x0800);
	return;
}

static inline int icmp_check_sum_correct(u16* start_of_icmp, int len)
{
	u32 sum=0;
	int i;
	int u16_num = len >> 1;
	int last_byte = len & 1;

	for(i=0; i<u16_num; i++)
		sum += start_of_icmp[i];
	if(last_byte)
		sum += *(u8*)(start_of_icmp+i);

	sum = (sum&0x0000ffff) + (sum>>16);
	//sum = (sum&0x0000ffff) + (sum>>16);
	//return (sum == 0x0000ffff);
    sum += (sum>>16);
    return ((u16)sum == 0xffff);
}

static inline u16 icmp_check_sum(u8 *data, u32 len)
{
    s32 sum=0;
    s32 odd = len & 0x01;

    while( len & 0xfffe)  {
        sum += *(u16*)data;
        data += 2;
        len -=2;
    }

    if( odd) {
        u16 tmp = ((*data)<<8)&0xff00;
        sum += tmp;
    }
    sum = (sum >>16) + (sum & 0xffff);
    sum += (sum >>16) ;
    return ~sum;
}



#endif
