/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			arp.h
* @brief			arp defines;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/


#ifndef _US_ARP_H
#define _US_ARP_H

/**
*@brief struct of arp msg format
*/
struct arphdr
{
        unsigned short  ar_hrd;         /**< format of hardware address   */
        unsigned short  ar_pro;         /**< format of protocol address   */
        unsigned char   ar_hln;         /**< length of hardware address   */
        unsigned char   ar_pln;         /**< length of protocol address   */

#define ARPOP_REQUEST   (0x0001)       /**< ARP request          */
#define ARPOP_REPLY 	(0x0002)       /**< ARP reply            */
        unsigned short  ar_op;          /* ARP opcode (command)         */
		
	unsigned char src_mac[6];		/**< mac address of sender */
	unsigned char src_ip[4];		/**< ip address of sender */
	unsigned char dest_mac[6];		/**< mac address of receiver */
	unsigned char dest_ip[4];		/**< ip address of receiver */

};


#endif
