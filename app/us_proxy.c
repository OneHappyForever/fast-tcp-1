/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_proxy.c
* @brief			a little test here;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/

#include "us_entry.h"

#include <stdlib.h>

int us_proxy_client_request_handle(struct socket *skt,void *arg, int b);
int us_proxy_client_recv_handle(struct socket *skt,void *arg, int b);
int us_proxy_connect_handle(struct socket *skt,void *arg, int b);
int us_proxy_recv_handle(struct socket *skt,void *arg, int b);

#define     proxy_init		(0)	
#define		client_req		(1)
#define 	client_recv		(2)
#define 	proxy_connecting (3)
#define 	proxy_connected	(4)
#define 	proxy_recv		(5)
#define		proxy_fin		(6)

#define     proxy_timer_pending	(1<<0)
#define     proxy_fin_pending	(1<<1)
#define     client_fin_pending	(1<<2)

typedef struct __us_proxyer{
	struct socket 			*req;
	struct socket 			*res;
	struct us_timer_list	timer;			//smallboy: If there is a wirte func, init a timer also;
	struct msghdr			*m_get;
	struct msghdr			*m_http;
	struct sockaddr_in		rs;
	struct us_timer_list	debug_t;
	u16						state;
	u16						flags;
	u16						ref;
	u16						__padding;
}us_proxyer;


void us_proxy_sock_debug(unsigned long data)
{
	//int ret = 0;
	//struct tcp_info	th_info;
	//int opt_len = sizeof(th_info);
	us_proxyer *us_p = (us_proxyer *)data;

	/*	
	if(us_p->res){
		ret = us_getsockopt(us_p->req,SOL_TCP,TCP_INFO,(char*)&th_info,&opt_len);
		if(ret < 0){
			US_ERR("TH:%u US_PROXY req socket get_sockopt failed for TCP_INFO!ret:%d\n"
				,US_GET_LCORE(),ret);
		}else{
			US_LOG("***************REQ_SK:%u %p*********************\n"
					,us_p->req->sk->sk_id,us_p->req->sk);
			us_debug_th_info(&th_info);
			US_LOG("******************TH:%u*********************\n",US_GET_LCORE());
		}
	}

	if(us_p->req){
		ret = us_getsockopt(us_p->res,SOL_TCP,TCP_INFO,(char*)&th_info,&opt_len);
		if(ret < 0){
			US_ERR("TH:%u US_PROXY res socket get_sockopt failed for TCP_INFO!ret:%d\n"
				,US_GET_LCORE(),ret);
		}else{
			US_DEBUG("***************RES_SK:%u %p*********************\n"
					,us_p->res->sk->sk_id,us_p->res->sk);
			us_debug_th_info(&th_info);
			US_DEBUG("******************TH:%u*********************\n",US_GET_LCORE());
		}
	}*/
	
	__us_mod_timer(&us_p->debug_t,jiffies+2000);
}

int us_http_get_parse(struct msghdr *msg,char**beg,int *len)
{
	
	return 0;
}

void us_proxy_destroy(unsigned long data)   //called by client side us_close 
{
	US_DEBUG("FUNC:%s,%u \n",__FUNCTION__,__LINE__);
	us_proxyer *us_p = (us_proxyer *)data;	//smallboy: It's whom that make it responsiblity of clean it;
	if(us_p->m_get){
		US_DEBUG("FUNC:%s,%u \n",__FUNCTION__,__LINE__);
		msghdr_free(us_p->m_get,US_MSGHDR_FREE_ALL);
		us_p->m_get = NULL;
	}

	if(us_p->ref == 1){	
		if(us_p->m_http){
			US_DEBUG("FUNC:%s,%u \n",__FUNCTION__,__LINE__);
			msghdr_free(us_p->m_http,US_MSGHDR_FREE_ALL);
			us_p->m_http = NULL;
		}

		if(us_p->res){
			US_DEBUG("FUNC:%s,%u \n",__FUNCTION__,__LINE__);
			us_close(us_p->res);
			us_p->res = NULL;
		}
	}

	us_p->ref--;

	US_DEBUG("FUNC:%s,%u \n",__FUNCTION__,__LINE__);
	us_del_timer(&us_p->timer);
	us_del_timer(&us_p->debug_t);

	if(us_p->ref == 0)
		free(us_p);
}

void us_proxy_setted(us_proxyer *us_p,struct socket *skt,int flags)
{
	if(flags){
		us_p->ref += us_p->req ? 0:1;
		us_p->req = skt;
	}else{
		us_p->ref += us_p->res ? 0:1;
		us_p->res = skt;
	}
}

void us_proxy_disconnect(unsigned long data) //called by server side us_close;
{
	US_DEBUG("FUNC:%s,%u \n",__FUNCTION__,__LINE__);
	us_proxyer *us_p = (us_proxyer *)data;
	if(us_p->m_http){
		US_DEBUG("FUNC:%s,%u \n",__FUNCTION__,__LINE__);
		msghdr_free(us_p->m_http,US_MSGHDR_FREE_ALL);
		us_p->m_http = NULL;
	}

	if(us_p->ref == 1){
		if(us_p->m_get){
			US_DEBUG("FUNC:%s,%u \n",__FUNCTION__,__LINE__);
			msghdr_free(us_p->m_get,US_MSGHDR_FREE_ALL);
			us_p->m_get = NULL;
		}

		US_DEBUG("FUNC:%s,%u \n",__FUNCTION__,__LINE__);
		us_del_timer(&us_p->timer);
	}

	us_p->ref--;
	
	if(us_p->ref == 0){
		US_DEBUG("FUNC:%s,%u \n",__FUNCTION__,__LINE__);
		free(us_p);		
	}
}

void us_proxy_send_delay(unsigned long data)
{
	//US_DEBUG("TH:%u,func:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);
	int ret = US_RET_OK;
	us_proxyer *us_p = (us_proxyer *)data;
	struct msghdr *msg = us_p->m_http;
	struct socket *skt = us_p->res;

	if(msg->msg_iovlen > 0){
		//US_DEBUG("msg->iovlen:%u  \n",(u32)(msg->msg_iovlen));	
		ret = us_seg_moveto(msg, skt, us_p->req, 0);
		if(ret < 0 ){
			US_ERR("TH:%u, proxy send response failed!ret:%d\n",US_GET_LCORE(),ret);
			goto err_out;
		}else {
			if(msg->msg_controllen <= msg->msg_iovlen){  //Full, detach the callback;
				us_callback_r_unload(skt);		
			}

			if(msg->msg_iovlen == 0){
				if(us_p->flags & proxy_timer_pending){
					us_p->flags &= ~proxy_timer_pending;
					us_del_timer(&us_p->timer);	
				}

				us_callback_r_reload(skt);	
			}else{
				// Append the retry timer;
				__us_mod_timer(&us_p->timer,jiffies+1);
				us_p->flags |= proxy_timer_pending;
				return ;
			}
		}
	}

	if(us_p->state == proxy_fin){
		US_ERR("TH:%u func:%s,%u ,proxy send over!\n",US_GET_LCORE(),__FUNCTION__,__LINE__);
		goto close_out;
	}

	return ;
close_out:
	us_close(us_p->res);	
	us_close(us_p->req);
	return ;
err_out:
	us_close(us_p->res);	
	us_close(us_p->req);	
	return ;
}

int us_proxy_recv_handle(struct socket *skt,void *arg, int b)
{
	//US_DEBUG("TH:%u,func:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);
	int ret = US_EINVAL;
	us_proxyer  *us_p = skt->obj;

	if(b < 0 && (b!= US_EAGAIN)){
		US_ERR("TH:%u,proxy recv err found! ret:%d\n",US_GET_LCORE(),b);
		goto err_out;
	}

	us_p->state =  proxy_recv;

	if(us_read_eof(skt)){
		US_DEBUG("TH:%u,func:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);
		us_p->state = proxy_fin;
	}

	//US_DEBUG("TH:%u,func:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);
	us_proxy_send_delay((unsigned long)us_p);

	return US_RET_OK;
err_out:
	us_close(us_p->res);
	us_close(us_p->req);
	return ret;
}

int us_proxy_client_request_handle(struct socket *skt, void *arg,  int b)
{
	//US_DEBUG("TH:%u,func:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);
	int ret = US_RET_OK;
	us_proxyer  *us_p = (us_proxyer *)malloc(sizeof(us_proxyer));	
	if(us_p == NULL){
		US_ERR("TH:%u %s\n",US_GET_LCORE(),"us_proxyer malloc failed!");
		goto err_out;
	}

	memset(us_p,0,sizeof(us_proxyer));
	us_p->m_get = msghdr_malloc(1, 0);  //smallboy: iov_size == 0 ; zero copy model;

	if(us_p->m_get == NULL){
		US_ERR("TH:%u %s\n",US_GET_LCORE(),"us_proxyer malloc client_msghdr failed!");
		goto early_out;
	}

	us_proxy_setted(us_p,skt,1);
	us_socket_obj_set(skt,us_p,us_proxy_destroy);
	
	us_p->state =  client_req;

	ret = us_recvv_set(skt,us_p->m_get,CALLBACK_RECV_NOCOPY,us_proxy_client_recv_handle,NULL);		
	if(ret < 0 ){
		US_ERR("TH:%u %s\n",US_GET_LCORE(),"us_proxyer reload client_recv failed!\n");
		goto err_out;
	}

	us_p->state =  client_recv;	

	return ret;	
early_out:
	msghdr_free(us_p->m_get,US_MSGHDR_FREE_ALL);
	return US_ENOMEM;
err_out:
	us_close(skt);
	return ret;
}

struct socket *us_proxy_get_rs(us_proxyer *us_p)
{
	int rs_ip;
	int ret ;
	struct socket * skt = us_socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	if(skt == NULL){
		return NULL;
	}

	ret = inet_pton(AF_INET, "192.168.53.2", &rs_ip);
	//ret = inet_pton(AF_INET, "192.168.30.76", &rs_ip);
	//ret = inet_pton(AF_INET, "192.168.42.8", &rs_ip);
	//ret = inet_pton(AF_INET, "199.168.54.2", &rs_ip);
	if(ret < 0){
		us_close(skt);
		return NULL;
	}
	
	us_p->rs.sin_family = AF_INET;
	us_p->rs.sin_addr.s_addr = rs_ip;
	us_p->rs.sin_port = htons(65532);

	return skt;
}

int us_proxy_connect_handle(struct socket *skt,void *arg, int b)
{
	//US_DEBUG("TH:%u,func:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);
	int ret = 0;
	us_proxyer *us = (us_proxyer*)skt->obj;

	ret = us_seg_moveto(us->m_get,us->req,us->res,0);	
	if(ret < 0){
		US_ERR("TH:%u, proxy get failed!\n",US_GET_LCORE());
		goto err_out;
	}

	//US_LOG("TH:%u  req_socket:%u,%u rs_socket:%u,%u \n"
	//		,US_GET_LCORE(),us->req->socket_id,us->req->sk->sk_id
	//		,us->res->socket_id,us->res->sk->sk_id);

	if(us->m_get->msg_iovlen > 0){		// send once for simple;
		US_ERR("TH:%u, proxy get not completed!\n",US_GET_LCORE());
		goto err_out;
	}
	
	us->m_http = msghdr_malloc(16, 0);	//smallboy: iov_size == 0 ; zero copy model;	
	if(us->m_http== NULL){
		US_ERR("TH:%u %s\n",US_GET_LCORE(),"us_proxyer malloc server_msghdr failed!");
		goto err_out;
	}

	ret = us_setup_timer(&us->timer, us_proxy_send_delay, us, TIMER_TYPE_USER4);
	if(ret < 0){
		US_ERR("TH:%u, proxyer timer setup failed!\n",US_GET_LCORE());
		goto err_out;
	}

	us_setup_timer(&us->debug_t, us_proxy_sock_debug, us,TIMER_TYPE_USER4);
	__us_mod_timer(&us->debug_t,jiffies+2000);

	ret = us_recvv_set(skt, us->m_http, CALLBACK_RECV_NOCOPY,  us_proxy_recv_handle,NULL);
	if(ret < 0){
		US_ERR("TH:%u , proxy recv reload failed!ret:%d\n",US_GET_LCORE(),ret);
		goto err_out;
	}

	us->state =  proxy_connected;
	
	return US_RET_OK;

err_out:
	us_close(skt);
	us_close(us->req);
	return -1;
}

int us_proxy_client_recv_handle(struct socket *skt,void *arg, int b)
{
	//US_DEBUG("TH:%u,func:%s,%u\n",US_GET_LCORE(),__FUNCTION__,__LINE__);
	int eof = 0;
	char *beg;
	int  len;
	int  ret = US_EINVAL;
	int	 opt = 0;
	int  optlen = sizeof(opt);
	struct socket *res = NULL;
	us_proxyer *us = (us_proxyer*)skt->obj ;	

	if(b < 0){
		US_ERR("TH:%u,proxy client recv err found! ret:%d\n",US_GET_LCORE(),b);
		goto err_out;
	}

	if(us_read_eof(skt)){
		eof = 1;	
	}
	
	if(us->state < proxy_connecting){
		if(us_http_get_parse(us->m_get,&beg,&len) == 0){
			res = us_proxy_get_rs(us);
			if(res == NULL){
				US_ERR("TH:%u,proxy server init failed!\n",US_GET_LCORE());
				goto err_out;
			}

			us_proxy_setted(us,res,0);
			us_socket_obj_set(res,us,us_proxy_disconnect);

			ret = us_getsockopt(skt, SOL_TCP, TCP_MAXSEG, (char*)&opt, &optlen);
			if(ret >= 0){
				//US_DEBUG("TH:%u advmss:%d \n",US_GET_LCORE(),opt);
				ret = us_setsockopt(us->res,SOL_TCP,TCP_MAXSEG, (char*)&opt, sizeof(opt));	
				if(ret < 0){
					US_ERR("TH:%u,proxy server side mss set failed!ret=%d\n" ,US_GET_LCORE(),ret);
				}
			}else{
				US_ERR("TH:%u,proxy server side mss get failed!ret=%d\n" ,US_GET_LCORE(),ret);
			}
			
			ret = us_connect(us->res,(struct sockaddr*)&us->rs,sizeof(struct sockaddr),0
								,us_proxy_connect_handle,NULL);
			if(ret < 0){
				US_ERR("TH:%u, proxy server start failed! err:%d\n",US_GET_LCORE(),ret);
				us_close(us->res);
				goto err_out;
			}

			us->state = proxy_connecting;			
		}else{
			US_ERR("TH:%u,incompleted http get!\n",US_GET_LCORE());
			goto err_out;
		}
	}else{
		if(eof ){
			us_close(skt);
			US_LOG("client close first here!\n");
		}
		US_LOG("TH:%u, read nothing here!\n",US_GET_LCORE());
	}

	return US_RET_OK;
err_out:
	us_close(skt);
	return ret;
}

int us_proxy_stub_init(void)
{
	s32 ret ,ip;
	struct socket *listener1;

	ret = inet_pton(AF_INET, "192.168.53.2", &ip);
	//ret = inet_pton(AF_INET, "192.168.42.8", &ip);
	if(ret < 0){
		US_ERR("us_app_stub init dest ip failed!\n");
		return ret;
	}

	glb_dest_ip = ip;
	
	ret = inet_pton(AF_INET, "192.168.30.76", &ip);
	if(ret < 0){
		US_ERR("us_app_stub init client ip failed!\n");
		return ret;
	}

	glb_client_ip = ip;

	struct sockaddr_in server;
	memset(&server,0,sizeof(struct sockaddr_in));

	server.sin_family	= AF_INET;
	server.sin_port 	= htons(80);
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	listener1 = us_socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	if(listener1 == NULL){
		US_ERR("TH:%u,proxy server1 socket create failed!\n",US_GET_LCORE());
		return US_RET_OK;
	}
	
	if(us_bind(listener1,(struct sockaddr *)&server,sizeof(struct sockaddr))<0){
		US_ERR("TH:%u,proxy server1 socket bind failed! errono:%d\n",US_GET_LCORE(),US_ERRNO);
		us_close(listener1);
		return US_RET_OK;
	}

	if(us_listen(listener1,5,us_proxy_client_request_handle)<0){
		US_ERR("TH:%u,proxy socket listen failed!\n",US_GET_LCORE());
		us_close(listener1);
		return US_RET_OK;		//smallboy: Fix it here ; replace it here with a  cmd pipe;
	}

	return US_RET_OK;
}


