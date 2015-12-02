/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_client.c
* @brief			a little test here;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/

#include "us_entry.h"

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>


char wget_name[8] = "wget_xxx";

static const char http_request[] =	"GET /index.html HTTP/1.0 \r\n"
									"Host: 192.168.42.8.65532 \r\n"
									"User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.6) \r\n"
									"Gecko/20050225 Firefox/1.0.1 \r\n\r\n";


typedef struct __us_client{
	struct socket 			*skt;
	struct us_timer_list  	timer;
	struct sockaddr_in 		dest;
	struct msghdr			*msg;
	int						fd;
	char				buf[4096];
}us_client;


extern int us_client_init(u32 delay);

void us_client_destroy(unsigned long data)
{
	us_client *uc = (us_client *)data;
	if(uc->fd > 0)
		close(uc->fd);
	free(uc);
}

int us_http_response_parse(us_client *uc,char**beg,int *len)
{
	int ret ;
	struct msghdr *msg = uc->msg;
	*beg = (char*)msg->msg_iov[0].iov_base;
	ret = msg->msg_iov[0].iov_len;
	*len = ret;

	return ret;
}

void us_client_recv_timeout(unsigned long data)
{
	struct socket *skt = (struct socket *)data;
	us_close(skt);
	US_ERR("TH:%u us_client recv timeout!\n",US_GET_LCORE());
}

int us_client_loop(struct socket *skt,void *b , int c)
{	
	int ret = 0;
	us_client *uc = (us_client*)skt->obj;
	//struct msghdr *msg = uc->msg;
	//char *beg = (char*)msg->msg_iov[0].iov_base;
	//int  beg_len = msg->msg_iov[0].iov_len;
	char 	*beg 		= b;	
	int 	 beg_len 	= c;
	if(c < 0){
		US_ERR("TH:%u,recv err found!\n",US_GET_LCORE());
		goto err_out;
	}

	ret = write(uc->fd,beg,beg_len);
	if(ret < beg_len){
		US_ERR("TH:%u,write back wgetfile on client_loop failed!\n",US_GET_LCORE());	
		goto err_out;
	}

	if(us_read_eof(skt)){
		us_close(skt);
		us_client_init(1);
		US_LOG("TH:%u,connect skt closed!\n",US_GET_LCORE());
		return US_RET_OK;
	}else{
		us_recv_set(skt, uc->buf,sizeof(uc->buf) , CALLBACK_RECV_RELOAD, NULL,NULL);  //reload the timer;
		return ret;
	}
	
err_out:
	us_close(skt);
	return -1;
}

int us_client_work(struct socket *skt,void *b , int c)
{	
	int ret = 0;
	int len = 0;
	char *beg = NULL;
	char wget_name_local[sizeof(wget_name)];
	
	us_client *uc = (us_client*)skt->obj;	
	ret = us_http_response_parse(uc,&beg,&len);
	if(ret < 0 ){
		US_ERR("TH:%u us http response error!\n",US_GET_LCORE());
		goto err_out;
	}else if(ret == 0){
		US_ERR("TH:%u us http response truncked!\n",US_GET_LCORE());
		goto err_out;
	}else{
		u32 lcore = US_GET_LCORE();
		memcpy(wget_name_local,wget_name,sizeof(wget_name));
		wget_name_local[sizeof(wget_name) - 2] = (lcore/10)+48;
		wget_name_local[sizeof(wget_name) - 3] = (lcore/10)+48;
		wget_name_local[sizeof(wget_name) - 1] = '\0';
		
		uc->fd = open(wget_name_local,O_WRONLY|O_CREAT|O_APPEND);
		if(uc->fd < 0){
			US_ERR("TH:%u,%s\n",lcore, "create wget file failed here!\n");
			goto err_out;
		}

		if(beg && len >0){
			ret = write(uc->fd,beg,len);
			if(ret < len){
				US_ERR("TH:%u,%s\n",lcore,"write back wget file failed here!\n");
				goto err_out;
			}
		}				
	}

	ret = us_recv_set(skt, uc->buf,sizeof(uc->buf) , 0,us_client_loop,us_client_recv_timeout);
	if(ret < 0){
		US_ERR("TH:%u,us_recv reload failed!\n",US_GET_LCORE());
		goto err_out;
	}

	us_callback_c_unload(skt);
	return US_RET_OK;
err_out:
	us_close(skt);
	return ret;
}

int us_client_get(struct socket *skt,void *b , int c)
{
	int ret = 0;
	us_client *uc = (us_client*)skt->obj ;
	ret = us_send(skt, (void*)http_request, sizeof(http_request), MSG_DONTWAIT);
	if(ret < 0){
		US_ERR("TH:%u,http_get send faild! err:%d\n",US_GET_LCORE(),ret);
		goto err_out;
	}

	ret = US_ENOMEM;

	ret = us_recv_set(skt,uc->buf, sizeof(uc->buf), 0, us_client_work,us_client_recv_timeout);
	if(ret < 0){
		US_ERR("TH:%u,us_recv failed! ret:%d\n",US_GET_LCORE(),ret);
		goto err_out;
	}	

	return US_RET_OK;
err_out:
	us_close(skt);
	return ret;
}

void us_client_conn_timeout(unsigned long data)
{
	struct socket *skt = (struct socket *)data;
	us_close(skt);
	US_ERR("TH:%u us_client connect timeout!\n",US_GET_LCORE());
}

void us_client_start(unsigned long data)
{
	int ret ;
	us_client *uc = (us_client*)data;	
	
	ret = us_connect(uc->skt,(struct sockaddr*)&uc->dest,sizeof(struct sockaddr),0
						,us_client_get,us_client_conn_timeout);
	if(ret < 0){
		US_ERR("TH:%u, us_client start failed! err:%d\n",US_GET_LCORE(),ret);
		goto over;
	}

	return ;
	
over:
	us_close(uc->skt);
	return ;
}

int us_client_init(u32 delay)
{	
	int ret = 0;
	int ip = 0;
	struct socket* client = NULL;
	//struct msghdr* msg = NULL;
	ret = inet_pton(AF_INET, "192.168.30.77", &ip);
	if(ret < 0){
		US_ERR("TH:%u,us_client_init init client dest ip failed!\n",US_GET_LCORE());
		return ret;
	}
	
	us_client *uc = (us_client*) malloc(sizeof(us_client));
	if(uc == NULL){
		US_ERR("TH:%u us_client malloc failed!\n",US_GET_LCORE());
		return US_ENOMEM;
	}

	memset(uc,0,sizeof(us_client) - sizeof(uc->buf));

	/*
	msg = msghdr_format(uc->buf, sizeof(uc->buf));
	uc->msg = msg;
	if(msg == NULL){
		US_ERR("TH:%u us_client msg init failed!\n",US_GET_LCORE());
		return US_ENOMEM;
	}*/
	
	uc->dest.sin_family 	= AF_INET;
	uc->dest.sin_port		= htons(80);
	uc->dest.sin_addr.s_addr = ip;

	client = us_socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	if(client == NULL){
		US_ERR("TH:%u client socket create failed!\n",US_GET_LCORE());
		return -1;
	}

	uc->skt = client;
	us_socket_obj_set(client, uc, us_client_destroy);

	us_setup_timer(&uc->timer,us_client_start ,uc,TIMER_TYPE_USER3);	
	__us_mod_timer(&uc->timer, jiffies + delay*1000);
	
	return US_RET_OK;
	
}


