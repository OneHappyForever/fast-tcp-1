/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_server.c
* @brief			a little test here;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/


#include "us_entry.h"

#include <unistd.h>

US_DEFINE_PER_LCORE(us_objslab *,us_server_slab);

struct socket *debug_sk_p = NULL;

u64 glb_us_server_num = 0;

static const char http_response[] =	"HTTP/1.1 200 OK\r\n"
								/*"Date: Mon, 27 Aug 2012 01:54:35 GMT\r\n"*/
								"Server: Apache/1.3.27 (Unix)\r\n"
								"Last-Modified: Tue, 15 Nov 2011 10:08:30 GMT\r\n"
								/*"ETag: \"10dc3fc-35-4ec23a1e\""*/
								"Accept-Ranges: bytes\r\n"
								//"Content-Length: \r\n"
								"Connection: close\r\n"
								"Content-Type: text/html\r\n\r\n";
								//"index.html from uinp05------------------------------\n";


typedef struct __us_server{
	struct socket 			*skt;
	struct us_timer_list  	timer;
	u64     				offset;
	char					data[1600];
}us_server;

int us_server_recv_handle (struct socket *skt, void *msg, int b);


void us_server_destroy(unsigned long data)
{
	us_server *user = (us_server*)data;
	us_del_timer(&user->timer);
	//free(user);
	us_memobj_slab_free(user);
}

inline void us_server_loop(unsigned long data)
{
#define snd_batch	(1400)	
//static u32 send_over = 0;

	//int len = 0;
	//char buf_tmp[8192];
	int ret = US_RET_OK;
	//char *beg = NULL;

	//struct msghdr 	*msg  = NULL;
	us_server 		*user = (us_server*)data;

	//if(user->offset == -1)
	{
		ret = us_send(user->skt,(void*)http_response,sizeof(http_response),MSG_DONTWAIT); //sizeof(http_response)
		if(ret < sizeof(http_response)){
			US_ERR("TH:%u,http response send failed!ret:%d\n",US_GET_LCORE(),ret);
			goto over;
		}
		
		user->offset = 0;
	}
	
	/*
	if(user->offset == -1){
		ret = us_send(user->skt,(void*)http_response,sizeof(http_response),MSG_DONTWAIT); //sizeof(http_response)
		if(ret < sizeof(http_response)){
			US_ERR("TH:%u,http response send failed!ret:%d\n",US_GET_LCORE(),ret);
			goto over;
		}
		US_DEBUG("ret:%d \n",ret);
		
		msg = msghdr_malloc( 1 , 1);
		len = 1;
		beg = msghdr_append(msg, &len);

		US_LOG("msghdr append len:%d msg->iov_len:%d \n", len ,msg->msg_iovlen);
		beg = msghdr_append(msg, &len);
		if(msg == NULL){
			US_ERR("TH:%u msghdr malloc failed here!\n",US_GET_LCORE());
			goto over;
		}

		US_LOG("msghdr append len:%d msg->iov_len:%d \n", len ,msg->msg_iovlen);

		if(len > 0){
			memset(beg,1,len);
		}

		ret = us_sendv(user->skt,msg, MSG_DONTWAIT);
		US_ERR("us_sendv ret:%d send_over:%u \n",ret ,send_over);
		if(ret < 0){
			goto over;
		}

		user->offset = (u64)msg;

		us_mod_timer(&user->timer,10);
		return ;
	}else {

		msg = (struct msghdr *)user->offset ;
		len = msghdr_realloc(msg, 2, 2);
		if(len <= 0){
			US_ERR("TH:%u msghdr relloc failed here! ret:%d\n",US_GET_LCORE(),len);
			goto  over;
		}

		len = 1024;
		beg = msghdr_append(msg, &len);	
		US_ERR("msghdr append failed! beg:%p  len:%d \n",beg,len);

		len = 1024;
		beg = msghdr_append(msg, &len);	
		US_ERR("msghdr append failed! beg:%p  len:%d \n",beg,len);
		
		if(len > 0 && beg != NULL){
			memset(beg,1,len);
		}

		ret = us_sendv(user->skt,msg, MSG_DONTWAIT);
		US_ERR("us_sendv ret:%d send_over:%u \n",ret ,send_over);
		if(ret < 0){
			goto over;
		}
		
		us_mod_timer(&user->timer,100*1000);

		if((send_over++) > 0){
			send_over = 0;
			goto  over;
		}

		return ; 
	}*/

	/*
	do{	
		ret = pread(glb_server_fd,buf_tmp,snd_batch,user->offset);
		//if(user->offset >= 4096){
		//	ret = 0;
		//}else{
		//	ret = 4096 - user->offset;
		//	ret = ret < 1400 ? ret : 1400;
		//}
		
		if(ret < 0){
			US_ERR("TH:%u,server read file failed! offset:%u\n"
				,US_GET_LCORE(),user->offset);
			return ;
		}else if(ret == 0){
			goto  over;			
		}else{	
			len = ret;
			ret = us_send(user->skt,buf_tmp,len,MSG_DONTWAIT);
			if(ret < 0){
				US_ERR("TH:%u,server send err!errno:%d\n",US_GET_LCORE(),ret);
				goto over;
			}

			user->offset += ret;
			if(ret < len){
				us_mod_timer(&user->timer,100);
				return ;
			}			
		}
	}while(true);*/	

	/*
	do{ 
		ret = pread(glb_server_fd,buf_tmp,snd_batch,user->offset);
		
		if(user->offset >= 4096){
			ret = 0;
		}else{
			ret = 4096 - user->offset;
			ret = ret < 1400 ? ret : 1400;
		}
		
		if(ret < 0){
			US_ERR("TH:%u,server read file failed! offset:%u\n"
				,US_GET_LCORE(),user->offset);
			return ;
		}else if(ret == 0){
			goto  over; 		
		}else{	
			len = ret;
			ret = us_send(user->skt,buf_tmp,len,MSG_DONTWAIT);
			if(ret < 0){
				US_ERR("TH:%u,server send err!errno:%d\n",US_GET_LCORE(),ret);
				goto over;
			}

			US_ERR("offset:%u \n",ret);
			user->offset += ret;
			if(ret < len){
				us_mod_timer(&user->timer,100);
				return ;
			}			
		}
	}while(true);	*/

	us_close(user->skt);
	return ;
over:
	//msghdr_free(msg, US_MSGHDR_FREE_ALL);
	us_close(user->skt);
	return ;
}


inline int us_server_start(us_server *user)
{
	us_server_loop((unsigned long)user);
	return US_RET_OK;
}

int us_server_recv_handle_s (struct socket *skt, void *msg, int b)
{
	int ret = US_RET_OK;
	//char buf[4096];
	
	if(b < 0 && b!= US_EAGAIN){
		ret = b;
		goto out;
	}

	//US_DEBUG("func:%s,%u  b_len:%d\n",__FUNCTION__,__LINE__,b);

	if(us_read_eof(skt)) {
	US_DEBUG("func:%s,%u  \n",__FUNCTION__,__LINE__);	
		goto out;
	}
	
	return US_RET_OK;
out:
	us_close(skt);
	return ret;
}

void us_server_recv_timeout(unsigned long data)
{
	struct socket *skt = (struct socket*) data;	
	US_ERR("TH:%u, func:%s,%u ATTENTION! timeout:%u\n"
			,US_GET_LCORE(),__FUNCTION__,__LINE__,skt->recv_callback.timer.period);
	
	us_close(skt);
}

void us_server_delay_loop(unsigned long data)
{
	int ret = 0;
	us_server *user = (us_server*)data;
	us_callback_r_reload(user->skt);

	ret = us_recv_set(user->skt, user->data, 1600,0
					,us_server_recv_handle,NULL); //us_server_recv_handle_s //us_server_recv_timeout  //us_server_recv_handle_z
	if(ret < 0){
		US_ERR("TH:%u,us_recv set failed!\n",US_GET_LCORE());
		return;
	}	
}

void us_server_init(us_server *user)
{
	user->skt = NULL;
	user->offset = -1;
	us_setup_timer(&user->timer,us_server_delay_loop,user,TIMER_TYPE_USER2);
	//us_setup_timer(&user->timer,us_server_loop,user,TIMER_TYPE_USER2);
}

void us_server_own_set(us_server *user,struct socket *skt)
{
	user->skt = skt;
	us_socket_obj_set(skt,user,us_server_destroy);
}

int us_server_recv_handle_z (struct socket *skt, void *msg, int b)
{
	int i;
	int iov_len ;
	char *data ;
	int data_len;
	int ret = US_RET_OK;
	
	if(b < 0 && b!= US_EAGAIN){
		ret = b;
		goto out;
	}

	struct msghdr *msg_p = msg;

	iov_len = msghdr_iov_len(msg_p);
		
	for(i = 0 ; i < iov_len ;i++){
		data = msghdr_get_data(msg_p , i, &data_len);

		US_DEBUG("index:%d data:%p len:%d \n", i, data , data_len);
	}

	msghdr_free(msg, US_MSGHDR_FREE_DATA);

	return US_RET_OK;

out:
	us_close(skt);
	return ret;
}
/*
int us_server_recv_handle (struct socket *skt, void *msg, int b)
{
	int ret = US_RET_OK;
	us_server *us_p = NULL;
	if(b < 0 && b!= US_EAGAIN){	  //  回调函数中处理错误； 
		ret = b;
		us_close(skt);					
	}

	us_p = init_server(skt);  // 初次接收数据， 初始 us_server 结构体；
	us_socket_obj_set(skt, us_p, us_server_destroy) ; // 绑定 us_server 以及 us_socket 结构体；
	strncmp(msg, target_str, sizeof(target_str)); // 处理 msg中已经完成读取的数据；

	while(us_read_ready(skt)){			//  查看 skt 中是否仍留有数据待读取；		
		b = us_recv(skt, buf, sizeof(buf) , 0);	  //  读取数据；
		if(b <= 0){
			if(us_read_eof(skt)){		//  是否 skt 上收到对端的FIN 报文，标识连接被动关闭；		
				us_close(skt);	  // 销毁 us_socket 相关所有资源，包括刚刚绑定的 us_server;
				return ret;
			}else{
				ret = b;     // err_log;
			}			
		}
	}

	return ret;				// 退回event_loop ;
}*/

int us_server_recv_handle (struct socket *skt, void *msg, int b)
{
	int ret = US_RET_OK;
	//char buf[4096];
	
	if(b < 0 && b!= US_EAGAIN){
		ret = b;
		goto out;
	}

	/*
	US_DEBUG("recv_data:%p b:%u ready:%d  eof:%d\n",msg, b, us_read_ready(skt), us_read_eof(skt));

	while(us_read_ready(skt) && b > 0){
		US_DEBUG("skt_ready:%d b:%d \n",us_read_ready(skt),b);
		b = us_recv(skt, buf, sizeof(buf), 0);
		if(b <= 0){
			US_DEBUG("skt b:%d eof:%d \n",b,us_read_eof(skt));	
		}
	}*/

	/*
	msg = msghdr_malloc( 2 , 0);
	if(msg == NULL){
		US_ERR("TH:%u msghdr malloc failed here!\n",US_GET_LCORE());
		goto out;
	}
		
	while(us_read_ready(skt) && b > 0){	
		US_DEBUG("skt_ready:%d b:%d \n",us_read_ready(skt),b);
		b = us_recvv(skt,msg,0);
		if(b > 0){
		US_DEBUG("%d ; b:%d \n",us_read_ready(skt),b);	
			msghdr_free(msg, US_MSGHDR_FREE_DATA) ;
		}
	}

	msghdr_free(msg, US_MSGHDR_FREE_ALL) ; 
	*/

	//int n1 = strncmp(msg, "GET", b);
    //int n2 = strncmp(msg ,"Accept", b);
	//fprintf(stderr,"url:%s    b:%d   n1:%d n2:%d\n", msg,b,n1,n2);

	us_server	*user = container_of(msg, us_server, data);	
	if(likely(skt->obj == NULL)){
		us_server_own_set(user,skt);	
	}else{
		user = (us_server*)skt->obj;
		//return US_RET_OK;							//smallboy: More server job here;
	}

	ret = us_send(user->skt,(void*)http_response,sizeof(http_response),MSG_DONTWAIT); //sizeof(http_response)
	if(ret < sizeof(http_response)){
		US_ERR("TH:%u,http response send failed!ret:%d\n",US_GET_LCORE(),ret);
		goto out;
	}
	
	user->offset = 0;
	glb_thcpu[US_GET_LCORE()].usser_num++; 

	/*
	ret = us_server_start(user);
	if(ret < 0){
		goto out;
	}*/

	//us_server_loop((unsigned long)user);

	/*
	us_callback_r_unload(skt);
	glb_thcpu[US_GET_LCORE()].usser_num++; 

	us_mod_timer(&user->timer,jiffies + 3000);	

	ret = write(glb_server_fd , msg ,b );
	if(ret < b){
		perror("write error!\n");
		US_DEBUG("write error! ret:%d b:%d \n",ret,b);
		us_abort(US_GET_LCORE());
	}

	while(us_read_ready(skt) && b > 0){
		US_DEBUG("skt_ready:%d b:%d \n",us_read_ready(skt),b);
		b = us_recv(skt, buf, sizeof(buf), 0);
		if(b <= 0){
			US_DEBUG("skt b:%d eof:%d \n",b,us_read_eof(skt));
			goto out;
		}

		ret = write(glb_server_fd , buf ,b );
		if(ret < b){
			US_DEBUG("skt bad write b:%d eof:%d \n",b,us_read_eof(skt));
			goto out;
		}
	}
		
	if(us_read_eof(skt)){
		close(glb_server_fd);
		goto out;
	} */

	us_close(skt);
	return US_RET_OK;
out:
	us_close(skt);
	return ret;
}

int us_server_request_handle (struct socket *skt,void *arg, int b)
{
	int ret = US_RET_OK;
	struct timeval opt = {30,0};
	int  opt_len = sizeof(opt);
	//struct msghdr	*msg  = NULL;
	us_server		*user = NULL;
	us_objslab		*us_sp = US_PER_LCORE(us_server_slab);
	struct sockaddr_in	*paddr;
	struct sockaddr		getaddr;
	int					getaddr_len;
	
	user = us_memobj_slab_alloc(us_sp);
	if(user == NULL){
		ret = US_ENOMEM;
		US_ERR("TH:%u,%u,us_memobj_slab_alloc failed!\n",US_GET_LCORE(),__LINE__);
		goto err_out;
	}else{
		us_server_init(user);
	}

	//us_setsockopt(skt,SOL_SOCKET,SO_RCVTIMEO,(char *)&opt,opt_len);

	ret = us_recv_set(skt, user->data, 1600,0
					,us_server_recv_handle,NULL);  //us_server_recv_handle_z us_server_recv_timeout
	if(ret < 0){
		US_ERR("TH:%u,us_recv set failed!\n",US_GET_LCORE());
		return ret;
	}

	/*
	if((ret = us_getsockname(skt, &getaddr, &getaddr_len)) < 0){		
		US_ERR("TH:%u us_getsockname for skt failed! errno:%d \n",US_GET_LCORE(),US_ERRNO);
		us_close(skt);
		goto err_out;
	}else{
		paddr = (struct sockaddr_in*) &getaddr;
		US_LOG("addr:%s,local_port:%d \n",trans_ip(paddr->sin_addr.s_addr),ntohs(paddr->sin_port));
	}

	if((ret = us_getpeername(skt, &getaddr, &getaddr_len)) < 0){		
		US_ERR("TH:%u us_getsockname for skt failed! errno:%d \n",US_GET_LCORE(),US_ERRNO);
		us_close(skt);
		goto err_out;
	}else{
		paddr = (struct sockaddr_in*) &getaddr;
		US_LOG("addr:%s,local_port:%d \n",trans_ip(paddr->sin_addr.s_addr),ntohs(paddr->sin_port));
	} */

	/*
	struct msghdr *msg = msghdr_malloc( 2 , 0);
	ret = us_recvv_set(skt, msg, 0,us_server_recv_handle_z,NULL);
	if(ret < 0){
		US_ERR("TH:%u,us_recvv_set failed! ret:%d\n",US_GET_LCORE(),ret);
		return ret;
	} */
	
	return ret;

err_out:
	us_close(skt);
	return ret;
}

int us_server_stub_init(void)
{
	s32 ret ,ip;
	struct socket *listener1;
	struct socket *listener2;
	struct socket *listener3;
	struct socket *listener4;
	us_objslab 		*us_sp = NULL;

	ret = inet_pton(AF_INET, "192.168.30.111", &ip);
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

	/*
	us_objslab * us_sp = us_memobj_slab_create(8, sizeof(us_server), 512*1024);
	
	if(us_sp == NULL){
		US_ERR("TH:%u,server slab cache create failed!\n",US_GET_LCORE());
		return US_ENOMEM;
	}	

	us_memobj_slab_destroy(us_sp);*/

	us_sp = us_memobj_slab_create(512*1024, sizeof(us_server), 512*1024);	
	if(us_sp == NULL){
		US_ERR("TH:%u,server slab cache create failed!\n",US_GET_LCORE());
		return US_ENOMEM;
	}	

	US_PER_LCORE(us_server_slab) = us_sp;
	
	struct sockaddr_in server;
	memset(&server,0,sizeof(struct sockaddr_in));

	server.sin_family	= AF_INET;
	server.sin_port 	= htons(80);
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	listener1 = us_socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	if(listener1 == NULL){
		US_ERR("TH:%u,server1 socket create failed!\n",US_GET_LCORE());
		return US_RET_OK;
	}
	
	if(us_bind(listener1,(struct sockaddr *)&server,sizeof(struct sockaddr))<0){
		US_ERR("TH:%u,server1 socket bind failed! errono:%d\n",US_GET_LCORE(),US_ERRNO);
		us_close(listener1);
		return US_RET_OK;
	}

	if(us_listen(listener1,4096,us_server_request_handle)<0){
		US_ERR("TH:%u,server1 socket listen failed!\n",US_GET_LCORE());
		us_close(listener1);
		return US_RET_OK;		//smallboy: Fix it here ; replace it here with a  cmd pipe;
	}

	if(US_GET_LCORE() == GLB_US_LCORE_LB)
		debug_sk_p = listener1;

	memset(&server,0,sizeof(struct sockaddr_in));	
	server.sin_family	= AF_INET;
	server.sin_port 	= htons(81);
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	listener2 = us_socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	if(listener2 == NULL){
		US_ERR("TH:%u,server2 socket create failed!\n",US_GET_LCORE());
		return US_RET_OK;
	}
	
	if(us_bind(listener2,(struct sockaddr *)&server,sizeof(struct sockaddr))<0){
		US_ERR("TH:%u,server2 socket bind failed! errono:%d\n",US_GET_LCORE(),US_ERRNO);
		us_close(listener2);
		return US_RET_OK;
	}

	if(us_listen(listener2,8192,us_server_request_handle)<0){
		US_ERR("TH:%u,server2 socket listen failed!\n",US_GET_LCORE());
		us_close(listener2);
		return US_RET_OK;		//smallboy: Fix it here ; replace it here with a  cmd pipe;
	}


	memset(&server,0,sizeof(struct sockaddr_in));	
	server.sin_family	= AF_INET;
	server.sin_port 	= htons(82);
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	listener3 = us_socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	if(listener3 == NULL){
		US_ERR("TH:%u,server3 socket create failed!\n",US_GET_LCORE());
		return US_RET_OK;
	}
	if(us_bind(listener3,(struct sockaddr *)&server,sizeof(struct sockaddr))<0){
		US_ERR("TH:%u,server3 socket bind failed! errono:%d\n",US_GET_LCORE(),US_ERRNO);
		us_close(listener3);
		return US_RET_OK;
	}

	if(us_listen(listener3,4096,us_server_request_handle)<0){
		US_ERR("TH:%u,server3 socket listen failed!\n",US_GET_LCORE());
		us_close(listener3);
		return US_RET_OK;		//smallboy: Fix it here ; replace it here with a  cmd pipe;
	}

	memset(&server,0,sizeof(struct sockaddr_in));	
	server.sin_family	= AF_INET;
	server.sin_port 	= htons(83);
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	
	listener4 = us_socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	if(listener4 == NULL){
		US_ERR("TH:%u,server4 socket create failed!\n",US_GET_LCORE());
		return US_RET_OK;
	}
	if(us_bind(listener4,(struct sockaddr *)&server,sizeof(struct sockaddr))<0){
		US_ERR("TH:%u,server4 socket bind failed! errono:%d\n",US_GET_LCORE(),US_ERRNO);
		us_close(listener4);
		return US_RET_OK;
	}

	if(us_listen(listener4,4096,us_server_request_handle)<0){
		US_ERR("TH:%u,server4 socket listen failed!\n",US_GET_LCORE());
		us_close(listener4);
		return US_RET_OK;		//smallboy: Fix it here ; replace it here with a  cmd pipe;
	}

	/*
	us_close(listener1);
	us_close(listener2);
	us_close(listener3);
	us_close(listener4);

	memset(&server,0,sizeof(struct sockaddr_in));

	server.sin_family	= AF_INET;
	server.sin_port 	= htons(80);
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	listener1 = us_socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	if(listener1 == NULL){
		US_ERR("TH:%u,server1 socket create failed!\n",US_GET_LCORE());
		return US_RET_OK;
	}
	
	if(us_bind(listener1,(struct sockaddr *)&server,sizeof(struct sockaddr))<0){
		US_ERR("TH:%u,server1 socket bind failed! errono:%d\n",US_GET_LCORE(),US_ERRNO);
		us_close(listener1);
		return US_RET_OK;
	}

	if(us_listen(listener1,1024,us_server_request_handle)<0){
		US_ERR("TH:%u,server1 socket listen failed!\n",US_GET_LCORE());
		us_close(listener1);
		return US_RET_OK;		//smallboy: Fix it here ; replace it here with a  cmd pipe;
	}	*/

	return US_RET_OK;
}

