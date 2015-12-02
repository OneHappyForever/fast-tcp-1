/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_memobj.c
* @brief			functions for us_slab interface;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/
#include "us_error.h"
#include "us_memobj_slab.h"

US_DECLARE_PER_LCORE(us_objslabs*,buffer_slab);

#define SLAB_HEAD_MAGIC_NUM 	3634528


//@brief ,free all the mem for a slab ;
void us_memobj_slab_destroy(us_objslab *us_p)
{
	struct us_list_head *p, *n;
	us_list_for_each_safe(p, n ,&us_p->slab_head){	
		us_free(p);
	}
	
	us_p->slab_num = 0;
	us_free(us_p);
}

//@brief , create a new slab here;
//@input , slab_water-> the nums of memobjs reserved;
//@input , slab_objsize-> sizeof memobj;
//@input , slab_max-> the max num of memobjs within a slab;
//@output, the pointer to a memobj slab if success; else NULL;
us_objslab *us_memobj_slab_create(int slab_water,int slab_objsize,int slab_max)
{
	int i = 0;
	char *p_obj = NULL;
	struct us_objslab_head *uss_head = NULL;
	
	if(slab_max <= 0 || slab_objsize <= 0 || slab_max <= 0 ||  slab_water > slab_max || slab_water < 0){
		US_ERRNO = US_EINVAL;
		return NULL;
	}
	
	us_objslab	*us_sp = (us_objslab*)us_zmalloc(NULL,sizeof(us_objslab),SMP_CACHE_BYTES);
	if(us_sp == NULL){
		US_ERRNO = US_ENOBUFS;
		return us_sp;
	}
	US_INIT_LIST_HEAD(&us_sp->slab_head);
	us_sp->slab_num = 0;
	us_sp->slab_max = slab_max;
	
	us_sp->slab_obj_size = ((slab_objsize + sizeof(struct us_objslab_head) + 15)&(~7));
	us_sp->slab_water = slab_water;

	for(i=0; i<us_sp->slab_water;i++){		
		p_obj = us_malloc(NULL,us_sp->slab_obj_size,SMP_CACHE_BYTES);
		if(p_obj == NULL){
			US_ERRNO = US_ENOMEM;
			goto err_out;
		}
		uss_head = (struct us_objslab_head *)p_obj;
		uss_head->slab = us_sp;
		
		uss_head->obj_size = us_sp->slab_obj_size - ((sizeof(struct us_objslab_head) + 7) &(~7));		
		uss_head->obj = (char *)p_obj + ((sizeof(struct us_objslab_head) + 7)&(~7)) ;

		uss_head->phead = (u64)uss_head;
		uss_head->magic_num = SLAB_HEAD_MAGIC_NUM;
		
		us_list_add(&uss_head->head,&us_sp->slab_head);
		us_sp->slab_num++;

		//US_ERR("usususussu malloc pobj:%p slab:%p slab->water:%d slab_num:%d slab_max:%d \n"
		//				,p_obj,us_sp,us_sp->slab_water,us_sp->slab_num,us_sp->slab_max);	

	}

	us_sp->slab_used = 0;
	return us_sp;

err_out:
	us_memobj_slab_destroy(us_sp);
	return NULL;
}

static inline int us_slab_is_full(us_objslab *us_p)
{
	return us_p->slab_num >  us_p->slab_max;
}

static inline int us_slab_is_overflow(us_objslab *us_p)
{
	return us_p->slab_num >  us_p->slab_water;
}

static inline int us_slab_is_empty(us_objslab *us_p)
{
	return us_list_empty(&us_p->slab_head);
}

static inline void *us_slab_get_one(us_objslab *us_p)
{
	struct us_objslab_head *uss_head 
		= us_list_first_entry(&us_p->slab_head, struct us_objslab_head , head);
	us_list_del(&uss_head->head);

	//US_ERR("usususussu get head:%p slab:%p data:%p size:%u \n"
	//		,uss_head,uss_head->slab,uss_head->obj,uss_head->obj_size);
	us_p->slab_used++;
	return (void *)uss_head->obj;
}

static inline void us_slab_put_one(us_objslab *us_p,struct us_objslab_head *uss_head)
{
	us_list_add(&uss_head->head, &us_p->slab_head);
	us_p->slab_used--;
	//US_ERR("usususussu free head:%p slab:%p data:%p size:%u \n"
	//		,uss_head,uss_head->slab,uss_head->obj,uss_head->obj_size);
}

static u32 glb_debug_uss = 0;

//@brief , alloc one obj from a objslab;
//@output, the pointer to the new obj if success,else NONE;
//@input , the pointer to the objslab;
void *us_memobj_slab_alloc(us_objslab *us_p)
{
	char *p_obj = NULL;
	struct us_objslab_head *uss_head = NULL;
	if(unlikely(us_p == NULL))
		return NULL;
	if(unlikely(us_slab_is_empty(us_p))){
		if(unlikely(us_slab_is_full(us_p))){
			return NULL;
		}else{
			p_obj = (char *)us_malloc(NULL,us_p->slab_obj_size,SMP_CACHE_BYTES);
			if(p_obj == NULL){
				return NULL;
			}
			uss_head = (struct us_objslab_head *)p_obj;
			uss_head->slab = us_p;		

			//uss_head->obj_size = us_p->slab_obj_size - sizeof(struct us_objslab_head) ;
			uss_head->obj_size = us_p->slab_obj_size - ((sizeof(struct us_objslab_head) + 7) &(~7));
			uss_head->obj = p_obj + ((sizeof(struct us_objslab_head) + 7)&(~7));// sizeof(struct us_objslab_head);

			uss_head->phead = (u64)uss_head;
			uss_head->magic_num = SLAB_HEAD_MAGIC_NUM;

			us_p->slab_num++;

			us_p->slab_used++;

			//US_ERR("usususussu malloc pobj:%p slab:%p slab->water:%d slab_num:%d slab_max:%d \n"
			//		,p_obj,us_p,us_p->slab_water,us_p->slab_num,us_p->slab_max);	

			//glb_debug_uss = 1;
			return uss_head->obj;
		}
	}else{
		return us_slab_get_one(us_p);
	}
}

//@brief ,try to give back a objslab; free it when water leve is high;
void us_memobj_slab_free(void *head)
{	struct us_objslab_head *uss_head ;
	long *delta = (long *)head;
	
	if(likely(head != NULL)){
		uss_head = (struct us_objslab_head *)(*(delta - 1));
		if(likely(uss_head->slab != NULL && uss_head->magic_num == SLAB_HEAD_MAGIC_NUM)){
			if(unlikely(us_slab_is_overflow(uss_head->slab))){
				uss_head->slab->slab_num--;
				uss_head->slab->slab_used--;

				//US_ERR("usususussu free pobj:%p slab:%p slab->water:%d slab_num:%d slab_max:%d \n"
				//		,uss_head,uss_head->slab,uss_head->slab->slab_water,uss_head->slab->slab_num,uss_head->slab->slab_max);	

				us_free(uss_head);
			}else{
				us_slab_put_one(uss_head->slab,uss_head);
			}
		}
	}
}

//@brief , try to alloc a buffer from the buf_slab;
//@input , the size of buffer in need;
//@output , the pointer to the buffer's data area if success; else NULL;
void *us_buf_slab_alloc(int size)
{	
	s32 slab_index = 0;
	long *delta = NULL;
	long *data = NULL;
	us_objslabs	*bslab = US_PER_LCORE(buffer_slab);
	us_objslab	*slab = NULL;
	if(size > 0){
		slab_index = (size - 1) >> US_BUF_SIZE_BASE_POW;  // 4096 in the first slab;
		if(slab_index >= US_BUF_SLAB_SIZE){
			data = (long *)malloc(size + sizeof(long));
			if(data == NULL){
				return data;
			}else{
				delta = data;	
				delta[0] = 0;
				data = &delta[1];
			}
		}else{
			slab = bslab->objslab[slab_index];
			data = us_memobj_slab_alloc(slab);	
		}
	}
	
	return data;
}

//@brief , try to give back a buffer ;
//@input , the pointer to the buffer's data area;
void us_buf_slab_free(void *data)
{	
	long *delta = (long *)data;
	if(delta){
		delta = delta - 1;
		if(*delta == 0){
			//US_DEBUG("ffffffffffree data:%p \n",delta);
			free(delta);
		}else{
			us_memobj_slab_free(data);		
		}
	}
}

//@brief , get the real buffer size ;
//@input , the buffer size when alloced;
//@output, the truesize of a buffer;
u32 us_buf_slab_truesize(int size)
{
	u32 size_pow = (size - 1) >> US_BUF_SIZE_BASE_POW;
	if(size_pow >= US_BUF_SLAB_SIZE)
		return size;
	else
		return US_BUF_SIZE_BASE*(size_pow + 1);
}

//@brief ;
void *us_buf_slab_end(void *head, int size)
{
	return (char*)head + us_buf_slab_truesize(size);
}

int us_slab_stub_test(void)
{
	int i = 0,j = 0;
	void *data = NULL;
	long *delta = NULL;

	void *d6[20] = {};
	struct us_objslab_head *uss_head = NULL;

	for(i = 0;i < 10;i++){
		data = us_buf_slab_alloc(16385); //16384
		if(data == NULL){
			break;
		}

		US_DEBUG("dddddddddddddata:%p \n",data);

		d6[i] = data;

		delta = (long *)data;
		uss_head = (struct us_objslab_head *)(*(delta - 1));
		//US_ERR("delta  alloc_head:%p \n",uss_head);
		//US_ERR("uss_head:%p slab:%p obj:%p  obj_size:%u \n",uss_head,uss_head->slab,uss_head->obj,uss_head->obj_size);
		memset(data,0,16386);	
	}

	for(j = 0 ;j < i;j++){
		data = d6[j];
		us_buf_slab_free(data);
	}

	return i;
}


