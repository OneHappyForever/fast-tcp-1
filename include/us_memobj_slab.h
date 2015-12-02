/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				us_memobj.h
* @brief			head file for memobj interface;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/

#ifndef _US_MEMOBJ_H
#define _US_MEMOBJ_H

#include "types.h"
#include "list.h"

typedef struct __us_objslab{
	struct us_list_head	slab_head;
	unsigned int 	slab_obj_size;
	unsigned int	slab_num;
	unsigned int 	slab_max;
	unsigned int 	slab_water;
	unsigned int 	slab_used;
	unsigned int 	__padding;
}us_objslab;

typedef struct __us_objslabs{
	us_objslab  *objslab[US_BUF_SLAB_SIZE];
}us_objslabs;

struct us_objslab_head{
	struct us_list_head	head;
	us_objslab			*slab;
	char				*obj;
	u32					obj_size;
	u32					magic_num;
	u64					phead;
};


extern void us_memobj_slab_destroy(us_objslab *us_p);
extern void *us_memobj_slab_alloc(us_objslab *us_p);
extern void us_memobj_slab_free(void *head);
extern void *us_buf_slab_alloc(int size);
extern void us_buf_slab_free(void *data);
extern u32 us_buf_slab_truesize(int size);
extern void *us_buf_slab_end(void *head, int size);
extern us_objslab *us_memobj_slab_create(int slab_water,int slab_objsize,int slab_max);


#endif

