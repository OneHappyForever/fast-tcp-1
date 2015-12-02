/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			atomic.h
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/

//@note , Not atomic here !!!!!!!

#ifndef _US_ATOMIC_H
#define _US_ATOMIC_H

#include "types.h"

//smallboy: Fix it later; problem: asm () block can not be compiled OK;

/**
 * atomic_dec_and_test - decrement and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
static inline int atomic_dec_and_test(atomic_t *v)
{
	/*unsigned char c;
	
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
		     : "+m" (*v), "=qm" (c)
		     : : "memory");
	return c != 0;
	*/
	*v -= 1;
	return !!(*v == 0);
}

/**
 * atomic_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
static inline int atomic_sub_and_test(int i, atomic_t *v)
{
	/*unsigned char c;

	
	asm volatile(LOCK_PREFIX "subl %2,%0; sete %1"
		     : "+m" (*v), "=qm" (c)
		     : "ir" (i) : "memory");
	return c;	
	*/

	*v -= i;
	return (*v == 0) ;
}



static inline int atomic_inc_not_zero(atomic_t *a)
{
	if(*a != 0) {
		(*a)++;
		return *a;
	}else{
		return *a;
	}
}

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */
static inline void atomic_add(int i, atomic_t *v)
{
	/*
	asm volatile(LOCK_PREFIX "addl %1,%0"
		     : "+m" (*v)
		     : "ir" (i));
	*/
	*v += i;
}

/**
 * atomic64_read - read atomic64 variable
 * @v: pointer of type atomic64_t
 *
 * Atomically reads the value of @v.
 * Doesn't imply a read memory barrier.
 */
static inline long atomic64_read(const long *v)
{
	return (*((volatile long *)(v)));
}


static inline long atomic_long_read(atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	return (long)atomic64_read(v);
}

/**
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically reads the value of @v.
 */
static inline int atomic_read(const atomic_t *v)
{
	//return (*(volatile int *)&(v)->counter);
	return (*((volatile int *)(v)));
}


/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
static inline void atomic_inc(atomic_t *v)
{
	/*
	asm volatile(LOCK_PREFIX "incl %0"
		     : "+m" (*v));
	*/

	*v += 1;
}

/**
 * atomic_sub - subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.
 */
static inline void atomic_sub(int i, atomic_t *v)
{
	/*
	asm volatile(LOCK_PREFIX "subl %1,%0"
		     : "+m" (*v)
		     : "ir" (i));
    */
	*v -= i;	   
}


/**
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
static inline void atomic_set(atomic_t *v, int i)
{
	//v->counter = i;
	*v = i;
}


/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
static inline void atomic_dec(atomic_t *v)
{
	/*
	asm volatile(LOCK_PREFIX "decl %0"
		     : "+m" (*v));
	*/
	*v -= 1;
}

/**
 * atomic64_add - add integer to atomic64 variable
 * @i: integer value to add
 * @v: pointer to type atomic64_t
 *
 * Atomically adds @i to @v.
 */
static inline void atomic64_add(long i, long *v)
{
	/*
	asm volatile(LOCK_PREFIX "addq %1,%0"
		     : "=m" (*v)
		     : "er" (i), "m" (*v));
	*/
	(*v) += i;	    
}

/**
 * atomic64_dec - decrement atomic64 variable
 * @v: pointer to type atomic64_t
 *
 * Atomically decrements @v by 1.
 */
static inline void atomic64_dec(long i,long *v)
{
	/*
	asm volatile(LOCK_PREFIX "decq %0"
		     : "=m" (*v)
		     : "m" (*v));
	*/
	*v-= i;
}


static inline void atomic_long_add(long i, atomic_long_t *l)
{
	atomic_long_t *v = (atomic_long_t *)l;

	atomic64_add(i, v);
}

static inline void atomic_long_dec(long i,atomic_long_t *l)
{
	atomic_long_t *v = (atomic_long_t *)l;

	atomic64_dec(i,v);
}


#endif
