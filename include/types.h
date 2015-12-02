/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file				types.h
* @brief			code pieces from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date				2013/12/20
***********************************************************************
*/


#ifndef _US_TYPES_H
#define _US_TYPES_H

#include "defines.h"
#include "us_rte.h"


typedef		unsigned char		__u8 ;	
typedef 	char				__s8 ;

typedef		unsigned short		__u16 ;
typedef 	short				__s16 ;

typedef		unsigned int		__u32 ;
typedef		int				 	__s32 ;

typedef 	unsigned long		__u64 ;	
typedef 	long				__s64 ;

typedef		__u8				u8 ;	
typedef 	__s8				s8 ;

typedef		__u16				u16 ;	
typedef 	__s16				s16 ;

typedef		__u32				u32 ;
typedef		__s32				s32 ;

typedef 	__u64				u64 ;	
typedef 	__s64				s64 ;



#define 	__bitwise

// Little Endian defines 
#ifndef __le16
#define __le16  __u16
#endif

#ifndef __le32
#define __le32  __u32
#endif

#ifndef __le64
#define __le64  __u64
#endif

// Big Endian defines 
#ifndef __be16
#define __be16  __u16
#define __be32  __u32
#define __be64  __u64

#endif	

typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;

typedef 		 int	bool;
#define 		 false	(0)
#define 		 true	(1)

//typedef rte_atomic64_t		atomic_long_t;
//typedef rte_atomic32_t		atomic_t ;

typedef s64		atomic64_t;
typedef s64		atomic_long_t;
typedef s32		atomic_t ;

typedef struct rte_ring 			us_ring;
typedef struct rte_mempool 			us_mempool;
typedef struct rte_memzone			us_memzone;

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

/**
 * div_u64_rem - unsigned 64bit divide with 32bit divisor with remainder
 *
 * This is commonly provided by 32bit archs to provide an optimized 64bit
 * divide.
 */
static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

static inline u64 div_u64(u64 dividend, u32 divisor)
{
	u32 remainder;
	return div_u64_rem(dividend, divisor, &remainder);
}


/**
 * clamp - return a value clamped to a given range with strict typechecking
 * @val: current value
 * @min: minimum allowable value
 * @max: maximum allowable value
 *
 * This macro does strict typechecking of min/max to make sure they are of the
 * same type as val.  See the unnecessary pointer comparisons.
 */
#define clamp(val, min, max) ({			\
	typeof(val) __val = (val);		\
	typeof(min) __min = (min);		\
	typeof(max) __max = (max);		\
	(void) (&__val == &__min);		\
	(void) (&__val == &__max);		\
	__val = __val < __min ? __min: __val;	\
	__val > __max ? __max: __val; })


/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})


/*
 * ..and if you can't take the strict
 * types, you can specify one yourself.
 *
 * Or not use min/max/clamp at all, of course.
 */
#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1: __max2; })

/*
 * min()/max()/clamp() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

#define min3(x, y, z) ({			\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	typeof(z) _min3 = (z);			\
	(void) (&_min1 == &_min2);		\
	(void) (&_min1 == &_min3);		\
	_min1 < _min2 ? (_min1 < _min3 ? _min1 : _min3) : \
		(_min2 < _min3 ? _min2 : _min3); })

#define max3(x, y, z) ({			\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	typeof(z) _max3 = (z);			\
	(void) (&_max1 == &_max2);		\
	(void) (&_max1 == &_max3);		\
	_max1 > _max2 ? (_max1 > _max3 ? _max1 : _max3) : \
		(_max2 > _max3 ? _max2 : _max3); })

/*
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
 */
#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})


#define __ALIGN_KERNEL(x, a)			__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define ALIGN(x, a)						__ALIGN_KERNEL((x), (a))
#define __ALIGN_MASK(x, mask)			__ALIGN_KERNEL_MASK((x), (mask))


/*
 * swap - swap value of @a and @b
 */
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

static inline u32 read_not_aligned_word(u8 *p)
{
	u32 tmp;
	u8  *c = (u8*)&tmp;
	c[0] = p[0];
	c[1] = p[1];
	c[2] = p[2];
	c[3] = p[3];
	return tmp;
}

#define htonl(a)  						\
(										\
	 (((a) & (0xFF)) << 24) 				\
			| (( (a) & (0xFF00))<<8)		\
			| (( (a) & (0xFF0000)) >>8)	\
			| (( (a) & (0xFF000000)) >> 24)	\
)

#define ntohl(a)	htonl(a)

#define htons(a)  					\
(									\
	(((a) & (0xFF)) << 8)				\
		|(((a) & (0xFF00)) >> 8)		\
)		

#define ntohs(a)	htons(a)

#define get_unaligned_be32(a)	(ntohl(*(u32 *)(a)))	
#define get_unaligned_be16(a)	(ntohs(*(u16 *)(a)))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))


/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME_32 0x9e370001UL
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001UL

#if BITS_PER_LONG == 32
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_32
#define hash_long(val, bits) hash_32(val, bits)
#elif BITS_PER_LONG == 64
#define hash_long(val, bits) hash_64(val, bits)
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_64
#else
#error Wordsize not 32 or 64
#endif

static inline u64 hash_64(u64 val, unsigned int bits)
{
	u64 hash = val;

	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	u64 n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;

	/* High bits are more random, so use them. */
	return hash >> (64 - bits);
}

static inline u32 hash_32(u32 val, unsigned int bits)
{
	/* On some cpus multiply is faster, on others gcc will do shifts */
	u32 hash = val * GOLDEN_RATIO_PRIME_32;

	/* High bits are more random, so use them. */
	return hash >> (32 - bits);
}

static inline unsigned long hash_ptr(const void *ptr, unsigned int bits)
{
	return hash_long((unsigned long)ptr, bits);
}

static inline int xchg(int *val_base,int new_val)
{
	int tmp = *val_base;
	*val_base = new_val;
	return tmp;
}

/**
 * div64_u64 - unsigned 64bit divide with 64bit divisor
 */
static inline u64 div64_u64(u64 dividend, u64 divisor)
{
	return dividend / divisor;
}

#if BITS_PER_LONG == 64
#define do_div(n,base) ({\
	u32 __base = (base);\
	u32 __rem;			\
	__rem = ((u64)(n)) % __base;\
	(n) = ((u64)(n)) / __base;\
	__rem; 						\
}) 
#endif



extern void us_abort(u32 lcore);			//smallboy:Fix it later;
extern s8 *trans_ip(u32 ip);				//smallboy:Fix it later;

#endif /* _UAPI_ASM_GENERIC_INT_L64_H */

