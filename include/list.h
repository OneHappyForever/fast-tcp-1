/**
**********************************************************************
*
* Copyright (c) 	2013 Baidu.com, Inc. All Rights Reserved
* @file 			list.h
* @brief			code pieces copied from the linux kernel;
* @author			smallboy.lf@gmail.com
* @date 			2013/12/20
***********************************************************************
*/ 


#ifndef _US_LIST_H
#define _US_LIST_H

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)


struct us_list_head {
	struct us_list_head *next, *prev;
};

#define US_LIST_HEAD_INIT(name) { &(name), &(name) }

#define US_LIST_HEAD(name) \
	struct us_list_head name = US_LIST_HEAD_INIT(name)

static inline void US_INIT_LIST_HEAD(struct us_list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __us_list_add(struct us_list_head *new,struct us_list_head *prev,
			      struct us_list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void us_list_add(struct us_list_head *new, struct us_list_head *head)
{
	__us_list_add(new, head, head->next);
}

/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void us_list_add_tail(struct us_list_head *new, struct us_list_head *head)
{
	__us_list_add(new, head->prev, head);
}

static inline void __us_list_del(struct us_list_head * prev, struct us_list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void __us_list_del_entry(struct us_list_head *entry)
{
	__us_list_del(entry->prev, entry->next);
}

static inline void us_list_del(struct us_list_head *entry)
{
	__us_list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

/**
 * list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void us_list_del_init(struct us_list_head *entry)
{
	__us_list_del_entry(entry);
	US_INIT_LIST_HEAD(entry);
}

/**
 * list_is_last - tests whether @list is the last entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int us_list_is_last(const struct us_list_head *list,
				const struct us_list_head *head)
{
	return list->next == head;
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int us_list_empty(const struct us_list_head *head)
{
	return head->next == head;
}

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define us_list_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define us_list_first_entry(ptr, type, member) \
	us_list_entry((ptr)->next, type, member)


/**
 * list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define us_list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)


/**
 * list_for_each_prev	-	iterate over a list backwards
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define us_list_for_each_prev(pos, head) \
		for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop cursor.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define us_list_for_each_safe(pos, n, head) \
		for (pos = (head)->next, n = pos->next; pos != (head); \
			pos = n, n = pos->next)
		
/**
 * list_for_each_prev_safe - iterate over a list backwards safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop cursor.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define us_list_for_each_prev_safe(pos, n, head) \
		for (pos = (head)->prev, n = pos->prev; \
			 pos != (head); \
			 pos = n, n = pos->prev)


/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define us_list_for_each_entry(pos, head, member)				\
	for (pos = us_list_entry((head)->next, typeof(*pos), member);	\
		 &pos->member != (head);	\
		 pos = us_list_entry(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define us_list_for_each_entry_safe(pos, n, head, member)			\
		for (pos = us_list_entry((head)->next, typeof(*pos), member),	\
			n = us_list_entry(pos->member.next, typeof(*pos), member); \
			 &pos->member != (head);					\
			 pos = n, n = us_list_entry(n->member.next, typeof(*n), member))


/**
 * list_for_each_entry_safe_from - iterate over list from current point safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type from current point, safe against
 * removal of list entry.
 */
#define us_list_for_each_entry_safe_from(pos, n, head, member) 			\
	for (n = us_list_entry(pos->member.next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = n, n = us_list_entry(n->member.next, typeof(*n), member))	



////////////////////////////////////////////////////////////////////////////////////////

struct us_hlist_node {
	struct us_hlist_node *next, **pprev;
};

struct us_hlist_head {
	struct us_hlist_node *first;
};

/*
 * Double linked lists with a single pointer list head.
 * Mostly useful for hash tables where the two pointer list head is
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */

#define us_hlist_entry(ptr, type, member) container_of(ptr,type,member)
	
#define US_HLIST_HEAD_INIT { .first = NULL }
#define US_HLIST_HEAD(name) struct us_hlist_head name = {  .first = NULL }
#define US_INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)


#define us_hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define us_hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)

#define us_hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)

#define us_hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? us_hlist_entry(____ptr, type, member) : NULL; \
	})


static inline int us_hlist_empty(const struct us_hlist_head *h)
{
	return !h->first;
}

static inline void US_INIT_HLIST_NODE(struct us_hlist_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

static inline int us_hlist_unhashed(const struct us_hlist_node *h)
{
	return !h->pprev;
}


static inline void __us_hlist_del(struct us_hlist_node *n)
{
	struct us_hlist_node *next = n->next;
	struct us_hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static inline void us_hlist_del(struct us_hlist_node *n)
{
	__us_hlist_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}

static inline void us_hlist_del_init(struct us_hlist_node *n)
{
	if (!us_hlist_unhashed(n)) {
		__us_hlist_del(n);
		US_INIT_HLIST_NODE(n);
	}
}

static inline void us_hlist_add_head(struct us_hlist_node *n, struct us_hlist_head *h)
{
	struct us_hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

static inline void us_hlist_add_before(struct us_hlist_node *n,struct us_hlist_node *next)
{
	n->pprev = next->pprev;
	n->next = next;
	next->pprev = &n->next;
	*(n->pprev) = n;
}

static inline void us_hlist_add_after(struct us_hlist_node *n,struct us_hlist_node *next)
{
	next->next = n->next;
	n->next = next;
	next->pprev = &n->next;

	if(next->next)
		next->next->pprev  = &next->next;
}

/**
 * hlist_for_each_entry	- iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
#define us_hlist_for_each_entry(pos, head, member)				\
	for (pos = us_hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = us_hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

/**
 * hlist_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another &struct hlist_node to use as temporary storage
 * @head:	the head for your list.
 * @member: the name of the hlist_node within the struct.
 */
#define us_hlist_for_each_entry_safe(pos, n, head, member) 		\
	for (pos = us_hlist_entry_safe((head)->first, typeof(*pos), member);\
		 pos && ({ n = pos->member.next; 1; }); 		\
		 pos = us_hlist_entry_safe(n, typeof(*pos), member))

#endif
