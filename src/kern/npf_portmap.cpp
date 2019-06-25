/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   portmap.cpp
 * Author: alexk
 *
 * Created on May 29, 2016, 4:22 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "libcuckoo/cuckoohash_map.hh"
#include "city.h"
#include "likely.h"

#include "npf_print_debug.h"
#include "npf_portmap.h"
#include "npf_stand.h"
#include "npf_impl.h"

class portmap_hasher {
public:
    size_t operator()(const uint32_t& key) const {
        return CityHash64((const char*) &key, sizeof(uint32_t));
    }
};

typedef cuckoohash_map<uint32_t, npf_portmap_entry_t*, portmap_hasher> 
	portmap_hash_t;	

/*
 * start using an existing portmap if any
 * or create a new one
 */
npf_portmap_entry_t*
npf_portmap_get(npf_portmap_hash_t* pm, uint32_t ip)
{
	portmap_hash_t* hash = (portmap_hash_t*) pm->hash;
	npf_portmap_entry_t* pm_entry;
	bool ret;

	while (true) {
		/* get pm */
		ret = hash->find(ip, pm_entry);
		if (likely(ret)) {
			assert(pm_entry);
			
			/* existing pm entry is found, try to use it */
			uint32_t rc = pm_entry->p_refcnt;

			if (likely(rc > 0)) {
				uint32_t new_rc = rc + 1;
				if (likely(atomic_cas_ptr(&pm_entry->p_refcnt, rc, new_rc) == rc)) {
					/* reference counter is sucessfully incremented */
					dprintf("Reference to existing portmap is acquired.\n");
					return pm_entry;
				}

				/* Pm has been updated by a concurrent thread.
				 * Try again.
				 */
				continue;
			}
			/* 
			 * Reference counter is zero. The pm entry is beeing deleted 
			 * at the moment. Peharps it will have been deleted  
			 * by the time we start the next iteration.
			 */
			continue;
		}
		
		/*
		 * There is no pm entry for the given ip.
		 * Try to create a new one.
		 */

		/* Allocate a new port map for the NAT policy. */
		dprintf("new portmap\n");
		
		/*
		 * todo: use a pool of pm entries to encrease perfomance
		 */
		
		npf_portmap_entry_t* new_pm_entry = 
				  (npf_portmap_entry_t*) kmem_zalloc(PORTMAP_MEM_SIZE, KM_SLEEP);
		new_pm_entry->p_refcnt = 1;

		if (likely(hash->insert(ip, new_pm_entry))) {
			return new_pm_entry;
		}

		/* a concurrent thread has already inserted a new pm entry
		 * for the given ip, we will try to use it in the next iteration.
		 */
		free(new_pm_entry);
	}
}

/*
 * npf_portmap_enqueue: atomically insert the pm_entry into the
 * singly-linked list of removed pm entries
 */
static void
npf_portmap_add_to_gc_list(npf_portmap_hash_t* pm,  npf_portmap_entry_t* pm_entry)
{
	npf_portmap_entry_t *head;

	do {
		head = pm->gc_list;
		pm_entry->next = head;
	} while (!atomic_cas_bool(&pm->gc_list, head, pm_entry));
}

/*
 * Stop using a portmap.
 * Free it if nobody else uses it.
 *
 * Returns:
 *		0 - success,
 *		<0 - failure
 */
int
npf_portmap_return(npf_portmap_hash_t* pm, uint32_t ip)
{
	portmap_hash_t* hash = (portmap_hash_t*) pm->hash;
	npf_portmap_entry_t* pm_entry;
	bool ret;

	while (true) {
		/* get pm */
		ret = hash->find(ip, pm_entry);
		if (likely(ret)) {
			assert(pm_entry);
			uint32_t rc = pm_entry->p_refcnt;
			if (likely(rc > 0)) {
				uint32_t new_rc = rc - 1;
				if (likely(atomic_cas_ptr(&pm_entry->p_refcnt, rc, new_rc) == rc)) {
					/* 
					 * Reference counter is successfully decremented.
					 * 
					 * Once reference counter is zero no other concurrent npf_pm_get() 
					 * functions will reuse the entry and increment its reference counter.
					 * Also a concurrent npf_pm_return() operations are impossible 
					 * too for the same reason when rc is zero.
					 * So, once a reference counter is 0 any other conncurrent 
					 * operations on it will be forbidden.
					 */
					if (unlikely(new_rc == 0)) {
						/* Nobody else uses it, free the entry.
						 *
						 * Don't free the entry immediately as
						 * there might be local references to
						 * it in concurrent operations,
						 * but use QSBR GC reclamation mechanism.
						 */
						dprintf("remove portmap entry\n");

						/* 
						 * Remove the pm entry from the hash 
						 */
						ret = hash->erase(ip);
						/* There are no concurrent operations on pm with the given ip 
						 * at the moment. Therefore the result must be always true.
						 * See the note above. */
						assert(ret);
						
						/* Add a removed entry to the gc list */
						npf_portmap_add_to_gc_list(pm, pm_entry);
					}

					/* success */
					return 0;
				}
				/* else: cas failed. Try again. */
				continue;
			}
			/* Rc is already zero.
			 * Somebody is trying to return pm second time.
			 */
			return -2;
		}
		else {
			/* pm is not found */
			return -1;
		}
		/* we should never get here */
		assert(0);
	}
}

/*
 * Free portmap entry
 */
static inline void
npf_portmap_destroy(npf_portmap_entry_t* pm_entry) {
	dprintf("free pm\n");
	kmem_free(pm_entry, PORTMAP_MEM_SIZE);
}

/*
 * Garbage collect all removed port map entries.
 * Not thread safe.
 */
void npf_portmap_gc(npf_portmap_hash_t* pm) {
	npf_portmap_entry_t* gc_list = (npf_portmap_entry_t*) atomic_swap_ptr(
			  &pm->gc_list, NULL);
	npf_portmap_entry_t* pm_entry = gc_list;
	while (pm_entry) {
		dprintf("npf_portmap_gc()\n");
		npf_portmap_entry_t *next = pm_entry->next;
		npf_portmap_destroy(pm_entry);
		pm_entry = next;
	}
}

/*
 * Not thread safe
 */
npf_portmap_hash_t*
npf_portmap_init(void)
{
	npf_portmap_hash_t* pm = (npf_portmap_hash_t*) kmem_zalloc(
			  sizeof(npf_portmap_hash_t), KM_SLEEP); 
	
	portmap_hash_t* hash = new portmap_hash_t(NPF_PORTMAP_HASH_SIZE);
	if (hash == NULL) {
		kmem_free(pm, sizeof(npf_portmap_hash_t));
		return NULL;
	}

	pm->hash = hash;
	pm->gc_list = NULL;
	
	dprintf("portmap hash BUCKETS: %lu\n", hash->bucket_count());
	return pm;
}

#ifdef NPF_CONN_DEBUG

/*
 * find pm by ip address
 */
npf_portmap_entry_t*
npf_portmap_find(npf_portmap_hash_t* pm, uint32_t ip) 
{
	portmap_hash_t* hash = (portmap_hash_t*) pm->hash;
	npf_portmap_entry_t* pm_entry;
	bool ret;

	ret = hash->find(ip, pm_entry);
	if (ret)
		return pm_entry;
	else
		return NULL;
}

#endif /* NPF_CONN_DEBUG */

/*
 * Not thread safe.
 */
void
npf_portmap_fini(npf_portmap_hash_t* pm)
{
	npf_portmap_gc(pm);
	
	portmap_hash_t* hash = (portmap_hash_t*) pm->hash;
	delete hash;
	kmem_free(pm, sizeof(npf_portmap_hash_t));
}

#ifdef ALEXK_DEBUG

void npf_portmap_test(void)
{
	npf_portmap_hash_t* pm;
	npf_portmap_entry_t* pm_entry, *pm_entry2, *pm_entry3, *pm_entry4;
	bool ret;
	int ret2;

	/* test 1 */
	pm = npf_portmap_init();
	assert(pm);

	pm_entry = npf_portmap_get(pm, 1);
	assert(pm_entry);
	assert(pm_entry->ref_c == 1);
	printf("portmap test 1 - success\n");

	pm_entry2 = npf_portmap_get(pm, 1);
	assert(pm_entry2);
	assert(pm_entry2 == pm_entry);
	assert(pm_entry->ref_c == 2);
	assert(pm_entry2->ref_c == 2);
	printf("portmap test 2 - success\n");

	ret2 = npf_portmap_return(pm, 1);
	assert(ret2 == 0);
	assert(pm_entry->ref_c == 1);
	printf("portmap test 3 - success\n");

	ret2 = npf_portmap_return(pm, 12);
	assert(ret2 == -1);
	printf("portmap test 4 - success\n");

	ret2 = npf_portmap_return(pm, 1);
	assert(ret2 == 0);
	ret2 = npf_portmap_return(pm, 1);
	assert(ret2 == -1);
	printf("portmap test 5 - success\n");

	pm_entry3 = npf_portmap_get(pm, 1);
	assert(pm_entry3);
	assert(pm_entry3->ref_c == 1);
	assert(pm_entry3 != pm_entry);
	printf("portmap test 6 - success\n");

	npf_portmap_fini(pm);
}

#endif /* ALEXK_DEBUG */