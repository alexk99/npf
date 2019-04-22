/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   npf_conn_map.cpp
 * Author: alexk
 *
 * Created on June 6, 2016, 10:08 PM
 */

#ifdef NPF_CONNMAP_EFFICIENT_CUCKOO

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "libcuckoo/cuckoohash_map.hh"
#include "city.h"
#include "likely.h"
#include "npf_connkey.h"
#include "npf_debug.h"

#include "npf_conn_map.h"

class conn_hasher {
public:
    size_t operator()(const npf_connkey_ipv4_t& key) const {
        return CityHash64((const char*) &key.ck_key[0], NPF_CONN_KEYLEN(&key));
    }
};

typedef cuckoohash_map<npf_connkey_ipv4_t, void *, conn_hasher> con_map_t;

#define NPF_CONN_MAP_IPV4_SIZE 196608 * 4 * 8

void * 
npf_conn_map_init(void) {
	con_map_t *map = new con_map_t(NPF_CONN_MAP_IPV4_SIZE);
	dprintf("conn map num BUCKETS: %lu\n", map->bucket_count());
	
	return (void *)map;
}

void 
npf_conn_map_fini(void *map) {
	con_map_t *cmap = (con_map_t *)map;
	
	delete cmap;
}

bool
operator==(const npf_connkey_ipv4_t& ck1, const npf_connkey_ipv4_t& ck2)
{
	int ret = memcmp(&ck1.ck_key[0], &ck2.ck_key[0], 
			  NPF_CONN_IPV4_KEYLEN_WORDS << 2);
	return ret == 0 ? true : false;
}

uint64_t
npf_conn_map_size(void *map) 
{
	con_map_t *cmap = (con_map_t *)map;
	
	return cmap->size();
}

void *
npf_conn_map_lookup(void *map, const npf_connkey_ipv4_t *key)
{
	con_map_t *cmap = (con_map_t *)map;
	void *con;
	
	return cmap->find(*key, con) ? con : NULL;
}

/*
 * npf_conndb_insert: insert the key representing the connection.
 */
bool
npf_conn_map_insert(void *map, const npf_connkey_ipv4_t *key, void *con)
{
	con_map_t *cmap = (con_map_t *)map;

	try {
	  return cmap->insert(*key, con);
	} 
	catch (std::bad_alloc &) {
		return false;
	}
}

/*
 * npf_conndb_remove: find and delete the key and return the connection
 * it represents.
 */
void *
npf_conn_map_remove(void *map, const npf_connkey_ipv4_t *key)
{
	con_map_t *cmap = (con_map_t *)map;
	void *removed_con = NULL;

	auto fn = [&removed_con](void *&con) {
		removed_con = con;
		return true;
	};
	
	return cmap->erase_fn(*key, fn) ? removed_con : NULL;
}

#endif /* NPF_CONNMAP_EFFICIENT_CUCKOO */
