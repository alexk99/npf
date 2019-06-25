/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   npf_conn_map_ipv6.cpp
 * Author: alexk
 *
 * Created on June 18, 2016, 17:45 PM
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "libcuckoo/cuckoohash_map.hh"
#include "city.h"
#include "likely.h"
#include "npf_connkey.h"
#include "npf_conn_map_ipv6.h"
#include "npf_print_debug.h"

#define NPF_CONN_MAP_IPV6_SIZE 512 * 4

class conn_hasher {
public:
    size_t operator()(const npf_connkey_ipv6_t& key) const {
        return CityHash64((const char*) &key.ck_key[0], NPF_CONN_KEYLEN(&key));
    }
};

typedef cuckoohash_map<npf_connkey_ipv6_t, void *, conn_hasher> con_map_ipv6_t;

void * 
npf_conn_map_ipv6_init(void) {
	con_map_ipv6_t *map = new con_map_ipv6_t(NPF_CONN_MAP_IPV6_SIZE);
	dprintf("conn map num BUCKETS: %lu\n", map->bucket_count());
	
	return (void *)map;
}

void npf_conn_map_ipv6_fini(void *map) {
	con_map_ipv6_t *cmap = (con_map_ipv6_t *)map;
	
	delete cmap;
}

bool 
operator==(const npf_connkey_ipv6_t& ck1, const npf_connkey_ipv6_t& ck2)
{
	int ret = memcmp(&ck1.ck_key[0], &ck2.ck_key[0], 
			  NPF_CONN_IPV6_KEYLEN_WORDS << 2);
	return ret == 0 ? true : false;
}

uint64_t 
npf_conn_map_ipv6_size(void *map) 
{
	con_map_ipv6_t *cmap = (con_map_ipv6_t *)map;
	
	return cmap->size();
}

void *
npf_conn_map_ipv6_lookup(void *map, const npf_connkey_ipv6_t *key)
{
	con_map_ipv6_t *cmap = (con_map_ipv6_t *)map;
	void *con;
	
	return cmap->find(*key, con) ? con : NULL;
}

/*
 * npf_conndb_insert: insert the key representing the connection.
 */
bool
npf_conn_map_ipv6_insert(void *map, const npf_connkey_ipv6_t *key, void *con)
{
	con_map_ipv6_t *cmap = (con_map_ipv6_t *)map;
	
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
npf_conn_map_ipv6_remove(void *map, const npf_connkey_ipv6_t *key)
{
	con_map_ipv6_t* cmap = (con_map_ipv6_t *)map;
	void *removed_con = NULL;
	
	auto fn = [&removed_con](void *&con) {
		removed_con = con;
		return true;
	};
	
	return cmap->erase_fn(*key, fn) ? removed_con : NULL;
}
