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

#include "cuckoo/cuckoohash_map.hh"
#include "city.h"
#include "likely.h"
#include "npf.h"
#include "npf_connkey.h"

typedef struct npf_connkey_ipv6 npf_connkey_ipv6_t;

#include "npf_conn_map_ipv6.h"
#include "npf_debug.h"

class conn_hasher {
public:
    size_t operator()(const npf_connkey_ipv6_t& key) const {
        return CityHash64((const char*) &key.ck_key[0], NPF_CONN_KEYLEN(&key));
    }
};

typedef cuckoohash_map<npf_connkey_ipv6_t, void*, 
		  conn_hasher> con_map_ipv6_t;

void* npf_conn_map_ipv6_init(void) {
	con_map_ipv6_t* map = new con_map_ipv6_t(NPF_CONN_MAP_IPV6_SIZE);
	dprintf2("conn map num BUCKETS: %lu\n", map->bucket_count());
	return (void*) map;
}

void npf_conn_map_ipv6_fini(void* map) {
	con_map_ipv6_t* cmap = (con_map_ipv6_t*) map;
	delete cmap;
}

bool operator==(const npf_connkey_ipv6_t& ck1, const npf_connkey_ipv6_t& ck2)
{
	int ret = memcmp(&ck1.ck_key[0], &ck2.ck_key[0], 
			  NPF_CONN_IPV6_KEYLEN_WORDS << 2);
	return ret == 0 ? true : false;
}

size_t npf_conn_map_ipv6_hash(void* map, const npf_connkey_ipv6_t *key) 
{
	con_map_ipv6_t* cmap = (con_map_ipv6_t*) map;
	return cmap->key_hash(*key);
}

uint64_t npf_conn_map_ipv6_size(void* map) 
{
	con_map_ipv6_t* cmap = (con_map_ipv6_t*) map;
	return cmap->size();
}

void *
npf_conn_map_ipv6_lookup(void* map, const npf_connkey_ipv6_t *key, const size_t hv)
{
	con_map_ipv6_t* cmap = (con_map_ipv6_t*) map;
	
	void* con;
	if (!cmap->find(*key, con, hv)) {
		return NULL;
	}

	return con;
}

/*
 * npf_conndb_insert: insert the key representing the connection.
 */
bool
npf_conn_map_ipv6_insert(void *map, const npf_connkey_ipv6_t *key, const size_t hv, 
		  void *con)
{
	con_map_ipv6_t* cmap = (con_map_ipv6_t*) map;
	return cmap->insert(*key, hv, con);
}

/*
 * npf_conndb_remove: find and delete the key and return the connection
 * it represents.
 */
void*
npf_conn_map_ipv6_remove(void *map, const npf_connkey_ipv6_t *key, const size_t hv)
{
	con_map_ipv6_t* cmap = (con_map_ipv6_t*) map;
	void* l_con = NULL;
	
	auto fn = [&l_con](void*& con) {
		l_con = con;
		con = NULL;
	};
	
	if (cmap->update_fn(*key, hv, fn)) {
		cmap->erase(*key, hv);
		return l_con;
	}
			  
	return NULL;
}
