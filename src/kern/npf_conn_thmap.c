/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   npf_conn_thmap.c
 * Author: alexk
 *
 * Created on April 21, 2019, 13:12 PM
 */

#ifdef NPF_CONNMAP_THMAP

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "likely.h"
#include "npf_connkey.h"
#include "npf_conn_map.h"
#include "npf_debug.h"
#include "thmap.h"
#include <assert.h>

void *
npf_conn_map_init(void)
{
	return (void *)thmap_create(0, NULL, THMAP_NOCOPY);
}

void
npf_conn_map_fini(void *map)
{
	thmap_destroy(map);
}

uint64_t
npf_conn_map_size(void *map)
{
	/* not supported */
	return 1;
}

void *
npf_conn_map_lookup(void *map, const npf_connkey_ipv4_t *key)
{
	return thmap_get(map, key, sizeof(npf_connkey_ipv4_t));
}

/*
 * npf_conndb_insert: insert the key representing the connection.
 */
bool
npf_conn_map_insert(void *map, const npf_connkey_ipv4_t *key, void *con)
{
	void *ret;

	d_hex_dump("insert key", key, sizeof(npf_connkey_ipv4_t));

	ret = thmap_put(map, key, sizeof(npf_connkey_ipv4_t), con);
	return (ret == con) ? true : false;
}

/*
 * npf_conndb_remove: find and delete the key and return the connection
 * it represents.
 */
void *
npf_conn_map_remove(void *map, const npf_connkey_ipv4_t *key)
{
	d_hex_dump("remove key", key, sizeof(npf_connkey_ipv4_t));

	return thmap_del(map, key, sizeof(npf_connkey_ipv4_t));
}

#ifdef ALEXK_DEBUG

#include <string.h>

void
npf_thmap_test(void)
{
	uint8_t key[10];
	uint8_t key2[10];
	void *p1 = (void *)0x1123;
	void *p2 = (void *)0x1124;
	void *ret;

	memset(key, 0, 10);
	key[0] = 1;
	key[1] = 2;

	memset(key2, 0, 10);
	key2[0] = 1;
	key2[1] = 2;

	// thmap_t *map = thmap_create(0, g_thmap_ops, THMAP_NOCOPY);
	thmap_t *map = thmap_create(0, NULL, THMAP_NOCOPY);
	assert(map != NULL);

	ret = thmap_put(map, key, 10, p1);
	assert(ret == p1);

	ret = thmap_put(map, key2, 10, p2);
	dprintf("ret %p\n", ret);
	assert(ret == p1);

	ret = thmap_del(map, key, 10);
	assert(ret == p1);

	thmap_destroy(map);

	dprintf("!!!!! npf thmap simple test is OK\n");
}

#endif /* ALEXK_DEBUG */

#endif /* NPF_CONNMAP_THMAP */