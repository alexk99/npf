/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   npf_conn_limit.cpp
 * Author: alexk
 *
 * Created on May 19, 2020, 19:39 PM
 */

#include <stdio.h>
#include <stdint.h>
#include "libcuckoo/cuckoohash_map.hh"
#include "city.h"
#include "likely.h"
#include "npf_conn_limit.h"

#define __NPF_CONN_PRIVATE
#include "npf_conn.h"

class conn_limit_hasher {
public:
    size_t operator()(const uint32_t& key) const {
        return CityHash64((const char *)&key, sizeof(uint32_t));
    }
};

typedef cuckoohash_map<uint32_t, npf_conn_limit_group_t, conn_limit_hasher> 
	con_limit_map_t;

#define NPF_CONN_LIMIT_MAP_SIZE 8096

npf_conn_limit_t *
npf_conn_limit_init(void) {
	npf_conn_limit_t *cl;
	con_limit_map_t *clmap;
	
	cl = (npf_conn_limit_t *)malloc(sizeof(npf_conn_limit_t));
	if (cl == NULL)
		return NULL;
	
	clmap = new con_limit_map_t(NPF_CONN_LIMIT_MAP_SIZE);
	if (clmap == NULL) {
		free(cl);
		return NULL;
	}
	
	cl->group_by = CONN_LIMIT_GROUP_OFF;
	cl->filter_mode = CONN_LIMIT_FILTER_NONE;
	cl->nb_filters = 0;
	cl->default_max_connections = 1024;
	cl->map = (void *)clmap;
	
	return cl;
}

void
npf_conn_limit_fini(npf_conn_limit_t *conn_limit)
{
	delete (con_limit_map_t *)conn_limit->map;
	free(conn_limit);
}

/*
 * update the limit db
 *
 * Returns:
 *   false - no more connections are allowed
 *   true - ok
 * 
 * Algorithm: 
 *   if there is no group in the db,
 *   then create a new one and set max_connections to the default and
 *   nb_connection to one and finally return true;
 *
 *   if group is found, then return false if no more connections
 *   can be created, otherwise increase the nb_connection counter
 *   and return true; 
 */
static bool
npf_conn_limit_map_inc(void *map, const uint32_t ip,
		  uint32_t default_max_conn)
{
	con_limit_map_t *clmap = (con_limit_map_t *)map;
	npf_conn_limit_group_t new_group;
	bool res;
	
	try {
		auto fn = [&res](npf_conn_limit_group_t &group) {
			if (group.nb_connections >= group.max_connections)
				res = false;
			else {
				group.nb_connections++;
				res = true;
			}
			
			/* don't delete the group */
			return false;
		};
		
		new_group.max_connections = default_max_conn;
		new_group.nb_connections = 1;
		
		if (clmap->uprase_fn(ip, fn, new_group))
			/* the new group has been inserted */
			return true;
		else
			return res;
	}
	catch (std::bad_alloc &) {
		return false;
	}
}

static void
npf_conn_limit_map_dec(void *map, const uint32_t ip)
{
	con_limit_map_t *clmap = (con_limit_map_t *)map;
	
	try {
		auto fn = [](npf_conn_limit_group_t &group) {
			if (group.nb_connections > 0)
				group.nb_connections--;
			/* 
			 * never delete the group, since we could  
			 * lost the max_conn value set up by a user
			 */
			return false;
		};
		
		clmap->erase_fn(ip, fn);
	}
	catch (std::bad_alloc &) {
		return;
	}
}

/*
 * Converts a given depth value to its corresponding mask value.
 *
 * depth  (IN)		: range = 1 - 32
 * mask   (OUT)		: 32bit mask
 */
static inline uint32_t
depth2mask(uint8_t depth)
{
	assert(depth >= 1 && depth <= 32);

	/* To calculate a mask start with a 1 on the left hand side and right
	 * shift while populating the left hand side with 1's
	 */
	return (int)0x80000000 >> (depth - 1);
}

static int
npf_conndb_limit_lookup_filter(const npf_conn_limit_t *conn_limit,
		  uint32_t ip)
{
	int i;

	for (i = 0; i < conn_limit->nb_filters; i++)
		if ((ip & depth2mask(conn_limit->filter_masks[i])) == 
				  conn_limit->filter_nets[i])
			return i;

	return -1;
}

static int
npf_conndb_limit_lookup_filter_exact(const npf_conn_limit_t *conn_limit,
		  uint32_t net, uint8_t mask)
{
	int i;

	for (i = 0; i < conn_limit->nb_filters; i++)
		if (net == conn_limit->filter_nets[i] && 
				  mask == conn_limit->filter_masks[i])
			return i;

	return -1;
}

/*
 * Limit the number of connections in a group
 *
 * Result:
 *	  if action is CONN_LIMIT_ACT_INC
 *      true - connection is permitted
 *      false - connection is forbidden
 *   if action is CONN_LIMIT_ACT_DEL
 *      always return true
 */
bool
npf_conn_limit(npf_conn_limit_t *conn_limit, npf_conn_ipv4_t *con_ipv4,
		  uint8_t action)
{
	uint32_t group_ip;

	switch (conn_limit->group_by) {
	case CONN_LIMIT_GROUP_BY_SRC:
		group_ip = ntohl(con_ipv4->c_forw_entry.ck_key[2]);
		break;

	case CONN_LIMIT_GROUP_BY_DST:
		group_ip = ntohl(con_ipv4->c_forw_entry.ck_key[3]);
		break;

	case CONN_LIMIT_GROUP_OFF:
		return true;
		
	default:
		assert(false);
	}	
	
	/* should we take into account this connection? */
	if (conn_limit->filter_mode == CONN_LIMIT_FILTER_SRC) {
		if (npf_conndb_limit_lookup_filter(conn_limit,
				  ntohl(con_ipv4->c_forw_entry.ck_key[2])) < 0)
			/* limit only connections included in the filter array */
			return true;
	}
	else if (conn_limit->filter_mode == CONN_LIMIT_FILTER_DST) {
		if (npf_conndb_limit_lookup_filter(conn_limit,
				  ntohl(con_ipv4->c_forw_entry.ck_key[3])) < 0)
			/* limit only connections included in the filter array */
			return true;
	}
	/* else limit all connections */

	/* 
	 * Update the limit map.
	 *
	 *   if there is no group in the map,
	 *   then create a new one and set max_connections to the default and
	 *   nb_connection to one and finally return true;
	 *
	 *   if group is found, then return false if no more connections
	 *   can be created, otherwise increase the nb_connection counter
	 *   and return true;
	 */
	if (action == CONN_LIMIT_ACT_INC)
		return npf_conn_limit_map_inc(conn_limit->map, group_ip,
			  conn_limit->default_max_connections);
	else {
		npf_conn_limit_map_dec(conn_limit->map, group_ip);
		return true;
	}
}

/*
 * Public API
 */

#ifdef __cplusplus
extern "C" {
#endif

__dso_public void
npf_nat_conn_limit_params_set(npf_t *npf,
	uint8_t group_by, uint8_t filter_mode, uint32_t default_max_conns)
{
	npf_conn_limit_t *cl = npf->conn_db->conn_limit;
	
	cl->default_max_connections = default_max_conns;
	cl->filter_mode = filter_mode;
	cl->group_by = group_by;
}

__dso_public void
npf_nat_conn_limit_params_get(npf_t *npf,
	uint8_t *group_by, uint8_t *filter_mode, uint32_t *default_max_conns)
{
	npf_conn_limit_t *cl = npf->conn_db->conn_limit;

	*default_max_conns = cl->default_max_connections;
	*filter_mode = cl->filter_mode;
	*group_by = cl->group_by;
}

__dso_public int
npf_nat_conn_limit_filter_add(npf_t *npf, uint32_t net, uint8_t mask)
{
	npf_conn_limit_t *cl = npf->conn_db->conn_limit;

	if (cl->nb_filters == CONN_LIMIT_MAX_FILTERS)
		/* no empty slots */
		return -1;

	cl->filter_nets[cl->nb_filters] = net & depth2mask(mask);
	cl->filter_masks[cl->nb_filters] = mask;
	cl->nb_filters++;

	/* success */
	return 0;
}

__dso_public int
npf_nat_conn_limit_filter_del(npf_t *npf, uint32_t net, uint8_t mask)
{
	int i, ret;
	npf_conn_limit_t *cl = npf->conn_db->conn_limit;
	
	ret = npf_conndb_limit_lookup_filter_exact(cl, net, mask);
	if (ret < 0)
		return ret;
	
	cl->nb_filters--;
	
	/* repack the filter arrays */
	for (i = ret; i < cl->nb_filters; i++) {
		cl->filter_nets[i] = cl->filter_nets[i + 1];
		cl->filter_masks[i] = cl->filter_masks[i + 1];
	}

	return 0;
}

__dso_public bool
npf_nat_conn_limit_get(npf_t *npf, uint32_t ip, uint32_t *max_conns,
		  uint32_t *nb_conns)
{
	con_limit_map_t *clmap = (con_limit_map_t *) npf->conn_db->conn_limit->map;
	npf_conn_limit_group_t group;
	
	try {
		if (clmap->find(ip, group)) {
			*nb_conns = group.nb_connections;
			*max_conns = group.max_connections;
			return true;
		}
		else
			return false;
	}
	catch (std::bad_alloc &) {
		return false;
	}
}

__dso_public void
npf_nat_conn_limit_set(npf_t *npf, uint32_t ip, uint32_t max_conns)
{
	con_limit_map_t *clmap = (con_limit_map_t *)npf->conn_db->conn_limit->map;;
	npf_conn_limit_group_t new_group;
	
	try {
		auto fn = [max_conns](npf_conn_limit_group_t &group) {
			group.max_connections = max_conns;
			/* don't delete the group */
			return false;
		};
		
		new_group.max_connections = max_conns;
		new_group.nb_connections = 0;
		
		/*
		 * update an existing group or
		 * create a new one
		 */
		clmap->uprase_fn(ip, fn, new_group);
	}
	catch (std::bad_alloc &) {
		return;
	}
}

#ifdef __cplusplus
}
#endif
