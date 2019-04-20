/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   npf_conn_map.h
 * Author: alexk
 *
 * Created on June 7, 2016, 8:09 PM
 */

#ifndef NPF_CONN_MAP_H
#define NPF_CONN_MAP_H

#ifdef __cplusplus
extern "C" {
#endif
	
void *
npf_conn_map_init(void);

void 
npf_conn_map_fini(void *map);

size_t 
npf_conn_map_hash(void *map, const void *key);

uint64_t 
npf_conn_map_size(void *map);

void *
npf_conn_map_lookup(void *map, const npf_connkey_ipv4_t *key);

bool
npf_conn_map_insert(void *map, const npf_connkey_ipv4_t *key, void *con);

void *
npf_conn_map_remove(void *map, const npf_connkey_ipv4_t *key);

#ifdef __cplusplus
}
#endif

#endif /* NPF_CONN_MAP_H */

