/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   npf_conn_map.h
 * Author: alexk
 *
 * Created on June 18, 2016, 17:45 PM
 */

#ifndef NPF_CONN_MAP_V6_H
#define NPF_CONN_MAP_V6_H

#ifdef __cplusplus
extern "C" {
#endif

void * 
npf_conn_map_ipv6_init(void);

void
npf_conn_map_ipv6_fini(void *map);

uint64_t 
npf_conn_map_ipv6_size(void *map);

void *
npf_conn_map_ipv6_lookup(void *map, const npf_connkey_ipv6_t *key);

bool
npf_conn_map_ipv6_insert(void *map, const npf_connkey_ipv6_t *key, void *con);

void *
npf_conn_map_ipv6_remove(void *map, const npf_connkey_ipv6_t *key);

#ifdef __cplusplus
}
#endif

#endif /* NPF_CONN_MAP_V6_H */

