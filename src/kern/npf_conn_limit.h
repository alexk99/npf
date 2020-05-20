/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   npf_conn_limit.h
 * Author: alexk
 *
 * Created on May 19, 2020, 7:42 PM
 */

#ifndef NPF_CONN_LIMIT_H
#define NPF_CONN_LIMIT_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Group connections by
 */
	
/* don't limit connections */
#define CONN_LIMIT_GROUP_OFF 0
/* 
 * group connections by the source ip address
 * and limit the number of coonections in a group
 */
#define CONN_LIMIT_GROUP_BY_SRC 1
/* 
 * group connections by the destination ip address
 * and limit the number of coonections in a group
 */
#define CONN_LIMIT_GROUP_BY_DST 2

/*
 * Connection limit filter mode
 */
	
/* limit all connections */
#define CONN_LIMIT_FILTER_NONE	0
/* limit only the connections with src address included into filters */
#define CONN_LIMIT_FILTER_SRC		1
/* limit only the connections with dst address included into filters */
#define CONN_LIMIT_FILTER_DST		2

/*
 * Max number of filters
 */
#define CONN_LIMIT_MAX_FILTERS 16

/*
 * Actions
 */
#define CONN_LIMIT_ACT_INC	0
#define CONN_LIMIT_ACT_DEC	1
	
typedef struct npf_conn_limit {
	/* group connection by */
	uint8_t group_by;
	/* which connections should be counted and limited */
	uint8_t filter_mode;
	/* number of filters */
	uint8_t nb_filters;
	/* maximum connections in a group, default value */
	uint32_t default_max_connections;
	void *map;
	/* filter: limit only this subnets */
	uint32_t filter_nets[CONN_LIMIT_MAX_FILTERS];
	uint8_t filter_masks[CONN_LIMIT_MAX_FILTERS];
}
npf_conn_limit_t;	

typedef struct npf_conn_limit_group {
	/* maximum number of connection allowed in the group */
	uint32_t max_connections;
	/* current number of connection in the group */
	uint32_t nb_connections;
}
npf_conn_limit_group_t;

typedef struct npf_conn_ipv4 npf_conn_ipv4_t;

npf_conn_limit_t *
npf_conn_limit_init(void);

void
npf_conn_limit_fini(npf_conn_limit_t *conn_limit);

bool
npf_conn_limit(npf_conn_limit_t *conn_limit, npf_conn_ipv4_t *con_ipv4,
		  uint8_t action);

#ifdef __cplusplus
}
#endif

#endif /* NPF_CONN_LIMIT_H */

