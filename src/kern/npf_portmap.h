/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   npf_portmap.h
 * Author: alexk
 *
 * Created on May 29, 2016, 7:13 PM
 */

#ifndef NPF_PORTMAP_H
#define NPF_PORTMAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stdbool.h"
#include "sys/types.h"
#include "stdint.h"
	
#define NPF_PORTMAP_MAX_ENTRIES 4096	
	
/* Portmap range: [ 1024 .. 65535 ] */
#define	PORTMAP_FIRST		(1024)
#define	PORTMAP_SIZE		((65536 - PORTMAP_FIRST) / 32)
#define	PORTMAP_FILLED		((uint32_t)~0U)
#define	PORTMAP_MASK		(31)
#define	PORTMAP_SHIFT		(5)

#define	PORTMAP_MEM_SIZE	\
    (sizeof(npf_portmap_t) + (PORTMAP_SIZE * sizeof(uint32_t)))	
	
/*
 * NPF portmap structure.

 *  */
typedef struct npf_portmap npf_portmap_entry_t;
	
typedef struct npf_portmap {
	u_int			p_refcnt;
	uint32_t		p_bitmap[0];
	npf_portmap_entry_t* next;
} npf_portmap_t;

typedef npf_portmap_t npf_portmap_entry_t;
	
typedef struct npf_portmap_hash {
	void* hash;
	npf_portmap_entry_t* gc_list;
}
npf_portmap_hash_t;
	
npf_portmap_hash_t* 
npf_portmap_init(void);

void 
npf_portmap_fini(npf_portmap_hash_t* pm);

npf_portmap_entry_t*
npf_portmap_get(npf_portmap_hash_t* pm, uint32_t ip);

int
npf_portmap_return(npf_portmap_hash_t* pm, uint32_t ip);

void 
npf_portmap_gc(npf_portmap_hash_t* pm);

#ifdef ALEXK_DEBUG
void npf_portmap_test(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NPF_PORTMAP_H */

