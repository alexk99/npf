/*	$NetBSD: npf_conn.h,v 1.8 2014/12/20 16:19:43 rmind Exp $	*/

/*-
 * Copyright (c) 2009-2014 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _NPF_CONN_H_
#define _NPF_CONN_H_

#if !defined(_KERNEL) && !defined(_NPF_STANDALONE)
#error "kernel-level header only"
#endif

#include <sys/types.h>

#include "npf_impl.h"

typedef struct npf_connkey_ipv4 npf_connkey_ipv4_t;
typedef struct npf_connkey_ipv6 npf_connkey_ipv6_t;

#if defined(__NPF_CONN_PRIVATE)

#include "npf_connkey.h"

#define	CONN_ACTIVE	0x004	/* visible on inspection */
#define	CONN_PASS	0x008	/* perform implicit passing */
#define	CONN_EXPIRE	0x010	/* explicitly expire */
#define	CONN_REMOVED 0x020	/* "forw/back" entries removed */
#define	CONN_IPV4	0x040	/* ipv4 connection */
#define	CONN_IPV6	0x080	/* ipv6 connection */

/* particial hash values of backward and forward keys are equal */
#define	CONN_PARTICIAL_HASH_COLLISION	0x100

/*
 * The main connection tracking structure.
 */

struct npf_conn {
	npf_lock_t		c_lock;

	/* It's the first 32 bits of forward key hash value.
	 * Particial key is used to determine the direction of a connection
	 * by its key hash value. Since always two keys lead to a single connection
	 * we have to determine which was used to find a connection in a particular
	 * case. To do that we compare a key hash value with a forward keys hash value.
	 * If values are equal then the direction is forward. 
	 * 
	 * It's enought to compare
	 * only first 32 bits of hash values due to rare hash collisions. 
	 * If a hash collision occurs we have to do the real comparasion by calculating
	 * full hash value and comparing it with the given key hash value. 
	 * 
	 * Since we compare only particial keys hash values the collision flag must 
	 * be determined by comparing particial values too. Fact of collision 
	 * is stored in CONN_PARTICIAL_HASH_COLLISION bit of the connection c_flag.
	 */
	uint32_t				c_forw_entry_particial_hash;
	
	/*
	 * The protocol state, reference count and the last activity
	 * time (used to calculate expiration time).
	 */
	npf_state_t		c_state;
	uint64_t		c_atime;
	
	u_int			c_proto;
	
	/* Interface ID (if zero, then the state is global) */
	u_int			c_ifid;

	/* Flags */
	u_int			c_flags;
	
	/* Associated rule procedure or NAT (if any). */
	npf_nat_t *		c_nat;
	npf_rproc_t *		c_rproc;
	
	/* Entry in the connection database or G/C list. */
	npf_conn_t *		c_next;
};

struct npf_conn_ipv4 {
	struct npf_conn conn;

	/* nat */
	in_addr_t		nt_oaddr;
	in_addr_t		nt_taddr;
	in_port_t	nt_oport;
	in_port_t	nt_tport;
	int nt_type;
	
	/*
	 * Connection "forwards" and "backwards" entries
	 */
	npf_connkey_ipv4_t		c_forw_entry;
	npf_connkey_ipv4_t		c_back_entry;
};

struct npf_conn_ipv6 {
	struct npf_conn conn;

	/* nat */
	npf_addr_t		nt_oaddr;
	npf_addr_t		nt_taddr;
	in_port_t	nt_oport;
	in_port_t	nt_tport;
	int nt_type;
	
	/*
	 * Connection "forwards" and "backwards" entries
	 */
	npf_connkey_ipv6_t		c_forw_entry;
	npf_connkey_ipv6_t		c_back_entry;
};

#endif

typedef struct npf_connkey_ipv4 npf_connkey_ipv4_t;
typedef struct npf_connkey_ipv6 npf_connkey_ipv6_t;

/*
 * Connection tracking interface.
 */
void		npf_conn_init(npf_t *, int);
void		npf_conn_fini(npf_t *);
void		npf_conn_tracking(npf_t *, bool);
void		npf_conn_load(npf_t *, npf_conndb_t *, bool);

unsigned	npf_conn_conkey(const npf_cache_t *, uint32_t *, bool);
npf_conn_t *	npf_conn_lookup(const npf_cache_t *, const int, bool *);
npf_conn_t *	npf_conn_inspect(npf_cache_t *, const int, int *);
npf_conn_t *	npf_conn_establish(npf_cache_t *, int, bool);
void		npf_conn_release(npf_conn_t *);
void		npf_conn_expire(npf_conn_t *);
bool		npf_conn_pass(const npf_conn_t *, npf_rproc_t **);
void		npf_conn_setpass(npf_conn_t *, npf_rproc_t *);
int		npf_conn_setnat(const npf_cache_t *, npf_conn_t *,
		    npf_nat_t *, u_int);
npf_nat_t *	npf_conn_getnat(npf_conn_t *, const int, bool *);
void		npf_conn_gc(npf_t *, npf_conndb_t *, bool, bool);
void		npf_conn_worker(npf_t *);
int		npf_conn_import(npf_t *, npf_conndb_t *, prop_dictionary_t,
		    npf_ruleset_t *);
prop_dictionary_t npf_conn_export(npf_t *, const npf_conn_t *);
void		npf_conn_print(const npf_conn_t *);

/*
 * Connection database (aka state table) interface.
 */
npf_conndb_t *	npf_conndb_create(void);
void		npf_conndb_destroy(npf_conndb_t *);

uint64_t npf_conndb_size(npf_conndb_t *);
uint64_t npf_conndb_ipv6_size(npf_conndb_t *);

uint64_t npf_conndb_hash(npf_conndb_t*, const void*, const u_int);

npf_conn_t * npf_conndb_lookup(npf_conndb_t *, const void *, const u_int, bool *);
bool npf_conndb_insert(npf_conndb_t *, void *, const u_int, uint64_t, npf_conn_t *);
npf_conn_t * npf_conndb_remove(npf_conndb_t *, void *, const u_int, uint64_t);

npf_conn_t *
npf_conndb_count(npf_conndb_t *cd);


void		npf_conndb_enqueue(npf_conndb_t *, npf_conn_t *);
void		npf_conndb_dequeue(npf_conndb_t *, npf_conn_t *,
		    npf_conn_t *);
npf_conn_t *	npf_conndb_getlist(npf_conndb_t *);
void		npf_conndb_settail(npf_conndb_t *, npf_conn_t *);
int		npf_conndb_export(npf_t *, prop_array_t);

void npf_conn_print_atime(const npf_conn_t *);

#endif	/* _NPF_CONN_H_ */
