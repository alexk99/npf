/*	$NetBSD: npf_conndb.c,v 1.2 2014/07/23 01:25:34 rmind Exp $	*/

/*-
 * Copyright (c) 2010-2014 The NetBSD Foundation, Inc.
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

/*
 * NPF connection storage.
 */

#ifdef _KERNEL
#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: npf_conndb.c,v 1.2 2014/07/23 01:25:34 rmind Exp $");

#include <sys/param.h>
#include <sys/types.h>

#include <sys/atomic.h>
#include <sys/cprng.h>
#include <sys/hash.h>
#include <sys/kmem.h>
#endif

#define __NPF_CONN_PRIVATE
#include "npf_conn.h"
#include "npf_impl.h"
#include "npf_conn_map.h"
#include "npf_conn_map_ipv6.h"
#include "npf_city_hasher.h"
#include "likely.h"

#ifdef NPF_DEBUG_COUNTERS
extern uint64_t g_debug_counter;
#endif /* NPF_DEBUG_COUNTERS */

/*
 * Note: (node1 < node2) shall return negative.
 */

inline static signed int
conndb_forw_cmp(npf_conn_t* con, const void* key, const u_int key_nwords)
{
	uint32_t* p;

	if (likely(key_nwords == NPF_CONN_IPV4_KEYLEN_WORDS)) {
		npf_conn_ipv4_t* con_ipv4 = (npf_conn_ipv4_t*) con;
		p = &con_ipv4->c_forw_entry.ck_key[0];
	}
	else {
		npf_conn_ipv6_t* con_ipv6 = (npf_conn_ipv6_t*) con;
		p = &con_ipv6->c_forw_entry.ck_key[0];
	}

	return memcmp(key, p, key_nwords << 2);
}

inline static void
npf_conndb_print_key(const uint32_t* key, const u_int key_nwords)
{
	u_int i;
	for (i=0; i<key_nwords; i++) {
		printf("%u", key[i]);
	}
	printf("\n");
}

npf_conndb_t *
npf_conndb_create(void)
{
	size_t len = sizeof(npf_conndb_t);
	npf_conndb_t *cd = kmem_zalloc(len, KM_SLEEP);

	cd->cd_seed = cprng_fast32();
	cd->conn_map_ipv4 = npf_conn_map_init();
	cd->conn_map_ipv6 = npf_conn_map_ipv6_init();
	cd->gc_state = NPF_GC_STATE_START;
	cd->cd_tail_valid = true;

	return cd;
}

void
npf_conndb_destroy(npf_conndb_t *cd)
{
	npf_conn_map_fini(cd->conn_map_ipv4);
	npf_conn_map_ipv6_fini(cd->conn_map_ipv6);

	size_t len = sizeof(npf_conndb_t);

	KASSERT(cd->cd_recent == NULL);
	KASSERT(cd->cd_list == NULL);
	KASSERT(cd->cd_tail == NULL);

	kmem_free(cd, len);
}

/*
 *
 */
uint64_t
npf_conndb_hash(npf_conndb_t* cd, const void* key, const u_int key_nwords)
{
	/* return murmurhash2(key->ck_key, NPF_CONN_KEYLEN(key), cd->cd_seed); */

	(void) cd;
	return npf_city_hash((const char*) key, key_nwords << 2);
}

/*
 * Returns the size of the conn map
 */
uint64_t
npf_conndb_size(npf_conndb_t* cd, const u_int key_nwords)
{
	if (likely(key_nwords == NPF_CONN_IPV4_KEYLEN_WORDS)) {
		return npf_conn_map_size(cd->conn_map_ipv4);
	}
	else {
		return npf_conn_map_ipv6_size(cd->conn_map_ipv6);
	}
}

/*
 * npf_conndb_lookup: find a connection given the key.
 */
npf_conn_t *
npf_conndb_lookup(npf_conndb_t *cd, const void *key, const u_int key_nwords,
		  bool *forw)
{
	npf_conn_t* con;
	const uint64_t hv = npf_conndb_hash(cd, key, key_nwords);

	if (likely(key_nwords == NPF_CONN_IPV4_KEYLEN_WORDS)) {
		con = (npf_conn_t*) npf_conn_map_lookup(cd->conn_map_ipv4, key, hv);
	}
	else {
		con = (npf_conn_t*) npf_conn_map_ipv6_lookup(cd->conn_map_ipv6, key, hv);
	}

	if (con == NULL) {
		return NULL;
	}

	/* determine forw */
	if (unlikely(con->c_flags & CONN_PARTICIAL_HASH_COLLISION)) {
		/* hash collision, we need to do full comparing */
		*forw = (conndb_forw_cmp(con, key, key_nwords) == 0);
	}
	else {
		uint32_t particial_hv = (uint32_t) hv & 0xFFFFFFFF;
		bool b = (con->c_forw_entry_particial_hash == particial_hv);
		*forw = b;
	}

	return con;
}

/*
 * npf_conndb_lookup: find a connection given the key.
 */
npf_conn_t *
npf_conndb_lookup_only(npf_conndb_t *cd, const void *key, const u_int key_nwords,
		  uint64_t* out_hv)
{
	npf_conn_t* con;
	const uint64_t hv = npf_conndb_hash(cd, key, key_nwords);

	if (likely(key_nwords == NPF_CONN_IPV4_KEYLEN_WORDS))
		con = (npf_conn_t*) npf_conn_map_lookup(cd->conn_map_ipv4, key, hv);
	else
		con = (npf_conn_t*) npf_conn_map_ipv6_lookup(cd->conn_map_ipv6, key, hv);

	if (con == NULL)
		return NULL;

	*out_hv = hv;
	return con;
}

/*
 *
 */
bool
npf_conndb_forw(npf_conn_t* con, const void *key, const u_int key_nwords,
		  const uint64_t hv)
{
	/* determine forw */
	if (unlikely(con->c_flags & CONN_PARTICIAL_HASH_COLLISION)) {
		/* hash collision, we need to do a real comparing */
		return (conndb_forw_cmp(con, key, key_nwords) == 0);
	}
	else {
		uint32_t particial_hv = (uint32_t) hv & 0xFFFFFFFF;
		return (con->c_forw_entry_particial_hash == particial_hv);
	}
}


/*
 * npf_conndb_insert: insert a key representing a connection.
 */
bool
npf_conndb_insert(npf_conndb_t *cd, void *key, const u_int key_nwords,
		  uint64_t hv, npf_conn_t *con)
{
	if (likely(key_nwords == NPF_CONN_IPV4_KEYLEN_WORDS)) {
		return npf_conn_map_insert(cd->conn_map_ipv4, key, hv, (void*) con);
	}
	else {
		return npf_conn_map_ipv6_insert(cd->conn_map_ipv6, key, hv, (void*) con);
	}
}

/*
 * npf_conndb_remove: find and delete the key and return the connection
 * it represents.
 */
npf_conn_t *
npf_conndb_remove(npf_conndb_t *cd, void *key, const u_int key_nwords,
		  uint64_t hv)
{
	if (likely(key_nwords == NPF_CONN_IPV4_KEYLEN_WORDS)) {
		return (npf_conn_t*) npf_conn_map_remove(cd->conn_map_ipv4, key, hv);
	}
	else {
		return (npf_conn_t*) npf_conn_map_ipv6_remove(cd->conn_map_ipv6, key, hv);
	}
}

uint64_t
npf_conndb_ipv4_size(npf_conndb_t *cd)
{
	return npf_conn_map_size(cd->conn_map_ipv4);
}

uint64_t
npf_conndb_ipv6_size(npf_conndb_t *cd)
{
	return npf_conn_map_ipv6_size(cd->conn_map_ipv6);
}

/*
 * npf_conndb_enqueue: atomically insert the connection into the
 * singly-linked list of "recent" connections.
 */
void
npf_conndb_enqueue(npf_conndb_t *cd, npf_conn_t *con)
{
	npf_conn_t *head;

	do {
		head = cd->cd_recent;
		con->c_next = head;
	} while (atomic_cas_ptr(&cd->cd_recent, head, con) != head);
}

/*
 * npf_conndb_dequeue: remove the connection from a singly-linked list
 * given the previous element; no concurrent writers are allowed here.
 */
void
npf_conndb_dequeue(npf_conndb_t *cd, npf_conn_t *con, npf_conn_t *prev)
{
	if (prev == NULL) {
		KASSERT(cd->cd_list == con);
		cd->cd_list = con->c_next;
	} else {
		prev->c_next = con->c_next;
	}
}

/*
 * npf_conndb_getlist: atomically take the "recent" connections and add
 * them to the singly-linked list of the connections.
 */
npf_conn_t *
npf_conndb_getlist(npf_conndb_t *cd)
{
	npf_conn_t *con, *prev;

	/*
	 * since gc might be in progress,
	 * tail might be invalid.
	 *
	 * find out new tail, if it's not valid
	 */
	if (!cd->cd_tail_valid) {
		con = cd->gc_list;
		prev = NULL;
		while (con) {
			prev = con;
			con = con->c_next;
		}
		npf_conndb_settail(cd, prev);
	}

	con = atomic_swap_ptr(&cd->cd_recent, NULL);
	if ((prev = cd->cd_tail) == NULL) {
		KASSERT(cd->cd_list == NULL);
		cd->cd_list = con;
	} else {
		KASSERT(prev->c_next == NULL);
		prev->c_next = con;
	}

	/* tail is not valid anymore,
	 * iterate till the end to find new tail
	 */
	cd->cd_tail_valid = false;

	return cd->cd_list;
}

/*
 * npf_conndb_settail: assign a new tail of the singly-linked list.
 */
void
npf_conndb_settail(npf_conndb_t *cd, npf_conn_t *con)
{
	KASSERT(con || cd->cd_list == NULL);
	KASSERT(!con || con->c_next == NULL);
	cd->cd_tail = con;
	cd->cd_tail_valid = true;
}

/*
 *
 */

#define CONNDB_NON_TCP_STATE 12
#define CONNDB_STATE_CNT (NPF_TCP_NSTATES + 1)

void
npf_conndb_print_state_summary(npf_conndb_t *cd, npf_print_cb_t print_line_cb,
		  void* context)
{
	uint32_t tcp_state_cnts[CONNDB_STATE_CNT];
	memset(&tcp_state_cnts[0], 0, sizeof(uint32_t) * CONNDB_STATE_CNT);

	npf_conn_t* conn = cd->cd_list;
	uint32_t state;

	/* interate conndb, count states */
	while (conn) {

		switch (conn->c_proto) {
			case IPPROTO_TCP:
				state = conn->c_state.nst_state;
				assert(state < NPF_TCP_NSTATES);
				tcp_state_cnts[state]++;
				break;

			default:
				tcp_state_cnts[CONNDB_NON_TCP_STATE]++;
				break;
		}

		conn = conn->c_next;
	}

	/* output tcp_state_cnt table using the callback function */
	int i;
	char msg[128];
	static const char* tcp_state_names[CONNDB_STATE_CNT] = {
		"closed\t",			/*	0 */
		"syn_sent",			/* 1 */
		"sim_syn_sent",	/* 2 */
		"syn_received",	/* 3 */
		"established",		/* 4 */
		"fin_sent",			/* 5 */
		"fin_received",	/* 6 */
		"close_wait",		/* 7 */
		"fin_wait",			/* 8 */
		"closing",			/* 9 */
		"last_ack",			/* 10 */
		"time_wait",		/* 11 */
		"non_tcp",			/* 12 */
	};

	sprintf(msg, "state\t\t\tcnt");
	print_line_cb(msg, context);
	sprintf(msg, "-------------------------");
	print_line_cb(msg, context);

	for (i=0; i<CONNDB_STATE_CNT; i++) {
		sprintf(msg, "%s:\t\t%u", tcp_state_names[i], tcp_state_cnts[i]);
		print_line_cb(msg, context);
	}
}