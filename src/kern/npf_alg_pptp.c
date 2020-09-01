/*	$NetBSD: npf_alg_pptp.c,v 1.02 2019/06/17 19:23:41 alexk99 Exp $	*/

/*-
 * Copyright (c) 2010 The NetBSD Foundation, Inc.
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
 * NPF ALG for PPTP translations.
 */

#ifdef _KERNEL
#include <sys/cdefs.h>
__KERNEL_RCSID(0,
		  "$NetBSD: npf_alg_pptp.c,v 1.00 2019/06/17 19:23:41 alexk99 Exp $");

#include <sys/param.h>
#include <sys/module.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/pfil.h>
#endif

#define __NPF_CONN_PRIVATE
#include "stand/cext.h"
#include "npf_impl.h"
#include "npf_conn.h"
#include "npf_alg_pptp.h"
#include "npf_pptp_gre.h"
#include "npf_print_debug.h"
#include "npf_conn.h"
#include "npf_portmap.h"
#include "npf_impl.h"
#include "npf_connkey.h"

MODULE(MODULE_CLASS_MISC, npf_alg_pptp, "npf");

#define	PPTP_SERVER_PORT	1723

static npf_alg_t *	alg_pptp_tcp = NULL	__read_mostly;
static npf_alg_t *	alg_pptp_gre = NULL	__read_mostly;

static npf_portmap_hash_t *alg_pptp_portmap_hash = NULL;

/* PPTP messages types */
#define PPTP_CTRL_MSG 1

/* Control message types */
#define PPTP_OUTGOING_CALL_REQUEST    7
#define PPTP_OUTGOING_CALL_REPLY      8
#define PPTP_CALL_CLEAR_REQUEST       12
#define PPTP_CALL_DISCONNECT_NOTIFY   13
#define PPTP_WAN_ERROR_NOTIFY         14

#define PPTP_OUTGOING_CALL_MIN_LEN   32

#define PPTP_MAGIC_COOKIE    0x1A2B3C4D

/* Maximum number of GRE connections
 * a host can establish to the same server
 */
#define PPTP_MAX_GRE_PER_CLIENT        4

/* PPTP ALG argument flags */
#define PPTP_ALG_FL_GRE_STATE_ESTABLISHED 0x1
#define PPTP_ALG_FL_ENTRY_IN_USE          0x2
/* server call-id has been seen */
#define PPTP_ALG_FL_SERVER_CALL_ID        0x4

struct pptp_msg_hdr {
	uint16_t len;
	uint16_t pptp_msg_type;
	uint32_t magic_cookie;
	uint16_t ctrl_msg_type;
	uint16_t rsvd0;
	uint16_t call_id;
}
__packed;

struct pptp_outgoing_call_req {
	struct pptp_msg_hdr hdr;
	uint16_t call_serial_nb;
	uint32_t min_bps;
	uint32_t max_bps;
	uint32_t bearer_type;
	uint16_t framing_type;
	/* etc */
}
__packed;

struct pptp_outgoing_call_reply {
	struct pptp_msg_hdr hdr;
	uint16_t peer_call_id;
	uint8_t  result_code;
	uint8_t  err_code;
	uint16_t cause_code;
	/* etc */
}
__packed;

#define PPTP_MIN_MSG_SIZE (MIN(\
	sizeof(struct pptp_outgoing_call_req) - sizeof(struct pptp_msg_hdr), \
	sizeof(struct pptp_outgoing_call_reply) - sizeof(struct pptp_msg_hdr)))

/*
 * pptp gre connection
 */
struct pptp_gre_slot {
	union {
		struct {
			/* all call id values use network byte order */
			struct pptp_gre_context ctx; /* client and server call ids*/
			uint16_t orig_client_call_id; /* original client call id */
			uint16_t flags;
		};

		uint64_t u64;
	};
};

/*
 * TCP PPTP NAT ALG datum.
 * Associated with a tcp connection via
 * npf_nat::nt_alg_arg
 */
struct pptp_alg_arg
{
	struct pptp_gre_slot gre_con_slots[PPTP_MAX_GRE_PER_CLIENT];
	kmutex_t	lock;
};

static inline void
npfa_pptp_tcp_conn_lock(struct pptp_alg_arg *gre_conns)
{
	mutex_enter(&gre_conns->lock);
}

static inline void
npfa_pptp_tcp_conn_unlock(struct pptp_alg_arg *gre_conns)
{
	mutex_exit(&gre_conns->lock);
}

/*
 * npfa_icmp_match: matching inspector determines ALG case and associates
 * our ALG with the NAT entry.
 */
static bool
npfa_pptp_tcp_match(npf_cache_t *npc, npf_nat_t *nt, int di)
{
	const uint16_t proto = npc->npc_proto;

	KASSERT(npf_iscached(npc, NPC_IP46));

	/* note: only the outbound NAT is supported */
	if (di != PFIL_OUT || proto != IPPROTO_TCP || npc->npc_l4.tcp == NULL ||
			  npc->npc_l4.tcp->th_dport != htons(PPTP_SERVER_PORT))
		return false;

	/* Associate ALG with translation entry. */
	npf_nat_setalg(nt, alg_pptp_tcp, 0);
	return true;
}

/*
 *
 */
static int
npfa_pptp_gre_establish_gre_conn(npf_cache_t *npc, int di,
		  struct pptp_gre_slot *gre_con, npf_nat_t *pptp_tcp_nt)
{
	npf_conn_t *con = NULL;
	int ret;

	NPF_DPRINTFCL(NPF_DC_PPTP_ALG, 50,
			  "establishing a new pptp gre connection: client call_id %hu, "
			  "server call_id %hu, orig client call_id %hu, flags %hu\n",
			  ntohs(gre_con->ctx.client_call_id),
			  ntohs(gre_con->ctx.server_call_id),
			  ntohs(gre_con->orig_client_call_id),
			  gre_con->flags);

	/* establish new gre connection state */
	if (npf_conn_establish(npc, di, true, &con) != 0) {
		NPF_DPRINTFCL(NPF_DC_PPTP_ALG, 50,
				  "failed to establish pptp gre connection\n");
		return ENOMEM;
	}
	else {
		NPF_DPRINTFCL(NPF_DC_PPTP_ALG, 50,
				  "new pptp gre connection is established, flags %u\n",
				  con->c_flags);
	}

	NPF_HEX_DUMPCL(NPF_DC_PPTP_ALG, 50,
			  "gre forw key",
			  ((struct npf_conn_ipv4 *)con)->c_forw_entry.ck_key,
			  NPF_CONN_IPV4_KEYLEN_WORDS * 4);
	NPF_HEX_DUMPCL(NPF_DC_PPTP_ALG, 50,
			  "gre back key",
			  ((struct npf_conn_ipv4 *)con)->c_back_entry.ck_key,
			  NPF_CONN_IPV4_KEYLEN_WORDS * 4);

	/*
	 * Create a new nat entry for created GRE connection.
	 * Use the same nat policy as the parent PPTP TCP control connection uses.
	 * Associate created nat entry with the gre connection.
	 */
	ret = npf_nat_share_policy(npc, con, pptp_tcp_nt);
	if (ret) {
		npf_conn_expire(con);
		npf_conn_release(con);
		return ret;
	}

	/* associate GRE ALG with the gre connection */
	npf_nat_setalg(con->c_nat, alg_pptp_gre, (uintptr_t)gre_con->u64);

	NPF_DPRINTFCL(NPF_DC_PPTP_ALG, 50,
			  "new pptp gre connection's nat %p\n", con->c_nat);

	/* make gre connection active and pass */
	npf_conn_setpass(con, NULL);
	npf_conn_release(con);

	gre_con->flags |= PPTP_ALG_FL_GRE_STATE_ESTABLISHED;
	return 0;
}

static uint16_t
npfa_translated_call_id_get(uint32_t ip)
{
	in_port_t port;
	npf_portmap_t *pm;

	pm = npf_portmap_get(alg_pptp_portmap_hash, ip);
	port = npf_portmap_getport(pm);

	NPF_DPRINTFCL(NPF_DC_PPTP_ALG, 50,
			  "pptp alg: get call_id %hu from "
			  "the pormap ip %u\n", port, ip);

	return (uint16_t)port;
}

static void
npfa_translated_call_id_put(uint32_t ip, uint16_t call_id)
{
	npf_portmap_t *pm;

	pm = npf_portmap_get(alg_pptp_portmap_hash, ip);
	npf_portmap_putport(pm, (in_port_t)call_id);

	NPF_DPRINTFCL(NPF_DC_PPTP_ALG, 50,
			  "pptp alg: put call_id %hu to "
			  "the pormap ip %u\n", call_id, ip);
}

/*
 * Free the gre slot and expire the gre connection associated with it.
 */
static void
npfa_pptp_gre_con_free(npf_t *npf, struct pptp_gre_slot *gre_slot,
		  uint32_t client_ip, uint32_t server_ip)
{
	NPF_DPRINTFCL(NPF_DC_PPTP_ALG, 50,
			  "expire gre con: orig client call_id %hu, client call_id %hu, "
			  "server call_id %hu, flags %hu, cl %u, srv %u\n",
			  ntohs(gre_slot->orig_client_call_id),
			  ntohs(gre_slot->ctx.client_call_id),
			  ntohs(gre_slot->ctx.server_call_id),
			  gre_slot->flags, client_ip, server_ip);

	/* expire the gre connection associated with the slot */
	if (gre_slot->flags & PPTP_ALG_FL_GRE_STATE_ESTABLISHED) {
		uint16_t key[NPF_CONN_IPV4_KEYLEN_WORDS * 2];
		npf_conn_t *gre_con;
		bool forw;

		/* init a forward gre key */
		npf_conn_init_ipv4_key(key, IPPROTO_GRE, gre_slot->ctx.server_call_id, 0,
				  client_ip, server_ip);

		/* lookup for the associated pptp gre connection */
		gre_con = npf_conndb_lookup(npf->conn_db, &key,
				  NPF_CONN_IPV4_KEYLEN_WORDS, &forw);
		if (gre_con != NULL) {
			/* mark the gre connection as expired.
			 * note: translated call-id will be put back to the portmap
			 * by gre connection destructor
			 */
			npf_conn_expire(gre_con);

			NPF_DPRINTFCL(NPF_DC_PPTP_ALG, 50,
				  "pptp control connection: expire associated gre conn "
				  "server call_id %hu\n", ntohs(gre_slot->ctx.server_call_id));
		}
		else {
			NPF_DPRINTFCL(NPF_DC_PPTP_ALG, 50,
				  "pptp control connection: associated gre conn not found, "
				  "server call_id %hu\n", ntohs(gre_slot->ctx.server_call_id));
		}

		gre_slot->flags &= ~PPTP_ALG_FL_GRE_STATE_ESTABLISHED;
	}
	else if (gre_slot->ctx.client_call_id != 0) {
		/* return translated call-id value back to the portmap */
		npfa_translated_call_id_put(server_ip, gre_slot->ctx.client_call_id);
	}

	/* free gre slot in the parent tcp connection nat arg */
	gre_slot->flags &= ~PPTP_ALG_FL_ENTRY_IN_USE;

	return;
}

/*
 * Allocate and init pptp alg arg
 */
static struct pptp_alg_arg *
npfa_pptp_alg_arg_init(void)
{
	int i;
	struct pptp_alg_arg *alg_arg;

	/* allocate */
	alg_arg = kmem_intr_zalloc(sizeof(struct pptp_alg_arg), KM_SLEEP);
	if (alg_arg == NULL)
		return NULL;

	mutex_init(&alg_arg->lock, MUTEX_DEFAULT, IPL_SOFTNET);

	return alg_arg;
}

/*
 * Destroy pptp alg arg
 */
static void
npfa_pptp_alg_arg_fini(struct pptp_alg_arg *gre_conns)
{
	mutex_destroy(&gre_conns->lock);
	kmem_intr_free(gre_conns, sizeof(struct pptp_alg_arg));
}

/*
 * Init and setup new alg arg
 */
static struct pptp_alg_arg *
npfa_pptp_alg_arg_alloc(npf_nat_t *nt)
{
	struct pptp_alg_arg *res_alg_arg;
	struct pptp_alg_arg *new_alg_arg;

	new_alg_arg = npfa_pptp_alg_arg_init();
	if (new_alg_arg == NULL)
		return NULL;

	res_alg_arg = npf_nat_cas_alg_arg(nt, (uintptr_t)NULL,
			  (uintptr_t)new_alg_arg);
	if (res_alg_arg != NULL) {
		/* someone else has already allocated arg before us */
		npfa_pptp_alg_arg_fini(new_alg_arg);
		return res_alg_arg;
	}

	return new_alg_arg;
}

/*
 * Find a free slot or reuse one with the same orig_client_call_id.
 * There must be only one slot with the same orig_client_call_id.
 *
 * Result:
 *   NULL - no empty slots or slot to reuse
 *   otherwise - a reference to a slot marked as used
 *      and into which client_call_id and trans_client_call_id are written
 */
static struct pptp_gre_slot *
npfa_pptp_gre_slot_lookup_and_use(npf_cache_t *npc,
		  struct pptp_alg_arg *gre_conns,
		  uint16_t client_call_id, uint16_t trans_client_call_id)
{
	struct pptp_gre_slot *slot, *empty_slot, old_reused_slot, new_slot;
	bool reuse_slot;

	reuse_slot = false;
	empty_slot = NULL;

	npfa_pptp_tcp_conn_lock(gre_conns);

	/* scan all slots to ensure that there is no one using the call_id */
	for (int i = 0; i < PPTP_MAX_GRE_PER_CLIENT; i++) {
		slot = &gre_conns->gre_con_slots[i];
		/* if call_id is already in use by a slot, then
		 * expire associated GRE connection and reuse the slot
		 */
		if ((slot->flags & PPTP_ALG_FL_ENTRY_IN_USE) == 0) {
			/* empty slot */
			empty_slot = slot;
		}
		else if (slot->orig_client_call_id == client_call_id) {
			reuse_slot = true;
			old_reused_slot.u64 = slot->u64;
			break;
		}
	}

	/* use empty slot or reuse a slot with the same client_call_id */
	if (reuse_slot || empty_slot != NULL) {
		if (!reuse_slot)
			slot = empty_slot;

		new_slot.orig_client_call_id = client_call_id;
		new_slot.ctx.client_call_id = trans_client_call_id;
		new_slot.flags = PPTP_ALG_FL_ENTRY_IN_USE;

		slot->u64 = new_slot.u64;
	}

	npfa_pptp_tcp_conn_unlock(gre_conns);

	if (reuse_slot) {
		npfa_pptp_gre_con_free(npc->npc_ctx, &old_reused_slot,
				  npc->npc_ips[NPF_SRC]->word32[0],
				  npc->npc_ips[NPF_DST]->word32[0]);
		return slot;
	}

	return empty_slot;
}

/*
 *
 */
static struct pptp_gre_slot *
npfa_pptp_gre_slot_lookup_with_server_call_id(struct pptp_alg_arg *arg,
		  uint16_t server_call_id)
{
	int i;
	struct pptp_gre_slot *gre_con;

	for (i = 0; i < PPTP_MAX_GRE_PER_CLIENT; i++) {
		gre_con = &arg->gre_con_slots[i];

		if ((gre_con->flags &
				  (PPTP_ALG_FL_ENTRY_IN_USE | PPTP_ALG_FL_SERVER_CALL_ID)) ==
				  (PPTP_ALG_FL_ENTRY_IN_USE | PPTP_ALG_FL_SERVER_CALL_ID) &&
				  gre_con->ctx.server_call_id == server_call_id)
			return gre_con;
	}

	return NULL;
}

/*
 *
 */
static struct pptp_gre_slot *
npfa_pptp_gre_slot_lookup_with_client_call_id(struct pptp_alg_arg *arg,
		  uint16_t client_call_id)
{
	int i;
	struct pptp_gre_slot *gre_con;

	for (i = 0; i < PPTP_MAX_GRE_PER_CLIENT; i++) {
		gre_con = &arg->gre_con_slots[i];

		if ((gre_con->flags & PPTP_ALG_FL_ENTRY_IN_USE) != 0 &&
				  gre_con->ctx.client_call_id == client_call_id)
			return gre_con;
	}

	return NULL;
}

/*
 * PPTP TCP control connection ALG translator.
 * It rewrites Call ID in the Outgoing-Call-Request
 * message and Peer Call ID in the Outgoing-Call-Reply message.
 */
static bool
npfa_pptp_tcp_translate(npf_cache_t *npc, npf_nat_t *nt, bool forw)
{
	uint16_t old_call_id;
	uint16_t trans_client_call_id;
	uint16_t orig_client_call_id;
	in_port_t o_port;
	uint32_t tcp_hdr_size;
	nbuf_t *nbuf;
	struct tcphdr *tcp;
	struct pptp_msg_hdr *pptp;
	struct pptp_outgoing_call_reply *pptp_call_reply;
	struct pptp_alg_arg *gre_conns;
	struct pptp_gre_slot *gre_slot;
	npf_addr_t *o_addr;
	uint32_t ip;
	npf_cache_t gre_npc;

	/* only ipv4 is supported so far */
	if (!(npf_iscached(npc, NPC_IP4) && npf_iscached(npc, NPC_TCP) &&
			  (npc->npc_l4.tcp->th_dport == htons(PPTP_SERVER_PORT) ||
			  npc->npc_l4.tcp->th_sport == htons(PPTP_SERVER_PORT))))
		return false;

	nbuf = npc->npc_nbuf;
	tcp = npc->npc_l4.tcp;
	tcp_hdr_size = tcp->th_off << 2;
	nbuf_reset(nbuf);

	pptp = nbuf_advance(nbuf, npc->npc_hlen + tcp_hdr_size,
			  sizeof(struct pptp_msg_hdr) + PPTP_MIN_MSG_SIZE);
	if (pptp == NULL)
		return false;

	if (pptp->pptp_msg_type != htons(PPTP_CTRL_MSG) ||
			  pptp->len < htons(PPTP_OUTGOING_CALL_MIN_LEN) ||
			  pptp->magic_cookie != htonl(PPTP_MAGIC_COOKIE))
		return false;

	/* get or allocate alg arg (gre connections) */
	gre_conns = (struct pptp_alg_arg *)npf_nat_get_alg_arg(nt);
	if (gre_conns == NULL) {
		gre_conns = npfa_pptp_alg_arg_alloc(nt);
		if (gre_conns == NULL)
			return false;
	}

	switch (ntohs(pptp->ctrl_msg_type)) {
	case PPTP_OUTGOING_CALL_REQUEST:
		if (pptp->len < sizeof(struct pptp_outgoing_call_req))
			return false;

		/* get translated call id value.
		 * it should be a unique value within the scope
		 * of all pptp connection distinated to the same server.
		 * Note: it's better to use the source address scope, but
		 * the translated source ip address is not known at this point,
		 * since alg->translate() executed before the normal NAT translation.
		 */
		ip = npc->npc_ips[NPF_DST]->word32[0]; /* pptp server ip */
		trans_client_call_id = npfa_translated_call_id_get(ip);
		if (trans_client_call_id == 0)
			return false;

		/* lookup for an empty gre slot or
		 * reuse one with the same original call_id
		 */
		gre_slot = npfa_pptp_gre_slot_lookup_and_use(npc, gre_conns,
				  pptp->call_id, trans_client_call_id);
		if (gre_slot == NULL) {
			/* all entries are in use */
			npfa_translated_call_id_put(ip, trans_client_call_id);
			return false;
		}

		/* rewrite client call id */
		old_call_id = pptp->call_id;
		pptp->call_id = trans_client_call_id;
		tcp->check = npf_fixup16_cksum(tcp->check, old_call_id,
				  trans_client_call_id);
		break;

	case PPTP_OUTGOING_CALL_REPLY:
		if (pptp->len < sizeof(struct pptp_outgoing_call_reply))
			return false;
		pptp_call_reply = (struct pptp_outgoing_call_reply *)pptp;

		/* lookup a gre connection */
		npfa_pptp_tcp_conn_lock(gre_conns);
		gre_slot = npfa_pptp_gre_slot_lookup_with_client_call_id(gre_conns,
				  pptp_call_reply->peer_call_id);
		/* slot is not found or call reply message has been already received */
		if (gre_slot == NULL ||
		    (gre_slot->flags & PPTP_ALG_FL_SERVER_CALL_ID) != 0) {
			npfa_pptp_tcp_conn_unlock(gre_conns);
			return false;
		}

		/* save server call id */
		gre_slot->ctx.server_call_id = pptp_call_reply->hdr.call_id;
		gre_slot->flags |= PPTP_ALG_FL_SERVER_CALL_ID;

		/*
		 * Client and server call ids have been seen,
		 * create new gre connection state entry
		 */

		/* create pptp gre context cache */
		memcpy(&gre_npc, npc, sizeof(npf_cache_t));
		gre_npc.npc_proto = IPPROTO_GRE;
		gre_npc.npc_info = NPC_IP46 | NPC_LAYER4 | NPC_ALG_PPTP_GRE_CTX;
		gre_npc.npc_l4.hdr = (void *)&gre_slot->ctx;
		/* setup ip addresses */
		npf_nat_getorig(nt, &o_addr, &o_port);
		gre_npc.npc_ips[NPF_SRC] = o_addr;
		gre_npc.npc_ips[NPF_DST] = npc->npc_ips[NPF_SRC];
		/* establish gre connection state and associate nat */
		npfa_pptp_gre_establish_gre_conn(&gre_npc, PFIL_OUT, gre_slot, nt);

		orig_client_call_id = gre_slot->orig_client_call_id;
		npfa_pptp_tcp_conn_unlock(gre_conns);

		/* rewrite peer сall id */
		old_call_id = pptp_call_reply->peer_call_id;
		pptp_call_reply->peer_call_id = orig_client_call_id;
		tcp->check = npf_fixup16_cksum(tcp->check, old_call_id,
				  orig_client_call_id);
		break;

	case PPTP_CALL_DISCONNECT_NOTIFY:
		if (pptp->len < sizeof(struct pptp_msg_hdr))
			return false;
		npf_nat_getorig(nt, &o_addr, &o_port);

		/* lookup for a gre connection entry */
		npfa_pptp_tcp_conn_lock(gre_conns);
		gre_slot = npfa_pptp_gre_slot_lookup_with_server_call_id(gre_conns,
				  pptp->call_id);
		if (gre_slot == NULL) {
			npfa_pptp_tcp_conn_unlock(gre_conns);
			return false;
		}

		npfa_pptp_gre_con_free(npc->npc_ctx, gre_slot, o_addr->word32[0],
				  npc->npc_ips[NPF_SRC]->word32[0]);
		npfa_pptp_tcp_conn_unlock(gre_conns);
		break;

	case PPTP_WAN_ERROR_NOTIFY:
		if (pptp->len < sizeof(struct pptp_msg_hdr))
			return false;

		npfa_pptp_tcp_conn_lock(gre_conns);
		gre_slot = npfa_pptp_gre_slot_lookup_with_client_call_id(gre_conns,
				  pptp->call_id);
		if (gre_slot == NULL) {
			npfa_pptp_tcp_conn_unlock(gre_conns);
			return false;
		}

		orig_client_call_id = gre_slot->orig_client_call_id;
		npfa_pptp_tcp_conn_unlock(gre_conns);

		/* rewrite */
		old_call_id = pptp->call_id;
		pptp->call_id = orig_client_call_id;
		tcp->check = npf_fixup16_cksum(tcp->check, old_call_id,
				  orig_client_call_id);
		break;

	default:
		return false;
	}

	return true;
}

/*
 *
 */
static void
npfa_pptp_tcp_destroy(npf_t *npf, npf_conn_t *con)
{
	struct npf_conn_ipv4 *con_ipv4;
	struct pptp_gre_slot *gre_con;
	struct pptp_alg_arg *alg_arg;
	uint32_t client_ip, server_ip;
	int i;

	NPF_DPRINTFCL(NPF_DC_PPTP_ALG, 50,
			  "pptp tcp alg destroy a tcp connection %p\n", con);

	alg_arg = (struct pptp_alg_arg *)npf_nat_get_alg_arg(con->c_nat);

	/* only ipv4 is supported */
	if ((con->c_flags & CONN_IPV4) == 0 || alg_arg == NULL)
		return;

	con_ipv4 = (struct npf_conn_ipv4 *)con;
	client_ip = con_ipv4->c_forw_entry.ck_key[2];
	server_ip = con_ipv4->c_forw_entry.ck_key[3];

	NPF_DPRINTFCL(NPF_DC_PPTP_ALG, 50,
			  "pptp tcp alg destroy a tcp connection %p, "
			  "client ip %u, server ip %u\n",
			  con, client_ip, server_ip);

	for (i = 0; i < PPTP_MAX_GRE_PER_CLIENT; i++) {
		gre_con = &alg_arg->gre_con_slots[i];
		if ((gre_con->flags & PPTP_ALG_FL_ENTRY_IN_USE) != 0)
			npfa_pptp_gre_con_free(npf, gre_con, client_ip, server_ip);
	}

	npfa_pptp_alg_arg_fini(alg_arg);
}

/*
 * Destroy PPTP TCP nat argument.
 * It will expire all associated gre connections.
 */
static void
npfa_pptp_gre_destroy(npf_t *npf, npf_conn_t *con)
{
	struct pptp_gre_slot gre_slot;
	npf_nat_t *nt;
	struct npf_conn_ipv4 *con_ipv4;
	uint32_t server_ip;

	nt = con->c_nat;

	/* only ipv4 is supported */
	if ((con->c_flags & CONN_IPV4) == 0 || nt == NULL)
		return;

	con_ipv4 = (struct npf_conn_ipv4 *)con;
	server_ip = con_ipv4->c_forw_entry.ck_key[3];

	gre_slot.u64 = (uint64_t)npf_nat_get_alg_arg(nt);
	if (gre_slot.ctx.client_call_id != 0)
		npfa_translated_call_id_put(server_ip, gre_slot.ctx.client_call_id);
}

/*
 * PPTP GRE ALG translator.
 */
static bool
npfa_pptp_gre_translate(npf_cache_t *npc, npf_nat_t *nt, bool forw)
{
	nbuf_t *nbuf = npc->npc_nbuf;
	struct pptp_gre_hdr *gre;
	struct pptp_gre_slot gre_con;

	if (forw || !npf_iscached(npc, NPC_IP4 | NPC_ALG_PPTP_GRE) ||
			  npc->npc_proto != IPPROTO_GRE)
		return false;

	nbuf_reset(nbuf);
	gre = nbuf_advance(nbuf, npc->npc_hlen, sizeof(struct pptp_gre_hdr));
	if (gre == NULL)
		return false;

	gre_con.u64 = (uint64_t)npf_nat_get_alg_arg(nt);

	KASSERT(gre->call_id == gre_con.ctx.client_call_id);
	NPF_DPRINTFCL(NPF_DC_PPTP_ALG, 60,
			  "gre call id translated %hu -> %hu, forw %d\n",
			  ntohs(gre->call_id), ntohs(gre_con.orig_client_call_id), forw);

	gre->call_id = gre_con.orig_client_call_id;
	return true;
}

/*
 * npf_alg_icmp_{init,fini,modcmd}: ICMP ALG initialization, destruction
 * and module interface.
 */

static int
npf_alg_pptp_init(npf_t *npf)
{
	static const npfa_funcs_t pptp_tcp = {
		.match     = npfa_pptp_tcp_match,
		.translate = npfa_pptp_tcp_translate,
		.inspect   = NULL,
		.destroy   = npfa_pptp_tcp_destroy,
	};

	static const npfa_funcs_t pptp_gre = {
		.match     = NULL,
		.translate = npfa_pptp_gre_translate,
		.inspect   = NULL,
		.destroy   = npfa_pptp_gre_destroy,
	};

	if (alg_pptp_portmap_hash == NULL)
		alg_pptp_portmap_hash = npf_portmap_init();
	if (alg_pptp_portmap_hash == NULL)
		return ENOMEM;

	if (alg_pptp_tcp == NULL)
		alg_pptp_tcp = npf_alg_register(npf, "pptp_tcp", &pptp_tcp);
	if (alg_pptp_tcp == NULL)
		return ENOMEM;

	if (alg_pptp_gre == NULL)
		alg_pptp_gre = npf_alg_register(npf, "pptp_gre", &pptp_gre);
	if (alg_pptp_gre == NULL) {
		npf_alg_unregister(npf, alg_pptp_tcp);
		return ENOMEM;
	} else {
		return 0;
	}
}

static int
npf_alg_pptp_fini(npf_t *npf)
{
	KASSERT(alg_pptp_tcp != NULL);
	KASSERT(alg_pptp_gre != NULL);
	npf_alg_unregister(npf, alg_pptp_tcp);
	return npf_alg_unregister(npf, alg_pptp_gre);
}

int
npf_alg_pptp_modcmd(modcmd_t cmd, void *arg)
{
	switch (cmd) {
	case MODULE_CMD_INIT:
		return npf_alg_pptp_init((npf_t *)arg);
	case MODULE_CMD_FINI:
		return npf_alg_pptp_fini((npf_t *)arg);
	case MODULE_CMD_AUTOUNLOAD:
		return EBUSY;
	default:
		return ENOTTY;
	}
	return 0;
}
