/*	$NetBSD: npf_handler.c,v 1.33 2014/07/23 01:25:34 rmind Exp $	*/

/*-
 * Copyright (c) 2009-2013 The NetBSD Foundation, Inc.
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
 * NPF packet handler.
 *
 * Note: pfil(9) hooks are currently locked by softnet_lock and kernel-lock.
 */

#ifdef _KERNEL
#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: npf_handler.c,v 1.33 2014/07/23 01:25:34 rmind Exp $");

#include <sys/types.h>
#include <sys/param.h>

#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <net/if.h>
#include <net/pfil.h>
#include <sys/socketvar.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif

#include "npf_impl.h"
#include "npf_conn.h"
#include "likely.h"
#include "npf_connkey.h"

static bool		pfil_registered = false;
static pfil_head_t *	npf_ph_if = NULL;
static pfil_head_t *	npf_ph_inet = NULL;
static pfil_head_t *	npf_ph_inet6 = NULL;

#if defined(_NPF_STANDALONE)
#define	m_freem(m)		npf->mbufops->free(m)
#define	m_clear_flag(m,f)
#else
#define	m_clear_flag(m,f)	(m)->m_flags &= ~(f)
#endif

#ifndef INET6
#define ip6_reass_packet(x, y)	ENOTSUP
#endif

static int
npf_reassembly(npf_t *npf, npf_cache_t *npc, struct mbuf **mp)
{
	nbuf_t *nbuf = npc->npc_nbuf;
	int error = EINVAL;

	/* Reset the mbuf as it may have changed. */
	*mp = nbuf_head_mbuf(nbuf);
	nbuf_reset(nbuf);

	if (npf_iscached(npc, NPC_IP4)) {
		struct ip *ip = nbuf_dataptr(nbuf);
		error = ip_reass_packet(mp, ip);
	} else if (npf_iscached(npc, NPC_IP6)) {
		/*
		 * Note: ip6_reass_packet() offset is the start of
		 * the fragment header.
		 */
		error = ip6_reass_packet(mp, npc->npc_hlen);
		if (error && *mp == NULL) {
			memset(nbuf, 0, sizeof(nbuf_t));
		}
	}
	if (error) {
		npf_stats_inc(npf, npc, NPF_STAT_REASSFAIL);
		return error;
	}
	if (*mp == NULL) {
		/* More fragments should come. */
		npf_stats_inc(npf, npc, NPF_STAT_FRAGMENTS);
		return 0;
	}

	/*
	 * Reassembly is complete, we have the final packet.
	 * Cache again, since layer 4 data is accessible now.
	 */
	nbuf_init(npf, nbuf, *mp, nbuf->nb_ifp);
	npc->npc_info = 0;

	if (npf_cache_all(npc) & NPC_IPFRAG) {
		return EINVAL;
	}
	npf_stats_inc(npf, npc, NPF_STAT_REASSEMBLY);
	return 0;
}

#define MARK_PKT_DESTROYED(bitfld, n) bitfld = bitfld | (1 << n)
#define IS_PKT_DESROYED(bitfld, n) (bitfld & (1 << n))


#define PH_STEP_PASS 5
#define PH_STEP_BLOCK 6
#define PH_STEP_OUT 7

#define max_vec_size 32

static inline void
prefetch0(const volatile void *p)
{
	asm volatile ("prefetcht0 %[p]" : : [p] "m" (*(const volatile char *)p));
}

typedef void *	(*mbuf_getdata_cb_t)(const struct mbuf *);

/*
 * npf_packet_handler: main packet handling routine for layer 3.
 *
 * Note: packet flow and inspection logic is in strict order.
 */
__dso_public bool
npf_packet_handler_vec(npf_t *npf, const uint8_t vec_size, struct mbuf **m_v,
		  uint8_t** mbuf_data_ptr_v,
		  ifnet_t **ifp_v, uint8_t* l2_size_v, int di, __time_t sec,
		  uint8_t cpu_thread, uint16_t* ret_v,
		  uint64_t* out_destroyed_packets_bitfld)
{
	nbuf_t nbuf_v[max_vec_size];
	npf_cache_t npc_v[max_vec_size];
	npf_conn_t* con_v[max_vec_size];
	npf_rule_t* rl_v[max_vec_size];
	npf_rproc_t* rp_v[max_vec_size];
	int error_v[max_vec_size];
	int retfl_v[max_vec_size];
	int decision_v[max_vec_size];
	uint8_t next_step_v[max_vec_size];
	uint8_t step = 1;
	int i;

	uint64_t destroyed_packets_bitfld = 0;

	/* QSBR checkpoint. */
	pserialize_checkpoint(npf->qsbr);
	KASSERT(ifp != NULL);

	dprintf("npf_packet_handler\n");

	/*
	 * when all packets are ok, which is very likely,
	 * set errors to false, indicating that there is no need no
	 * to check return values for each packet
	 */
	bool errors = false;
	memset(next_step_v, 0, max_vec_size);

	/*
	 * step 1
	 * Initialize npf cache
	 */
	npf_cache_t* npc = npc_v;
	nbuf_t* nbuf = nbuf_v;
	for (i=0; i<vec_size; i++,npc++,nbuf++) {
		/* init next_step
		 * 0 means than next step is undefined (not used)
		 */
		dprintf(" -- step %d -- \n", step);

		struct mbuf* mp = m_v[i];
		uint8_t l2_size = l2_size_v[i];
		ifnet_t *ifp = ifp_v[i];

		npc->sec = sec;

		/*
		 * Initialise packet information cache.
		 * Note: it is enough to clear the info bits.
		 */
		npc->npc_ctx = npf;
		nbuf_init2(npf, nbuf, mp, l2_size, ifp, mbuf_data_ptr_v[i]);
		npc->npc_nbuf = nbuf;
		npc->npc_info = 0;
		npc->cpu_thread = cpu_thread;

		decision_v[i] = NPF_DECISION_BLOCK;
		error_v[i] = 0;
		retfl_v[i] = 0;
		rp_v[i] = NULL;

		/* Cache everything.  Determine whether it is an IP fragment. */
		if (unlikely(npf_cache_all(npc) & NPC_IPFRAG)) {
			/*
			 * Pass to IPv4 or IPv6 reassembly mechanism.
			 */
			int error = npf_reassembly(npf, npc, &mp);
			if (unlikely(error)) {
				con_v[i] = NULL;
				/* goto out */
				next_step_v[i] = PH_STEP_OUT;
				continue;
			}
			if (mp == NULL) {
				MARK_PKT_DESTROYED(destroyed_packets_bitfld, i);
				/* More fragments should come; return. */
				ret_v[i] = 0;
				continue;
			}
		}
	}

//	*out_destroyed_packets_bitfld = destroyed_packets_bitfld;
//	return errors;

	step++;

	/*
	 * step 2.0
	 * Connection lookup part1
	 *
	 * Lookup connection and prefetch it
	 */
	{
		uint32_t conn_key_buf[NPF_CONN_IPV6_KEYLEN_WORDS * max_vec_size];
		uint64_t hashval_v[max_vec_size];

		uint64_t* hv_ptr = hashval_v;
		npf_conn_t** con_ptr = con_v;
		uint32_t* conn_key_ptr = conn_key_buf;
		bool conn_found = false;

		npc = npc_v;
		for (i=0; i<vec_size; i++,npc++,hv_ptr++,con_ptr++,
				  conn_key_ptr+=NPF_CONN_IPV6_KEYLEN_WORDS) {
			/* skip freed packets or handle goto */
			if (IS_PKT_DESROYED(destroyed_packets_bitfld, i) ||
					  next_step_v[i] > step)
				continue;

			dprintf(" -- step %d .0 -- \n", step);

			/* Inspect the list of connections (if found, acquires a reference). */

			/* todo: split inspect process into two steps: find and prefetch,
			 * then inspect
			 */
			*con_ptr = npf_conn_inspect_part1(npc, conn_key_ptr, di, &error_v[i],
					  hv_ptr);
			if (unlikely(error_v[i])) {
				errors = true;
			}
			else {
				if (*con_ptr != NULL) {
					prefetch0(*con_ptr);
					conn_found = true;
				}
			}
		}

		/*
		 * step 2.1
		 * Connection lookup part2
		 * Inspect the found connection.
		 */
		if (conn_found) {
			npc = npc_v;
			hv_ptr = hashval_v;
			con_ptr = con_v;
			conn_key_ptr = conn_key_buf;

			for (i=0; i<vec_size; i++,npc++,hv_ptr++,con_ptr++,
					  conn_key_ptr+=NPF_CONN_IPV6_KEYLEN_WORDS) {
				/* skip freed packets or handle goto */
				if (IS_PKT_DESROYED(destroyed_packets_bitfld, i) ||
						  next_step_v[i] > step)
					continue;

				dprintf(" -- step %d .1 -- \n", step);

				/* Inspect the list of connections (if found, acquires a reference). */

				/* todo: split inspect process into two steps: find and prefetch,
				 * then inspect
				 */
				if (*con_ptr != NULL) {
					*con_ptr = npf_conn_inspect_part2(*con_ptr, npc, conn_key_ptr,
							  *hv_ptr, di);
				}
			}
		}
	}

	step++;

	/*
	 * step 3
	 */
	npc = &npc_v[0];
	npf_conn_t** con = &con_v[0];
	for (i=0; i<vec_size; i++,npc++,con++) {
		/* skip destroyed packets or handle goto */
		if (IS_PKT_DESROYED(destroyed_packets_bitfld, i) || next_step_v[i] > step)
			continue;

		dprintf(" -- step %d -- \n", step);

		/* If "passing" connection found - skip the ruleset inspection. */
		if (*con && npf_conn_pass(*con, &rp_v[i])) {
			npf_stats_inc(npf, npc, NPF_STAT_PASS_CONN);
			KASSERT(error_v[i] == 0);
			dprintf ("npf: pass 1\n");
			/* goto pass */
			next_step_v[i] = PH_STEP_PASS;
			continue;
		}
		if (unlikely(error_v[i])) {
			if (error_v[i] == ENETUNREACH) {
				dprintf2("npf: block 1: ENETUNREACH\n");
				next_step_v[i] = PH_STEP_BLOCK;
				continue;
			}
			next_step_v[i] = PH_STEP_OUT;
			continue;
		}

		/* Acquire the lock, inspect the ruleset using this packet. */
		int slock = npf_config_read_enter();
		npf_ruleset_t *rlset = npf_config_ruleset(npf);

		dprintf("conn: %p\n", *con);
		dprintf("rule inspect\n");

		npf_rule_t* rl = npf_ruleset_inspect(npc, rlset, di, NPF_LAYER_3);
		rl_v[i] = rl;
		if (unlikely(rl == NULL)) {
			const bool pass = npf_default_pass(npf);
			npf_config_read_exit(slock);

			if (pass) {
				npf_stats_inc(npf, npc, NPF_STAT_PASS_DEFAULT);
				dprintf ("npf: pass 2\n");
				next_step_v[i] = PH_STEP_PASS;
				continue;
			}
			npf_stats_inc(npf, npc, NPF_STAT_BLOCK_DEFAULT);
			dprintf2("npf: block 2: block_default\n");
			next_step_v[i] = PH_STEP_BLOCK;
			continue;
		}

		/*
		 * Get the rule procedure (acquires a reference) for association
		 * with a connection (if any) and execution.
		 */
		KASSERT(rp_v[i] == NULL);
		rp_v[i] = npf_rule_getrproc(rl);

		dprintf("rule conclude\n");

		/* Conclude with the rule and release the lock. */
		int error = npf_rule_conclude(rl, &retfl_v[i]);
		npf_config_read_exit(slock);

		if (error) {
			npf_stats_inc(npf, npc, NPF_STAT_BLOCK_RULESET);
			dprintf2("npf: block 3: block_ruleset\n");
			next_step_v[i] = PH_STEP_BLOCK;
			continue;
		}
		npf_stats_inc(npf, npc, NPF_STAT_PASS_RULESET);
	}

	step++;

	/*
	 * step 4
	 */
	npc = &npc_v[0];
	con = &con_v[0];
	for (i=0; i<vec_size; i++,npc++,con++) {
		/* skip destroyed packets or handle goto */
		if (IS_PKT_DESROYED(destroyed_packets_bitfld, i) || next_step_v[i] > step)
			continue;

		dprintf(" -- step %d -- \n", step);

		/*
		 * Establish a "pass" connection, if required.  Just proceed if
		 * connection creation fails (e.g. due to unsupported protocol).
		 */
		npf_conn_t* c = *con;

		if ((retfl_v[i] & NPF_RULE_STATEFUL) != 0 && !c) {
			c = npf_conn_establish(npc, di,
				 (retfl_v[i] & NPF_RULE_MULTIENDS) == 0);
			if (c) {
				/*
				 * Note: the reference on the rule procedure is
				 * transfered to the connection.  It will be
				 * released on connection destruction.
				 */
				npf_conn_setpass(c, rp_v[i]);
				*con = c;
			}
		}
	}
	step++;

	/*
	 * step 5
	 * pass label
	 */
	npc = &npc_v[0];
	con = &con_v[0];
	for (i=0; i<vec_size; i++,npc++,con++) {
		/* skip destroyed packets or handle goto */
		if (IS_PKT_DESROYED(destroyed_packets_bitfld, i) || next_step_v[i] > step)
			continue;

		dprintf(" -- step %d -- \n", step);

		dprintf("pass point\n");
		decision_v[i] = NPF_DECISION_PASS;
		KASSERT(error_v[i] == 0);
		/*
		 * Perform NAT.
		 */
		error_v[i] = npf_do_nat(npc, *con, di);
		if (unlikely(error_v[i])) {
			dprintf2("do nat err: %d\n", error);
		}
	}
	step++;

	/*
	 * step 6
	 * block label
	 */
	npc = &npc_v[0];
	con = &con_v[0];
	for (i=0; i<vec_size; i++,npc++,con++) {
		/* skip destroyed packets or handle goto */
		if (IS_PKT_DESROYED(destroyed_packets_bitfld, i) || next_step_v[i] > step)
			continue;

		dprintf(" -- step %d -- \n", step);

		/*
		 * Execute the rule procedure, if any is associated.
		 * It may reverse the decision from pass to block.
		 */
		if (rp_v[i] && !npf_rproc_run(npc, rp_v[i], &decision_v[i])) {
			if (*con) {
				npf_conn_release(*con);
			}
			npf_rproc_release(rp_v[i]);

			MARK_PKT_DESTROYED(destroyed_packets_bitfld, i);
			ret_v[i] = 0;
			continue;
		}
	}
	step++;

	/*
	 * step 7
	 * out label
	 */
	npc = &npc_v[0];
	nbuf = &nbuf_v[0];
	con = &con_v[0];
	for (i=0; i<vec_size; i++,npc++,con++,nbuf++) {
		/* skip destroyed packets or handle goto */
		if (IS_PKT_DESROYED(destroyed_packets_bitfld, i) || next_step_v[i] > step)
			continue;

		dprintf(" -- step %d -- \n", step);

		/*
		 * Release the reference on a connection.  Release the reference
		 * on a rule procedure only if there was no association.
		 */
		if (*con) {
			npf_conn_release(*con);
		}
		else if (rp_v[i]) {
			npf_rproc_release(rp_v[i]);
		}

		/* Reset mbuf pointer before returning to the caller. */
		struct mbuf* mp = nbuf_head_mbuf(nbuf);
		if (unlikely(mp  == NULL)) {
			dprintf2 ("npf: block 10: ENOMEM or error\n");
			ret_v[i] = error_v[i] ? error_v[i] : ENOMEM;
			errors = true;
			continue; // final return
		}

		dprintf("err: %d\n", error_v[i]);

		/* Pass the packet if decided and there is no error. */
		if (likely(decision_v[i] == NPF_DECISION_PASS && !error_v[i])) {
			/*
			 * XXX: Disable for now, it will be set accordingly later,
			 * for optimisations (to reduce inspection).
			 */
			m_clear_flag(mp, M_CANFASTFWD);
			/* final return */
			ret_v[i] = 0;
			continue;
		}

		/*
		 * Block the packet.  ENETUNREACH is used to indicate blocking.
		 * Depending on the flags and protocol, return TCP reset (RST) or
		 * ICMP destination unreachable.
		 */


		if (retfl_v[i] && npf_return_block(npc, retfl_v[i])) {
			dprintf2 ("npf: block 4\n");
			mp = NULL;
			MARK_PKT_DESTROYED(destroyed_packets_bitfld, i);
		}

		if (!error_v[i]) {
			error_v[i] = ENETUNREACH;
		}

		if (mp) {
			/* Free the mbuf chain. */
			m_freem(mp);
			MARK_PKT_DESTROYED(destroyed_packets_bitfld, i);
		}

		ret_v[i] = error_v[i];
		if (ret_v[i]) {
			errors = true;
		}
	}

	*out_destroyed_packets_bitfld = destroyed_packets_bitfld;
	return errors;
}

/*
 * npf_packet_handler: main packet handling routine for layer 3.
 *
 * Note: packet flow and inspection logic is in strict order.
 */
__dso_public int
npf_packet_handler(npf_t *npf, struct mbuf **mp, uint8_t* mbuf_data_ptr,
		  size_t l2_hdr_size, ifnet_t *ifp, int di, __time_t sec,
		  uint8_t cpu_thread)
{
	nbuf_t nbuf;
	npf_cache_t npc;
	npf_conn_t *con;
	npf_rule_t *rl;
	npf_rproc_t *rp;
	int error, retfl;
	int decision;

	// return 0; // return #0

	/* QSBR checkpoint. */
	pserialize_checkpoint(npf->qsbr);
	KASSERT(ifp != NULL);

	dprintf("npf_packet_handler\n");
	npc.sec = sec;

	// return 0; // return #1

	/*
	 * Initialise packet information cache.
	 * Note: it is enough to clear the info bits.
	 */
	npc.npc_ctx = npf;
	nbuf_init2(npf, &nbuf, *mp, l2_hdr_size, ifp, mbuf_data_ptr);
	npc.npc_nbuf = &nbuf;
	npc.npc_info = 0;
	npc.cpu_thread = cpu_thread;

	decision = NPF_DECISION_BLOCK;
	error = 0;
	retfl = 0;
	rp = NULL;

	// return 0; // return #2

	/* Cache everything.  Determine whether it is an IP fragment. */
	if (__predict_false(npf_cache_all(&npc) & NPC_IPFRAG)) {
		/*
		 * Pass to IPv4 or IPv6 reassembly mechanism.
		 */
		error = npf_reassembly(npf, &npc, mp);
		if (error) {
			con = NULL;
			goto out;
		}
		if (*mp == NULL) {
			/* More fragments should come; return. */
			return 0;
		}
	}

	// return 0; // return #3

	dprintf("connection inspect\n");
	/* Inspect the list of connections (if found, acquires a reference). */
	con = npf_conn_inspect(&npc, di, &error);

	// return 0; // return #4

	/* If "passing" connection found - skip the ruleset inspection. */
	if (con && npf_conn_pass(con, &rp)) {
		npf_stats_inc(npf, &npc, NPF_STAT_PASS_CONN);
		KASSERT(error == 0);
		dprintf ("npf: pass 1\n");
		goto pass;
	}
	if (__predict_false(error)) {
		if (error == ENETUNREACH) {
			dprintf2("npf: block 1: ENETUNREACH\n");
			goto block;
		}
		goto out;
	}

	/* Acquire the lock, inspect the ruleset using this packet. */
	int slock = npf_config_read_enter();
	npf_ruleset_t *rlset = npf_config_ruleset(npf);

	dprintf("conn: %p\n", con);
	dprintf("rule inspect\n");

	rl = npf_ruleset_inspect(&npc, rlset, di, NPF_LAYER_3);
	if (__predict_false(rl == NULL)) {
		const bool pass = npf_default_pass(npf);
		npf_config_read_exit(slock);

		if (pass) {
			npf_stats_inc(npf, &npc, NPF_STAT_PASS_DEFAULT);
			dprintf ("npf: pass 2\n");
			goto pass;
		}
		npf_stats_inc(npf, &npc, NPF_STAT_BLOCK_DEFAULT);
		dprintf2("npf: block 2: block_default\n");
		goto block;
	}

	/*
	 * Get the rule procedure (acquires a reference) for association
	 * with a connection (if any) and execution.
	 */
	KASSERT(rp == NULL);
	rp = npf_rule_getrproc(rl);

	dprintf("rule conclude\n");

	/* Conclude with the rule and release the lock. */
	error = npf_rule_conclude(rl, &retfl);
	npf_config_read_exit(slock);

	if (error) {
		npf_stats_inc(npf, &npc, NPF_STAT_BLOCK_RULESET);
		dprintf2("npf: block 3: block_ruleset\n");
		goto block;
	}
	npf_stats_inc(npf, &npc, NPF_STAT_PASS_RULESET);

	/*
	 * Establish a "pass" connection, if required.  Just proceed if
	 * connection creation fails (e.g. due to unsupported protocol).
	 */
	if ((retfl & NPF_RULE_STATEFUL) != 0 && !con) {
		con = npf_conn_establish(&npc, di,
		    (retfl & NPF_RULE_MULTIENDS) == 0);
		if (con) {
			/*
			 * Note: the reference on the rule procedure is
			 * transfered to the connection.  It will be
			 * released on connection destruction.
			 */
			npf_conn_setpass(con, rp);
		}
	}
pass:
	dprintf("pass point\n");
	decision = NPF_DECISION_PASS;
	KASSERT(error == 0);
	/*
	 * Perform NAT.
	 */
	error = npf_do_nat(&npc, con, di);
	if (__predict_false(error)) {
		dprintf2("do nat err: %d\n", error);
	}
block:
	/*
	 * Execute the rule procedure, if any is associated.
	 * It may reverse the decision from pass to block.
	 */
	if (rp && !npf_rproc_run(&npc, rp, &decision)) {
		if (con) {
			npf_conn_release(con);
		}
		npf_rproc_release(rp);
		*mp = NULL;
		return 0;
	}
out:
	/*
	 * Release the reference on a connection.  Release the reference
	 * on a rule procedure only if there was no association.
	 */
	if (con) {
		npf_conn_release(con);
	} else if (rp) {
		npf_rproc_release(rp);
	}

	/* Reset mbuf pointer before returning to the caller. */
	if (__predict_false((*mp = nbuf_head_mbuf(&nbuf)) == NULL)) {
		dprintf2 ("npf: block 10: ENOMEM or error\n");
		return error ? error : ENOMEM;
	}

	dprintf("decision: %d, err: %d\n", decision, error);

	/* Pass the packet if decided and there is no error. */
	if (__predict_true(decision == NPF_DECISION_PASS && !error)) {
		/*
		 * XXX: Disable for now, it will be set accordingly later,
		 * for optimisations (to reduce inspection).
		 */
		m_clear_flag(*mp, M_CANFASTFWD);
		return 0;
	}

	/*
	 * Block the packet.  ENETUNREACH is used to indicate blocking.
	 * Depending on the flags and protocol, return TCP reset (RST) or
	 * ICMP destination unreachable.
	 */
	if (retfl && npf_return_block(&npc, retfl)) {
		dprintf2 ("npf: block 4\n");
		*mp = NULL;
	}

	if (!error) {
		error = ENETUNREACH;
	}

	if (*mp) {
		/* Free the mbuf chain. */
		m_freem(*mp);
		*mp = NULL;
	}
	return error;
}

#ifdef _KERNEL
/*
 * npf_ifhook: hook handling interface changes.
 */
static int
npf_ifhook(void *arg, struct mbuf **mp, ifnet_t *ifp, int di)
{
	u_long cmd = (u_long)mp;

	if (di == PFIL_IFNET) {
		switch (cmd) {
		case PFIL_IFNET_ATTACH:
			npf_ifmap_attach(ifp);
			break;
		case PFIL_IFNET_DETACH:
			npf_ifmap_detach(ifp);
			break;
		}
	}
	return 0;
}

/*
 * npf_pfil_register: register pfil(9) hooks.
 */
int
npf_pfil_register(bool init)
{
	npf_t *npf = npf_getkernctx();
	int error = 0;

	mutex_enter(softnet_lock);
	KERNEL_LOCK(1, NULL);

	/* Init: interface re-config and attach/detach hook. */
	if (!npf_ph_if) {
		npf_ph_if = pfil_head_get(PFIL_TYPE_IFNET, 0);
		if (!npf_ph_if) {
			error = ENOENT;
			goto out;
		}
		error = pfil_add_hook(npf_ifhook, NULL,
		    PFIL_IFADDR | PFIL_IFNET, npf_ph_if);
		KASSERT(error == 0);
	}
	if (init) {
		goto out;
	}

	/* Check if pfil hooks are not already registered. */
	if (pfil_registered) {
		error = EEXIST;
		goto out;
	}

	/* Capture points of the activity in the IP layer. */
	npf_ph_inet = pfil_head_get(PFIL_TYPE_AF, (void *)AF_INET);
	npf_ph_inet6 = pfil_head_get(PFIL_TYPE_AF, (void *)AF_INET6);
	if (!npf_ph_inet && !npf_ph_inet6) {
		error = ENOENT;
		goto out;
	}

	/* Packet IN/OUT handlers for IP layer. */
	if (npf_ph_inet) {
		error = pfil_add_hook(npf_packet_handler, npf,
		    PFIL_ALL, npf_ph_inet);
		KASSERT(error == 0);
	}
	if (npf_ph_inet6) {
		error = pfil_add_hook(npf_packet_handler, npf,
		    PFIL_ALL, npf_ph_inet6);
		KASSERT(error == 0);
	}
	pfil_registered = true;
out:
	KERNEL_UNLOCK_ONE(NULL);
	mutex_exit(softnet_lock);

	return error;
}

/*
 * npf_pfil_unregister: unregister pfil(9) hooks.
 */
void
npf_pfil_unregister(bool fini)
{
	npf_t *npf = npf_getkernctx();

	mutex_enter(softnet_lock);
	KERNEL_LOCK(1, NULL);

	if (fini && npf_ph_if) {
		(void)pfil_remove_hook(npf_ifhook, NULL,
		    PFIL_IFADDR | PFIL_IFNET, npf_ph_if);
	}
	if (npf_ph_inet) {
		(void)pfil_remove_hook(npf_packet_handler, npf,
		    PFIL_ALL, npf_ph_inet);
	}
	if (npf_ph_inet6) {
		(void)pfil_remove_hook(npf_packet_handler, npf,
		    PFIL_ALL, npf_ph_inet6);
	}
	pfil_registered = false;

	KERNEL_UNLOCK_ONE(NULL);
	mutex_exit(softnet_lock);
}

bool
npf_pfil_registered_p(void)
{
	return pfil_registered;
}
#endif
