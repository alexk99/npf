/*	$NetBSD: npf.c,v 1.22 2014/07/25 08:10:40 dholland Exp $	*/

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
 * NPF main: dynamic load/initialisation and unload routines.
 */

#ifdef _KERNEL
#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: npf.c,v 1.22 2014/07/25 08:10:40 dholland Exp $");

#include <sys/param.h>
#include <sys/types.h>

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/percpu.h>
#endif

#include "npf_impl.h"
#include "npf_conn.h"

#include "stdarg.h"
#include "likely.h"

#define _XOPEN_SOURCE 600

#include <stdlib.h>
#include "npf_alg_icmp.h"

#ifdef NPF_DEBUG_COUNTERS
uint64_t g_debug_counter;
uint64_t g_conn_map_size;
#endif /* NPF_DEBUG_COUNTERS */

static npf_t *	npf_kernel_ctx = NULL __read_mostly;

__dso_public int
npf_sysinit(unsigned nworkers)
{
	npf_bpf_sysinit();
	npf_tableset_sysinit();
	npf_nat_sysinit();
	return npf_worker_sysinit(nworkers);
}

__dso_public void
npf_sysfini(void)
{
	npf_worker_sysfini();
	npf_nat_sysfini();
	npf_tableset_sysfini();
	npf_bpf_sysfini();
}

#ifdef NPF_DEBUG_COUNTERS
__dso_public uint64_t
npf_get_n_conndb_rbtree_cmp_nodes(npf_t * npf)
{
	return g_debug_counter;
}
#endif /* NPF_DEBUG_COUNTERS */

__dso_public uint64_t
npf_get_conn_map_size(npf_t * npf)
{
	return npf_conndb_ipv4_size(npf->conn_db);
}

__dso_public npf_t *
npf_create(int flags, const npf_mbufops_t *mbufops, const npf_ifops_t *ifops,
		  void* log_func, uint16_t num_threads)
{
	npf_t *npf;

	npf = kmem_zalloc(sizeof(npf_t), KM_SLEEP);
	npf->qsbr = pserialize_create();
	if (!npf->qsbr) {
		kmem_free(npf, sizeof(npf_t));
		return NULL;
	}

	/* statistics */
	npf->stats_percpu_size = num_threads;
	npf->stats_percpu = (uint64_t**) kmem_alloc(num_threads *
			  sizeof(uint64_t*), KM_SLEEP);

	int i, ret;
	for (i=0; i<num_threads; i++) {
		ret = posix_memalign((void**) &npf->stats_percpu[i], CACHE_LINE_SIZE,
				  NPF_STATS_SIZE);
		if (unlikely(ret != 0)) {
			return NULL;
		}
		// npf->stats_percpu[i] = (uint64_t*) alligned_alloc(CACHE_LINE_SIZE,
		//		  NPF_STATS_SIZE);
		memset(npf->stats_percpu[i], 0, NPF_STATS_SIZE);
	}

	npf->mbufops = mbufops;

	npf->nat_portmap_hash = npf_portmap_init();
	if (!npf->nat_portmap_hash) {
		kmem_free(npf, sizeof(npf_t));
		return NULL;
	}

#ifdef ALEXK_DEBUG
	npf_portmap_test();
#endif

	npf_ifmap_init(npf, ifops);
	npf_conn_init(npf, flags);
	npf_alg_init(npf);
	npf_ext_init(npf);

#ifdef NPF_LOG_DEBUG
	g_log_func = log_func;
#else
	(void) log_func;
#endif

#ifdef NPF_DEBUG_COUNTERS
	g_debug_counter = 0;
#endif /* NPF_DEBUG_COUNTERS */

	/* Load an empty configuration. */
	npf_config_init(npf);

	/* init icmp alg */
	npf_alg_icmp_modcmd(MODULE_CMD_INIT, npf);

	return npf;
}

__dso_public void npf_checkpoint(npf_t * npf) {
   qsbr_checkpoint(npf->qsbr);
}

__dso_public void
npf_destroy(npf_t *npf)
{
	/*
	 * Destroy the current configuration.  Note: at this point all
	 * handlers must be deactivated; we will drain any processing.
	 */
	npf_config_fini(npf);

	/* Finally, safe to destroy the subsystems. */
	npf_ext_fini(npf);
	npf_alg_fini(npf);
	npf_conn_fini(npf);
	npf_ifmap_fini(npf);
	npf_portmap_fini(npf->nat_portmap_hash);

	pserialize_destroy(npf->qsbr);

	/* destroy statistic memory */
	int i;
	for (i=0; i<npf->stats_percpu_size; i++) {
		free(npf->stats_percpu[i]);
	}
	kmem_free(npf->stats_percpu, sizeof(uint64_t*) * stat_num_pointers);

	/**/
	kmem_free(npf, sizeof(npf_t));
}

__dso_public int
npf_load(npf_t *npf, void *ref, npf_error_t *err)
{
	return npfctl_load(npf, 0, ref);
}

__dso_public void
npf_gc(npf_t *npf, uint8_t cpu_thread)
{
	npf_cache_t npc;
	npc.cpu_thread = cpu_thread;

	npf_conn_worker(npf, &npc);
	pserialize_perform(npf->qsbr);
	npf_portmap_gc(npf->nat_portmap_hash);
}

__dso_public void
npf_thread_register(npf_t *npf)
{
	pserialize_register(npf->qsbr);
}

void
npf_setkernctx(npf_t *npf)
{
	npf_kernel_ctx = npf;
}

npf_t *
npf_getkernctx(void)
{
	return npf_kernel_ctx;
}

/*
 * NPF statistics interface.
 */

void
npf_stats_inc(const npf_t *npf, const npf_cache_t *npc, npf_stats_t st)
{
	uint64_t *stats = npf->stats_percpu[npc->cpu_thread];
	stats[st]++;
}

void
npf_stats_dec(const npf_t *npf, const npf_cache_t *npc, npf_stats_t st)
{
	uint64_t *stats = npf->stats_percpu[npc->cpu_thread];
	stats[st]--;
}

/*
 * npf_stats: export collected statistics.
 */
__dso_public void
npf_stats(npf_t* npf, uint64_t* full_stats)
{
	memset(full_stats, 0, NPF_STATS_SIZE);
	uint64_t* percpu_stats;

	for (unsigned i=0; i<npf->stats_percpu_size; i++) {
		percpu_stats = npf->stats_percpu[i];
		for (unsigned j=0; j<NPF_STATS_COUNT; j++) {
			full_stats[j] += percpu_stats[j];
		}
	}
}

/*
 * zero per cpu stats
 */
__dso_public void
npf_stats_clear(npf_t* npf)
{
	uint64_t* percpu_stats;

	for (unsigned i=0; i<npf->stats_percpu_size; i++) {
		percpu_stats = npf->stats_percpu[i];

		/* zero per cpu stats */
		for (unsigned j=0; j<NPF_STATS_COUNT; j++) {
			percpu_stats[j] = 0;
		}
	}
}

/*
 * conndb summary
 */
__dso_public void
npf_conndb_state_summary(npf_t* npf, npf_print_cb_t print_line_cb, void* context)
{
	npf_conndb_print_state_summary(npf->conn_db, print_line_cb, context);
}
