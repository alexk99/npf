/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#ifdef NPF_CONN_DEBUG

#define __NPF_CONN_PRIVATE
#include "npf_conn.h"
#include "npf_impl.h"
#include "likely.h"

#include "npf_conn_map.h"
#include "npf_conn_debug.h"
#include "npf_portmap.h"

#define transl_ip_arr_size 4096

typedef struct npf_dbg_transl_ip {
	uint32_t transl_ip;

	/* count of nat entries using the translation ip */
	uint32_t nat_cnt;

	/* portmap ref_cnt */
	uint32_t portmap_ref_cnt;

	/* portmap */
	npf_portmap_entry_t* pm;

	/* pm up bits count */
	uint32_t pm_bit_cnt;
}
npf_dbg_transl_ip_t;

void
npf_conn_debug_check_con_list(npf_t *npf, npf_conn_t *con)
{
	/* connection with nat count */
	uint32_t conn_nat_cnt = 0;
	uint32_t transl_ip;

	npf_dbg_transl_ip_t transl_ip_arr[transl_ip_arr_size];
	uint32_t transl_ip_arr_cnt = 0;
	npf_dbg_transl_ip_t* t;
	uint32_t i, j, k;
	uint32_t conn_i = 1;
	npf_portmap_entry_t* pm;
	npf_addr_t* nt_taddr;
	in_port_t nt_tport;
	uint32_t bitmap_word;
	uint32_t bit_cnt;

	memset(transl_ip_arr, 0, sizeof(npf_dbg_transl_ip_t) * transl_ip_arr_size);

	while (con) {
		if (con->c_nat != NULL) {
			conn_nat_cnt++;

			npf_nat_gettrans(con->c_nat, &nt_taddr, &nt_tport);
			transl_ip = nt_taddr->word32[0];

			/* find transl ip in the array and inc its counter */
			for (i=0; i<transl_ip_arr_cnt; i++) {
				if (transl_ip_arr[i].transl_ip == transl_ip) {
					transl_ip_arr[i].nat_cnt++;
					break;
				}
			}

			/* if not found, add new element to the array */
			if (i == transl_ip_arr_cnt) {
				transl_ip_arr[transl_ip_arr_cnt].transl_ip = transl_ip;
				transl_ip_arr[transl_ip_arr_cnt].nat_cnt = 1;
				/* find portmap */
				pm = npf_portmap_find(npf->nat_portmap_hash, transl_ip);
				transl_ip_arr[transl_ip_arr_cnt].pm = pm;

				/* calc pm_num_bits */
				bit_cnt = 0;
				for (j=0; j<PORTMAP_SIZE; j++) {
					bitmap_word = pm->p_bitmap[j];
					for (k=0; k<32; k++) {
						if (bitmap_word & (uint32_t) (1 << k))
							bit_cnt++;
					}
				}
				transl_ip_arr[transl_ip_arr_cnt].pm_bit_cnt = bit_cnt;

				transl_ip_arr_cnt++;
				assert(transl_ip_arr_cnt < transl_ip_arr_size);
			}
		}

		con = con->c_next;
		conn_i++;
	}

	for (i=0; i<transl_ip_arr_cnt; i++) {
		t = &transl_ip_arr[i];

		if (t->pm != NULL)
			npf_log(NPF_LOG_CONN_DBG,
					  "transl %u, nat cnt %u, pm.ref_cnt %u, pm.bit_cnt %u\n",
					  t->transl_ip, t->nat_cnt, t->pm->p_refcnt, t->pm_bit_cnt);
		else
			npf_log(NPF_LOG_CONN_DBG, "transl %u, nat cnt %u, pm NOT found\n",
					  t->transl_ip, t->nat_cnt);
	}
}

__dso_public void
npf_conn_debug(npf_t *npf)
{
	npf_log(NPF_LOG_CONN_DBG, "conndb stat:\n");
	npf_conn_t *con = npf_conndb_getlist(npf->conn_db);
	npf_conn_debug_check_con_list(npf, con);
}

#endif /* NPF_CONN_DEBUG */