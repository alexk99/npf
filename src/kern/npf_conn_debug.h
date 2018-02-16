/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   npf_conn_debug.h
 * Author: alexk
 *
 * Created on February 14, 2018, 5:27 PM
 */

#ifndef NPF_CONN_DEBUG_H
#define NPF_CONN_DEBUG_H

#ifdef NPF_CONN_DEBUG

#ifdef __cplusplus
extern "C" {
#endif

void
npf_conn_debug_check_con_list(npf_t *npf, npf_conn_t *con);
	
void
npf_conn_debug(npf_t *npf);


#ifdef __cplusplus
}
#endif

#endif /* NPF_CONN_DEBUG */

#endif /* NPF_CONN_DEBUG_H */

