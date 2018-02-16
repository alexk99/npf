/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   npf_debug.h
 * Author: alexk
 *
 * Created on June 21, 2016, 1:40 AM
 */

#ifndef NPF_DEBUG_H
#define NPF_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ALEXK_DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define	dprintf(...)
#endif

/* log context */
#define NPF_LOG_CONN			1
#define NPF_LOG_CONN_DBG	2
	
#ifdef NPF_LOG_DEBUG
#define npf_log g_log_func
#else
#define	npf_log(...)
#endif


#ifdef ALEXK_DEBUG2
#define dprintf2(...) printf(__VA_ARGS__)
#else
#define	dprintf2(...)
#endif

#ifdef ALEXK_DEBUG2
#define dprintf3(...) syslog(LOG_DEBUG, __VA_ARGS__)
#else
#define	dprintf2(...)
#endif


#ifdef __cplusplus
}
#endif

#endif /* NPF_DEBUG_H */

