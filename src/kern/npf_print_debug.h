/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   npf_print_debug.h
 * Author: alexk
 *
 * Created on June 21, 2016, 1:40 AM
 */

#ifndef NPF_DEBUG_H
#define NPF_DEBUG_H

#include <stdint.h>

#ifdef NPF_PRINT_DEBUG
	
/* debug print contexts */
#define NPF_DC_PPTP_ALG                     0	
#define NPF_DC_GRE                          1
#define NPF_DC_ESTABL_CON                   2

int
npf_dprintfc(uint32_t context, char *format, ...);
#define NPF_DPRINTFC(context, ...) npf_dprintfc(context, __VA_ARGS__)

int
npf_dprintfcl(uint32_t context, uint32_t level, char *format, ...);
#define NPF_DPRINTFCL(context, level, ...) \
		  npf_dprintfcl(context, level, __VA_ARGS__)

void
npf_hex_dump(const char *desc, const void *addr, int len);

void
npf_dhexdumpcl(uint32_t context, uint32_t level, char *desc, void *addr,
		  int len);
#define NPF_HEX_DUMPCL(context, level, desc, addr, len) \
	npf_dhexdumpcl(context, level, desc, addr, len)
	
#else /* NPF_PRINT_DEBUG */

#define NPF_DPRINTFC(...)
#define NPF_DPRINTFCL(...)
#define NPF_HEX_DUMPCL(...)

#endif /* NPF_PRINT_DEBUG */

/* log context */
#define NPF_LOG_CONN			1
#define NPF_LOG_CONN_DBG	2
	
#ifdef NPF_LOG_DEBUG
#define npf_log g_log_func
#else
#define	npf_log(...)
#endif

#ifdef ALEXK_DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define	dprintf(...)
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

#endif /* NPF_DEBUG_H */

