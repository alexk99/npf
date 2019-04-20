/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   npf_connkey.h
 * Author: alexk
 *
 * Created on June 7, 2016, 7:28 PM
 */

#ifndef NPF_CONN_KEY
#define NPF_CONN_KEY

typedef struct npf_ipv6_addr
{
	uint8_t ipv6[16];
}
npf_ipv6_addr_t;

/*
 * See npf_conn_conkey() function for the key layout description.
 */
#define	NPF_CONN_IPV4_KEYLEN_WORDS	4
#define	NPF_CONN_IPV6_KEYLEN_WORDS	(2 + ((sizeof(npf_ipv6_addr_t) * 2) >> 2))
#define	NPF_CONN_NKEYWORDS	(2 + ((sizeof(npf_addr_t) * 2) >> 2))
#define	NPF_CONN_MAXKEYLEN	(NPF_CONN_NKEYWORDS * sizeof(uint32_t))
#define	NPF_CONN_GETALEN(key)	((key)->ck_key[0] & 0xffff)
#define	NPF_CONN_KEYLEN(key)	(8 + (2 * NPF_CONN_GETALEN(key)))

typedef struct npf_connkey_ipv4 
{
	uint32_t		ck_key[NPF_CONN_IPV4_KEYLEN_WORDS];
}
npf_connkey_ipv4_t;

typedef struct npf_connkey_ipv6
{
	uint32_t		ck_key[NPF_CONN_IPV6_KEYLEN_WORDS];
}
npf_connkey_ipv6_t;

#endif /* NPF_CONN_KEY */

