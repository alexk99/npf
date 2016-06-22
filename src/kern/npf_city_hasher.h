/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   npf_city_hasher.h
 * Author: alexk
 *
 * Created on June 7, 2016, 11:37 PM
 */

#ifndef NPF_CITY_HASHER_H
#define NPF_CITY_HASHER_H

#ifdef __cplusplus
extern "C" {
#endif

uint64_t npf_city_hash(const char* buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NPF_CITY_HASHER_H */

