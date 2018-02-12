/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   MersenneTwister.h
 * Author: alexk
 *
 * Created on February 11, 2018, 9:10 PM
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MERSENNETWISTER_H
#define MERSENNETWISTER_H

void* 
mersenne_twister_create(unsigned int seed);

unsigned int 
mersenne_twister_integer(void* slf);

#ifdef __cplusplus
}
#endif

#endif /* MERSENNETWISTER_H */

