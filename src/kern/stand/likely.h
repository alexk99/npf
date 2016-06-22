/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   likely.h
 * Author: alexk
 *
 * Created on June 7, 2016, 7:39 PM
 */

#ifndef LIKELY_H
#define LIKELY_H

#ifndef likely
#define	likely(x)	__builtin_expect((x) != 0, 1)
#endif
#ifndef unlikely
#define	unlikely(x)	__builtin_expect((x) != 0, 0)
#endif	

#endif /* LIKELY_H */

