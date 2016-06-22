/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "city.h"
#include "npf_city_hasher.h"

uint64 npf_city_hash(const char* buf, size_t len)
{
	return CityHash64(buf, len);
}
