#pragma once
#include "pcg_basic.h"


extern pcg32_random_t gen;

void set_random_seed(uint64_t s1, uint64_t s2);
int rand();

