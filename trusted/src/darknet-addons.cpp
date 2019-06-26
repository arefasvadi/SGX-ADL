#include "darknet.h"

/* static uint64_t seed_1; */
/* static uint64_t seed_2; */
extern  pcg32_random_t gen;

void set_random_seed(uint64_t s1, uint64_t s2) {

  /* seed_1 = s1; */
  /* seed_2 = s2; */

  
  pcg32_srandom_r(&gen, s1, s2);
}

int rand() { return (int)pcg32_random_r(&gen); }
