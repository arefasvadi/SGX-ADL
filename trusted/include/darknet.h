#pragma once

#include "common.h"
#include <assert.h>
#include <stdlib.h>
#include "util.h"


#ifndef USE_SGX
#define USE_SGX
//#ifndef USE_SGX_BLOCKING
//#define USE_SGX_BLOCKING
//#endif
#endif

#undef GPU
#undef DEBUG
#undef OPENCV
#undef OPENMP
#undef CUDNN

#include "../../third_party/darknet/include/darknet.h"

#if defined(__cplusplus)
extern "C" {
#endif

#include "pcg_basic.h"
// #define RAND_MAX (int)2147483647

// extern uint64_t seed_1;
// extern uint64_t seed_2;
static pcg32_random_t gen;

void set_random_seed(uint64_t s1, uint64_t s2);
int rand();
// void srand(unsigned seed);

void custom_error(char *s);
extern void printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

#define error(...)                                                             \
  do {                                                                         \
    if (0)                                                                     \
      custom_error(__VA_ARGS__);                                               \
  } while (0);

#define fprintf(...)
//#define printf(...)
#define print_statistics(...)
#define srand(x) set_random_seed(x, 1)

// #define box_iou(...)
// #define float_to_box(...)
