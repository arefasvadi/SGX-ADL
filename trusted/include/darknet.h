#pragma once

#include "common.h"
#include <assert.h>
#include <stdlib.h>
#include "util.h"


#ifndef USE_SGX
#define USE_SGX
#endif

#undef GPU
#undef DEBUG
#undef OPENCV
#undef OPENMP
#undef CUDNN

#include "enclave_t.h"

#ifdef USE_SGX_LAYERWISE
#undef USE_SGX_BLOCKING
#endif

#ifdef USE_SGX_BLOCKING
#undef USE_SGX_LAYERWISE
#endif

#if defined (USE_SGX) && defined (USE_SGX_BLOCKING)
#include "BlockEngine.hpp"
#endif

#if defined (USE_SGX) && defined (USE_SGX_LAYERWISE)
#include "SpecialBuffer.hpp"
#include <vector>
#endif


#include "../../third_party/darknet/include/darknet.h"
#include "pcg_basic.h"
extern int printf(const char *fmt, ...);

static pcg32_random_t gen;
static bool global_training;

void set_random_seed(uint64_t s1, uint64_t s2);
int rand();

#if defined(__cplusplus)
extern "C" {
#endif

// #define RAND_MAX (int)2147483647

// extern uint64_t seed_1;
// extern uint64_t seed_2;
// void srand(unsigned seed);

void custom_error(char *s);

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
