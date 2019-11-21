#pragma once

#include <assert.h>
#include <stdlib.h>
#include <string>
#include "common.h"
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

#include "rand/PRNG.h"

#ifdef USE_SGX_BLOCKING
#undef USE_SGX_LAYERWISE
#endif

#if defined(USE_SGX) && defined(USE_SGX_BLOCKING)
#include "BlockEngine.hpp"
#endif

#include <vector>

#if defined(USE_SGX) && defined(USE_SGX_LAYERWISE)

#include "SpecialBuffer.hpp"
#endif

template <typename T>
struct atomwrapper
{
  std::atomic<T> _a;

  atomwrapper()
    :_a()
  {}

  atomwrapper(const std::atomic<T> &a)
    :_a(a.load())
  {}

  atomwrapper(const atomwrapper &other)
    :_a(other._a.load())
  {}

  atomwrapper &operator=(const atomwrapper &other)
  {
    _a.store(other._a.load());
  }
};

#if defined(USE_SGX)

typedef enum class thread_task_status_t {
  not_started,
  in_progress,
  finished,
} thread_task_status_t;

typedef struct gemm_multi_thread_params_t {
  float *A;
  float *B;
  float *C;
  float  ALPHA;
  float  BETA;
  int    TA;
  int    TB;
  int    M;
  int    N;
  int    K;
  int    lda;
  int    ldb;
  int    ldc;
  int starterM;
  int starterN;
} gemm_multi_thread_params_t;

using gemm_thread_task_t
    = std::pair<gemm_multi_thread_params_t, atomwrapper<thread_task_status_t>>;
extern std::vector<gemm_thread_task_t> per_thr_params;
extern gemm_multi_thread_params_t      gemm_params;

// can be used for scal_cpu, fill_cpu and const_cpu;
// typedef struct cpu_same_src_dest_multi_thread_params_t {
//   float *X;
//   int    N;
//   int    INCX;
//   float  ALPHA;
//   int starterN;
// } cpu_same_src_dest_multi_thread_params_t;

// using cpu_same_thread_task_t
//     = std::pair<cpu_same_src_dest_multi_thread_params_t, atomwrapper<thread_task_status_t>>;
// extern std::vector<cpu_same_thread_task_t> cpu_same_src_dest_per_thr_params;
// extern cpu_same_src_dest_multi_thread_params_t cpu_same_src_dest_params;
// extern const int cpu_same_src_dest_num;
struct network;
void set_network_batch_randomness(const int iteration,network & net_);

#endif


#include "../../third_party/darknet/include/darknet.h"
#include "pcg_basic.h"
extern int
printf(const char *fmt, ...);

static pcg32_random_t gen;
extern bool           global_training;

void
set_random_seed(uint64_t s1, uint64_t s2);
int
rand();

#if defined(__cplusplus)
extern "C" {
#endif

// #define RAND_MAX (int)2147483647

// extern uint64_t seed_1;
// extern uint64_t seed_2;
// void srand(unsigned seed);

void
custom_error(char *s);

#if defined(__cplusplus)
}
#endif

#define error(...)               \
  do {                           \
    if (0)                       \
      custom_error(__VA_ARGS__); \
  } while (0);

#define fprintf(...)
//#define printf(...)
#define print_statistics(...)
#define srand(x) set_random_seed(x, 1)

// #define box_iou(...)
// #define float_to_box(...)
