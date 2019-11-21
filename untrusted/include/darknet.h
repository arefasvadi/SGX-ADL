#pragma once

#undef USE_SGX
#undef USE_SGX_LAYERWISE
#undef USE_SGX_BLOCKING
// #undef USE_GEMM_THREADING
#include "common.h"
#include "global-vars-untrusted.h"
#include "rand/PRNG.h"
// #ifndef GPU
// #define GPU
// #endif  // !GPU

#include "../../third_party/darknet/include/darknet.h"
#include "../../third_party/darknet/src/data.h"

void
main_logger(int level, const char *file, int line, const char *format, ...);

extern bool global_training;
