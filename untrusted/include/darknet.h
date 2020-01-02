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
#include <openssl/sha.h>

std::array<uint64_t, 16> generate_random_seed_from(PRNG &rng);
void setup_layers_iteration_seed(network& net, int iteration);

void
main_logger(int level, const char *file, int line, const char *format, ...);

void gen_sha256(const uint8_t* msg, const size_t msg_len, uint8_t* out);

extern bool global_training;
