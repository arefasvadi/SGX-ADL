#include "SpecialBufferCommon.h"

#include "common.h"

uint32_t SpecialBufferCommon::currID_               = 0;
uint64_t SpecialBufferCommon::overallBytesConsumed_ = 0;

// std::vector<uint8_t> SpecialBufferCommon::CommonBuffer_(
//     SGX_LAYERWISE_MAX_LAYER_SIZE, 0);
