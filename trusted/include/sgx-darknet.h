#pragma once

#undef OPENCV
#undef GPU
#undef CUDNN
// Maybe uncomment the below line. Don't know if OPENMP is linkable to SGX as of
// now
// #undef OPENMP
#include "darknet.h"

namespace sgxdarknet {
namespace trusted {


};
};
