#pragma once
#include "IO.h"

namespace sgxdarknet {
namespace trusted {
class DNNDataIO : public IO<char, DNNData> {};
}
}
