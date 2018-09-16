#pragma once
#include "IO.h"

namespace sgxdarknet {
namespace trusted {
class DNNParamIO : public IO<char, DNNParam> {};
}
}
