#include "DNNTrainer.h"
#include <string>

namespace sgx {
namespace trusted {
namespace darknet {
DNNTrainer::DNNTrainer(const std::string &config_file_path,
                       const std::string &param_dir_path,
                       const std::string &data_dir_data)
    : cryptoEngine_(sgt::CryptoEngine<uint8_t>::Key{
          1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
      configIO_(std::unique_ptr<DNNConfigIO>(
          new DNNConfigIO(config_file_path, cryptoEngine_))) {}
}
}
}
