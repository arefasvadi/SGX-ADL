#include "DNNTrainer.h"
#include <string>

// extern void printf(const char *fmt, ...);

namespace sgx {
namespace trusted {
namespace darknet {
DNNTrainer::DNNTrainer(const std::string &config_file_path,
                       const std::string &param_dir_path,
                       const std::string &data_dir_path)
    : cryptoEngine_(sgt::CryptoEngine<uint8_t>::Key{
          1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
      configIO_(std::unique_ptr<DNNConfigIO>(
          new DNNConfigIO(config_file_path, cryptoEngine_))) {}

bool DNNTrainer::loadNetworkConfig() const {

  bool res = configIO_->receiveFromUntrusted(ocall_load_net_config);
  if (!res) {
    my_printf("%s:%d@%s => Cannot properly move config into enclave!\n",
              __FILE__, __LINE__, __func__);
    return false;
  } else {
    my_printf("%s:%d@%s => properly moved config into enclave!\n", __FILE__,
              __LINE__, __func__);
  }
  my_printf("%s:%d@%s => about to load the network object!\n", __FILE__,
            __LINE__, __func__);

  network *net =
      load_network((char *)configIO_->getNetConfig().c_str(), nullptr, 1);

  return true;
}
void DNNTrainer::intitialSort() {
  BitonicSorter sorter(50000, true, cryptoEngine_);
  // BitonicSorter sorter(10000, true, cryptoEngine_);
  sorter.doSort();
}
}
}
}
