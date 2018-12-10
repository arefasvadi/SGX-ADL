#pragma once

#include "CryptoEngine.hpp"
#include "DNNConfigIO.h"
#include "bitonic-sort.h"
#include "darknet.h"
// #include "DNNDataIO.h"
// #include "DNNParamIO.h"
#include <memory>
#include <string>

namespace sgx {
namespace trusted {
namespace darknet {

namespace sgt = ::sgx::trusted;
namespace std = ::std;
class DNNTrainer {
public:
  explicit DNNTrainer(const std::string &config_file_path,
                      const std::string &param_dir_path,
                      const std::string &data_dir_path);

  bool loadNetworkConfig() ;
  inline sgt::CryptoEngine<uint8_t> &getCryptoEngine() {
    return cryptoEngine_;
  };
  void intitialSort();
  void train();

private:
  bool prepareBatch(int start);
  sgt::CryptoEngine<uint8_t> cryptoEngine_;
  std::unique_ptr<DNNConfigIO> configIO_;
  data trainData_ = {0};
  network* net_ = nullptr;
  const int trainSize_ = TOTAL_IMG_TRAIN_RECORDS; 
  // std::unique_ptr<DNNParamIO> paramoIO_;
  // std::unique_ptr<DNNDataIO> dataIO_;
};
}
}
}
