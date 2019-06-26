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

  bool loadNetworkConfig();
#if defined(USE_SGX) && defined(USE_SGX_BLOCKING)
  bool loadNetworkConfigBlocked();
  void trainBlocked();
  void loadTrainDataBlocked(
      std::shared_ptr<sgt::BlockedBuffer<float, 2>> XBlocked_,
      std::shared_ptr<sgt::BlockedBuffer<float, 2>> YBlocked_);
  bool prepareBatchTrainBlocked(int start);
#endif
  inline sgt::CryptoEngine<uint8_t> &getCryptoEngine() {
    return cryptoEngine_;
  };
  void intitialSort();
  void train(bool is_plain = false);

private:
  bool prepareBatchTrainEncrypted(int start);
  bool prepareBatchTrainPlain(int start);
  bool prepareBatchTestEncrypted(int start);
  bool prepareBatchTestPlain(int start);
  sgt::CryptoEngine<uint8_t> cryptoEngine_;
  std::unique_ptr<DNNConfigIO> configIO_;
  data trainData_ = {0};
  data testData_ = {0};
  network *net_ = nullptr;
#if defined(USE_SGX) && defined(USE_SGX_BLOCKING)
  network_blocked *net_blcoked_ = nullptr;
  std::shared_ptr<sgt::BlockedBuffer<float, 2>> trainXBlocked_;
  std::shared_ptr<sgt::BlockedBuffer<float, 2>> trainYBlocked_;
#endif
  const int trainSize_ = TOTAL_IMG_TRAIN_RECORDS;
  const int testSize_ = TOTAL_IMG_TEST_RECORDS;
  // std::unique_ptr<DNNParamIO> paramoIO_;
  // std::unique_ptr<DNNDataIO> dataIO_;
};
} // namespace darknet
} // namespace trusted
} // namespace sgx
