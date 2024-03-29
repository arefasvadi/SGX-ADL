#pragma once

#include "CryptoEngine.hpp"
#include "DNNConfigIO.h"
//#include "bitonic-sort.h"
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

enum class DNNTask { NO_TASK, TRAIN, VALIDATION, TEST, PREDICTION };

class DNNTrainer {
public:
  explicit DNNTrainer(const char *config_file_path,
                      const std::string &param_dir_path,
                      const std::string &data_dir_path,
                      SecStrategyType security_mode, int width, int height,
                      int channels, int num_classes, int train_size,
                      int test_size, int predict_size);

  bool loadNetworkConfig();
  bool loadWeights();

#if defined(USE_SGX) && defined(USE_SGX_BLOCKING)
  bool loadNetworkConfigBlocked();
  void trainBlocked();
  void
  loadTrainDataBlocked(std::shared_ptr<sgt::BlockedBuffer<float, 2>> XBlocked_,
                       std::shared_ptr<sgt::BlockedBuffer<float, 2>> YBlocked_);
  bool prepareBatchTrainBlocked(int start);
  bool prepareBatchTrainBlockedDirect();
#endif
  sgt::CryptoEngine<uint8_t> &getCryptoEngine();
  void intitialSort();
  void train();
  void test();
  void predict();

  int trainSize_;
  int testSize_;
  int predictSize_;
  int w;
  int h;
  int c;
  int n_classes;
  SecStrategyType secMode;
  // DNNTask currTask_;
private:
  bool prepareBatchTrainEncrypted(int start);
  bool prepareBatchTrainPlain(int start);
  bool prepareBatchTestEncrypted(int start);
  bool prepareBatchTestPlain(int start);
  bool prepareBatchPredictEncrypted(int start);
  bool prepareBatchPredictPlain(int start);
  bool loadWeightsPlain();
  bool loadWeightsEncrypted();
  sgt::CryptoEngine<uint8_t> cryptoEngine_;
  std::unique_ptr<DNNConfigIO> configIO_;
  std::vector<float> predResults_;

#if defined(USE_SGX) && defined(USE_SGX_BLOCKING)
  network_blocked *net_blcoked_ = nullptr;
  std::shared_ptr<sgt::BlockedBuffer<float, 2>> trainXBlocked_;
  std::shared_ptr<sgt::BlockedBuffer<float, 2>> trainYBlocked_;
#elif defined(USE_SGX)

#endif
  data trainData_ = {0};
  data testData_ = {0};
  data predictData_ = {0};
  network *net_ = nullptr;

  // std::unique_ptr<DNNParamIO> paramoIO_;
  // std::unique_ptr<DNNDataIO> dataIO_;
};
} // namespace darknet
} // namespace trusted
} // namespace sgx
