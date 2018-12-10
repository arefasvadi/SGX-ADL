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
          new DNNConfigIO(config_file_path, cryptoEngine_))) {
  trainData_.shallow = 0;
  trainData_.w = IMG_WIDTH;
  trainData_.h = IMG_HEIGHT;
}

bool DNNTrainer::loadNetworkConfig() {

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

  net_ = load_network((char *)configIO_->getNetConfig().c_str(), nullptr, 1);

  return true;
}
void DNNTrainer::intitialSort() {
  BitonicSorter sorter(50000, true, cryptoEngine_);
  // BitonicSorter sorter(10000, true, cryptoEngine_);
  sorter.doSort();
}

bool DNNTrainer::prepareBatch(int start) {
  if (start + net_->batch <= trainSize_) {
    std::vector<uint8_t> enc_payload(sizeof(trainRecordEncrypted));
    std::vector<uint8_t> enc_data(sizeof(trainRecordSerialized));
    std::array<uint8_t, 12> IV;
    std::array<uint8_t, 16> MAC;
    sgx_status_t res = SGX_ERROR_UNEXPECTED;

    trainData_.X.rows = net_->batch;
    trainData_.X.cols = WIDTH_X_HEIGHT_X_CHAN;
    trainData_.X.vals = (float **)calloc(trainData_.X.rows, sizeof(float *));

    trainData_.y.rows = net_->batch;
    trainData_.y.cols = NUM_CLASSES;
    trainData_.y.vals = (float **)calloc(trainData_.y.rows, sizeof(float *));

    for (int i = 0; i < net_->batch; ++i) {
      res = ocall_get_records(start + i, &enc_payload[0],
                              sizeof(trainRecordEncrypted));
      if (res !=
          SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
        my_printf("ocall get records caused problem! the error is "
                  "%#010X \n",
                  res);
        abort();
      }
      trainRecordEncrypted *enc_r = (trainRecordEncrypted *)&(enc_payload[0]);
      std::memcpy(&enc_data[0], &(enc_r->encData),
                  sizeof(trainRecordSerialized));
      std::memcpy(&IV[0], (enc_r->IV), AES_GCM_IV_SIZE);
      std::memcpy(&MAC[0], (enc_r->MAC), AES_GCM_TAG_SIZE);

      auto enc_tuple = std::make_tuple(enc_data, IV, MAC);
      // my_printf("oblivious compared called for %d times\n",++num_calls);
      auto decrypted = cryptoEngine_.decrypt(enc_tuple);
      trainRecordSerialized *record = (trainRecordSerialized *)&(decrypted[0]);

      trainData_.X.vals[i] =
          (float *)calloc(WIDTH_X_HEIGHT_X_CHAN, sizeof(float));
      std::memcpy(trainData_.X.vals[i], record->data,
                  WIDTH_X_HEIGHT_X_CHAN * sizeof(float));

      trainData_.y.vals[i] = (float *)calloc(NUM_CLASSES, sizeof(float));
      std::memcpy(trainData_.y.vals[i], record->label,
                  NUM_CLASSES * sizeof(float));
    }
    trainData_.shallow = 0;
    return true;
  }
  return false;
}

void DNNTrainer::train() {

  int start = 0;
  float avg_loss = -1, loss = -1;

  while (get_current_batch(net_) < net_->max_batches) {
    auto prepared = prepareBatch(start);
    if (!prepared) {
      intitialSort();
      start = 0;
      prepared = prepareBatch(start);
    }
    // my_printf("starting iteration for batch number %d\n",
    // get_current_batch(net_));
    loss = train_network(net_, trainData_);
    // my_printf("* reported loss is: %f\n ",loss);
    if (avg_loss == -1)
      avg_loss = loss;

    avg_loss = avg_loss * .9 + loss * .1;
    my_printf("%ld: %f, %f avg, %f rate, %ld images\n", get_current_batch(net_),
              loss, avg_loss, get_current_rate(net_), *net_->seen);

    free_data(trainData_);
  }
}
}
}
}
