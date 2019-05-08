#pragma once

#include "CryptoEngine.hpp"
#include "common.h"
#include <vector>

#undef USE_SGX
#include "../../third_party/darknet/include/darknet.h"
matrix load_image_paths(char **paths, int n, int w, int h);
matrix load_labels_paths(char **paths, int n, char **labels, int k,
                         tree *hierarchy);
#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif

#include <string>

typedef struct training_pub_params {
  std::string label_path;
  // std::vector<std::string> labels;
  std::string train_paths;

  int total_records;
  int num_classes;

  int width;
  int height;
  int channels;

  data input_data;
  list *plist;
  char **paths;
  char **labels;

} training_pub_params;

bool load_training_data(training_pub_params &par);

bool serialize_training_data(training_pub_params &par,
                             std::vector<trainRecordSerialized> &out);

bool encrypt_training_data(
    sgx::untrusted::CryptoEngine<uint8_t> &crypto_engine,
    const std::vector<trainRecordSerialized> &in,
    std::vector<trainRecordEncrypted> &out);

void initialize_training_params_cifar(training_pub_params &param);

void initialize_data(training_pub_params &tr_pub_params,
                     std::vector<trainRecordSerialized> &plain_dataset,
                     std::vector<trainRecordEncrypted> &encrypted_dataset,
                     sgx::untrusted::CryptoEngine<uint8_t> &crypto_engine);

void random_id_assign(std::vector<trainRecordEncrypted> &encrypted_dataset);
