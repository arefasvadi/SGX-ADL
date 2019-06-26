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

typedef struct data_params {
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

} data_params;

bool load_train_test_data(data_params &par);

bool serialize_train_test_data(data_params &par,
                               std::vector<trainRecordSerialized> &out);

bool encrypt_train_test_data(
    sgx::untrusted::CryptoEngine<uint8_t> &crypto_engine,
    const std::vector<trainRecordSerialized> &in,
    std::vector<trainRecordEncrypted> &out);

void initialize_train_params_cifar(data_params &param);
void initialize_test_params_cifar(data_params &param);

void initialize_data(data_params &tr_pub_params, data_params &test_pub_params,
                     std::vector<trainRecordSerialized> &plain_dataset,
                     std::vector<trainRecordEncrypted> &encrypted_dataset,
                     std::vector<trainRecordSerialized> &test_plain_dataset,
                     std::vector<trainRecordEncrypted> &test_encrypted_dataset,
                     sgx::untrusted::CryptoEngine<uint8_t> &crypto_engine);

void random_id_assign(std::vector<trainRecordEncrypted> &encrypted_dataset);
