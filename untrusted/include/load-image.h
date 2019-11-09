#pragma once

#include "CryptoEngine.hpp"
#include "common.h"
#include <vector>
#include <nlohmann/json.hpp>
//#include "fbs_gen_code/plainimagemeta_generated.h"

using json = nlohmann::json;
#include "darknet.h"

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif

#include <string>

typedef struct trainRecordSerialized {
  //float data[WIDTH_X_HEIGHT_X_CHAN];
  std::vector<float> data;
  //float label[NUM_CLASSES];
  std::vector<float> label;
  unsigned int shuffleID;
} trainRecordSerialized;

typedef struct trainRecordEncrypted {
  //trainRecordSerialized encData;
  std::vector<uint8_t> encData;
  unsigned char IV[AES_GCM_IV_SIZE];
  unsigned char MAC[AES_GCM_TAG_SIZE];
} trainRecordEncrypted;

typedef struct data_params {
  std::string label_path;
  // std::vector<std::string> labels;
  std::string data_paths;

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

std::vector<uint8_t> read_file_binary(const char* file_name);
bool write_file_binary(const char* file_name, const std::vector<uint8_t>& contents);
std::vector<std::string> read_file_text(const char* file_name);

bool load_train_test_data(data_params &par);

bool serialize_train_test_data(data_params &par,
                               std::vector<trainRecordSerialized> &out);

bool encrypt_train_test_data(
    sgx::untrusted::CryptoEngine<uint8_t> &crypto_engine,
    const std::vector<trainRecordSerialized> &in,
    std::vector<trainRecordEncrypted> &out);

//void initialize_train_params_cifar(data_params &param);
//void initialize_test_params_cifar(data_params &param);

//void initialize_train_params_imagenet(data_params &param);
//void initialize_test_params_imagenet(data_params &param);

void initialize_data(data_params &tr_pub_params, data_params &test_pub_params, data_params &predict_pub_params,
                     std::vector<trainRecordSerialized> &plain_dataset,
                     std::vector<trainRecordEncrypted> &encrypted_dataset,
                     std::vector<trainRecordSerialized> &test_plain_dataset,
                     std::vector<trainRecordEncrypted> &test_encrypted_dataset,
                     std::vector<trainRecordSerialized> &predict_plain_dataset,
                     std::vector<trainRecordEncrypted> &predict_encrypted_dataset,
                     sgx::untrusted::CryptoEngine<uint8_t> &crypto_engine);

void random_id_assign(std::vector<trainRecordEncrypted> &encrypted_dataset);

//std::vector<uint8_t> flatBuffInitImageMeta();
// PlainImage flatBuffInitPlainImage();
// PlainImageSet flatBuffInitImageDataSet();

// PlainLabelMeta flatBuffInitLabelMeta();
// PlainLabel flatBuffInitPlainLabel();
// PlainLabelSet flatBuffInitLabelDataSet();

// PlainImageLabelMeta flatBuffInitImageLabelMeta();
// PlainImageLabel flatBuffInitPlainImageLabel();
// PlainImageLabelSet flatBuffInitImageLabelDataSet();