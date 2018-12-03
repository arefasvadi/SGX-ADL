#include "load-image.h"
#include "../enclave_u.h"
#include "common.h"
#include <CryptoEngine.hpp>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>

extern sgx_enclave_id_t global_eid;

bool load_training_data(training_pub_params &par) {

  par.labels = get_labels((char *)par.label_path.c_str());
  par.plist = get_paths((char *)par.train_paths.c_str());
  par.paths = (char **)list_to_array(par.plist);
  par.total_records = par.plist->size;
  par.input_data = {0};
  par.input_data.shallow = 0;
  par.input_data.X =
      load_image_paths(par.paths, par.total_records, par.width, par.height);
  std::cout << "Each image is are of length: " << par.input_data.X.cols << "\n";
  par.input_data.y = load_labels_paths(par.paths, par.total_records, par.labels,
                                       par.num_classes, NULL);
  std::cout << "Each label is are of length: " << par.input_data.y.cols << "\n";
  // TODO remember to delete
  // paths in plist
  // free_list too
  // free network too

  return true;
}

bool serialize_training_data(training_pub_params &par,
                             std::vector<trainRecordSerialized> &out) {
  if (par.height * par.width * par.channels != WIDTH_X_HEIGHT_X_CHAN ||
      par.num_classes != NUM_CLASSES) {
    std::cout << "Problems with image size or labels size!!\n";
    std::exit(1);
    // return false;
  }

  out.resize(par.total_records);
  int cnt = 0;
  for (auto &t_record : out) {
    t_record.shuffleID = 0;
    // fill the labels
    std::memcpy(t_record.label, par.input_data.y.vals[cnt],
                NUM_CLASSES * sizeof(float));
    // fill the data
    std::memcpy(t_record.data, par.input_data.X.vals[cnt],
                WIDTH_X_HEIGHT_X_CHAN * sizeof(float));
    ++cnt;
  }

  return true;
}

bool encrypt_training_data(sgx::untrusted::CryptoEngine<uint8_t> &crypto_engine,
                           const std::vector<trainRecordSerialized> &in,
                           std::vector<trainRecordEncrypted> &out) {

  out.resize(in.size());
  int cnt = 0;
  for (const auto &record : in) {
    std::vector<uint8_t> buff(sizeof(record));
    std::memcpy(&buff[0], &record, sizeof(record));
    auto enc = crypto_engine.encrypt(buff);
    trainRecordEncrypted enc_rec;
    auto enc_data = std::get<0>(enc);
    auto IV = std::get<1>(enc);
    auto MAC = std::get<2>(enc);
    std::memcpy(&enc_rec.encData, &enc_data[0], sizeof(trainRecordSerialized));
    std::memcpy(enc_rec.IV, &IV[0], AES_GCM_IV_SIZE);
    std::memcpy(enc_rec.MAC, &MAC[0], AES_GCM_TAG_SIZE);
    out[cnt] = enc_rec;
    ++cnt;
  }
  return true;
}

/* initializing dataset params */
void initialize_training_params_cifar(training_pub_params &param) {
  param.label_path =
      "/home/aref/projects/SGX-DDL/test/config/cifar10/labels.txt";
  param.train_paths =
      "/home/aref/projects/SGX-DDL/test/config/cifar10/train.list";
  param.width = 28;
  param.height = 28;
  param.channels = 3;
  param.num_classes = 10;
}

void initialize_data(training_pub_params &tr_pub_params,
                     std::vector<trainRecordSerialized> &plain_dataset,
                     std::vector<trainRecordEncrypted> &encrypted_dataset,
                     sgx::untrusted::CryptoEngine<uint8_t> &crypto_engine) {
  initialize_training_params_cifar(tr_pub_params);
  load_training_data(tr_pub_params);
  serialize_training_data(tr_pub_params, plain_dataset);
  encrypt_training_data(crypto_engine, plain_dataset, encrypted_dataset);
  plain_dataset.clear();
}

void random_id_assign(std::vector<trainRecordEncrypted> &encrypted_dataset) {
  constexpr int group_size = 5;
  const int dataset_size = encrypted_dataset.size();
  std::cout
      << "Entered in random_id_assign in untrusted zone for dataset of size "
      << dataset_size << " each being "  << sizeof(trainRecordEncrypted)  << " bytes!\n";
  int count = 0;
  while (true) {
    if (count + group_size < dataset_size) {
      // ecall on count, count+groupsize-1 index
      sgx_status_t ret = SGX_ERROR_UNEXPECTED;
      ret = ecall_assign_random_id(global_eid,
                                   (unsigned char *)&(encrypted_dataset[count]),
                                   group_size * sizeof(trainRecordEncrypted));
      // std::cout << "calling enclave..\n";
      if (ret != SGX_SUCCESS) {
        printf("ecall assign random_id enclave caused problem! the error is "
               "%#010X \n",
               ret);
        abort();
      }
      count += group_size;

    } else if (count == dataset_size) {
      break;
    } else {
      // ecall on count, until the end of list
      sgx_status_t ret = SGX_ERROR_UNEXPECTED;
      ret = ecall_assign_random_id(
          global_eid, (unsigned char *)&(encrypted_dataset[count]),
          (dataset_size - count) * sizeof(trainRecordEncrypted));
      if (ret != SGX_SUCCESS) {
        printf("ecall assign random_id enclave caused problem! the error is "
               "%#010X   \n",
               ret);
        abort();
      }

      break;
    }
  }
}
