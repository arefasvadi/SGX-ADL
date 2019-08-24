#include "load-image.h"
#include "../enclave_u.h"
#include "app.h"
#include "common.h"
#include <CryptoEngine.hpp>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>

extern sgx_enclave_id_t global_eid;
extern json configs;


bool load_train_test_data(data_params &par) {

  std::string task = configs["task"];
  bool is_image = configs["data_config"]["is_image"];
  par.plist = get_paths((char *)par.data_paths.c_str());
  par.paths = (char **)list_to_array(par.plist);
  par.total_records = par.plist->size;
  par.input_data = {0};
  par.input_data.shallow = 0;
  if (is_image) {
    par.input_data.X =
      load_image_paths(par.paths, par.total_records, par.width, par.height);
    LOG_INFO("Total images %d Each image is are of length: %d\n", par.total_records, par.input_data.X.cols);
  } else if (configs["data_config"]["is_idash"]){
    par.input_data = load_data_idash(par.paths, par.total_records);
    par.input_data.y = make_matrix(par.total_records, par.num_classes);
  }
  else {
    LOG_ERROR("Data handler of this type not known!\n")
    abort();
  }
  if (task.compare(std::string("predict")) != 0) {
    par.labels = get_labels((char *)par.label_path.c_str());
    par.input_data.y = load_labels_paths(par.paths, par.total_records, par.labels,
                                       par.num_classes, NULL);
    LOG_INFO("Each label is are of length: %d\n", par.input_data.y.cols);
  }
  
  // TODO remember to delete
  // paths in plist
  // free_list too
  // free network too

  return true;
}

bool serialize_train_test_data(data_params &par,
                             std::vector<trainRecordSerialized> &out) {
  /* if (par.height * par.width * par.channels != WIDTH_X_HEIGHT_X_CHAN ||
      par.num_classes != NUM_CLASSES) {
    LOG_ERROR("Problems with image size or labels size!!\n");
    std::exit(1);
    // return false;
  } */

  out.resize(par.total_records);
  int cnt = 0;
  for (auto &t_record : out) {
    t_record.shuffleID = 0;
    t_record.data.resize(par.channels*par.height*par.width);
    t_record.label.resize(par.num_classes);
    // fill the labels
    std::memcpy(&t_record.label[0], par.input_data.y.vals[cnt],
                par.num_classes * sizeof(float));
    // fill the data
    std::memcpy(&t_record.data[0], par.input_data.X.vals[cnt],
                par.height * par.width * par.channels * sizeof(float));
    ++cnt;
  }

  return true;
}

bool encrypt_train_test_data(sgx::untrusted::CryptoEngine<uint8_t> &crypto_engine,
                           const std::vector<trainRecordSerialized> &in,
                           std::vector<trainRecordEncrypted> &out) {

  out.resize(in.size());
  int cnt = 0;
  for (const auto &record : in) {
    std::vector<uint8_t> buff((record.data.size()+record.label.size())*sizeof(float)+sizeof(record.shuffleID));
    std::memcpy(&buff[0], &record.data[0], record.data.size() * sizeof(float));
    std::memcpy(&buff[record.data.size() * sizeof(float)], &record.label[0], record.label.size() * sizeof(float));
    std::memcpy(&buff[(record.data.size()+record.label.size()) * sizeof(float)], &record.shuffleID, sizeof(record.shuffleID));
    auto enc = crypto_engine.encrypt(buff);
    trainRecordEncrypted enc_rec;
    enc_rec.encData.resize((record.data.size()+record.label.size())*sizeof(float)+sizeof(record.shuffleID));
    auto enc_data = std::get<0>(enc);
    auto IV = std::get<1>(enc);
    auto MAC = std::get<2>(enc);
    std::memcpy(&enc_rec.encData[0], &enc_data[0], enc_rec.encData.size());
    std::memcpy(enc_rec.IV, &IV[0], AES_GCM_IV_SIZE);
    std::memcpy(enc_rec.MAC, &MAC[0], AES_GCM_TAG_SIZE);
    out[cnt] = enc_rec;
    ++cnt;
  }
  return true;
}

void handle_idash_encrypted(data_params &predict_pub_params,
                            std::vector<trainRecordEncrypted> &predict_encrypted_dataset) {

  std::string pred_file = configs["data_config"]["enc_predict_path"];
  const int TOTAL_PRED_RECORDS = configs["data_config"]["predictSize"];
  predict_pub_params.total_records = TOTAL_PRED_RECORDS;
  auto enc_preds_file_names = read_file_text(pred_file.c_str());
  if (enc_preds_file_names.size() != predict_pub_params.total_records) {
    LOG_ERROR("the number of files in %s is different from predicSize in json file : %d vs %d\n",pred_file.c_str(),
      enc_preds_file_names.size(),predict_pub_params.total_records);
    abort();
  }
  predict_encrypted_dataset.resize(predict_pub_params.total_records);
  std::string iv_f = "";
  std::string tag_f = "";
  std::string enc_f = "";
  for (int i=0;i<enc_preds_file_names.size();++i) {
    enc_f = enc_preds_file_names[i] + ".enc";
    iv_f = enc_preds_file_names[i] + ".iv";
    tag_f = enc_preds_file_names[i] + ".tag";
    predict_encrypted_dataset[i].encData = read_file_binary(enc_f.c_str());
    
    auto iv_ = read_file_binary(iv_f.c_str());
    std::memcpy(predict_encrypted_dataset[i].IV, &iv_[0], AES_GCM_IV_SIZE);

    auto tag_ = read_file_binary(tag_f.c_str());
    std::memcpy(predict_encrypted_dataset[i].MAC, &tag_[0], AES_GCM_TAG_SIZE);
  }
  
}

void initialize_train_params(data_params &param) {
  param.label_path = configs["data_config"]["labels_path"];
  param.data_paths = configs["data_config"]["train_path"];
  param.width = configs["data_config"]["dims"][0];
  param.height = configs["data_config"]["dims"][1];
  param.channels = configs["data_config"]["dims"][2];
  param.num_classes = configs["data_config"]["num_classes"];
}

void initialize_test_params(data_params &param) {
  param.label_path = configs["data_config"]["labels_path"];
  param.data_paths = configs["data_config"]["test_path"];
  param.width = configs["data_config"]["dims"][0];
  param.height = configs["data_config"]["dims"][1];
  param.channels = configs["data_config"]["dims"][2];
  param.num_classes = configs["data_config"]["num_classes"];
}

void initialize_predict_params(data_params &param) {
  param.label_path = configs["data_config"]["labels_path"];
  param.data_paths = configs["data_config"]["predict_path"];
  param.width = configs["data_config"]["dims"][0];
  param.height = configs["data_config"]["dims"][1];
  param.channels = configs["data_config"]["dims"][2];
  param.num_classes = configs["data_config"]["num_classes"];
}

/* initializing dataset params */
/* void initialize_train_params_cifar(data_params &param) {
  param.label_path =
      "/home/aref/projects/SGX-ADL/test/config/cifar10/labels.txt";
  param.train_paths =
      "/home/aref/projects/SGX-ADL/test/config/cifar10/train.list";
  param.width = 28;
  param.height = 28;
  param.channels = 3;
  param.num_classes = 10;
} */

/* void initialize_test_params_cifar(data_params &param) {
  param.label_path =
      "/home/aref/projects/SGX-ADL/test/config/cifar10/labels.txt";
  param.train_paths =
      "/home/aref/projects/SGX-ADL/test/config/cifar10/test.list";
  param.width = 28;
  param.height = 28;
  param.channels = 3;
  param.num_classes = 10;
} */

/* void initialize_train_params_imagenet(data_params &param) {
  param.label_path =
      "/home/aref/projects/SGX-ADL/test/config/imagenet_sample/imagenet.labels.list";
  param.train_paths =
      "/home/aref/projects/SGX-ADL/test/config/imagenet_sample/darknet_imagenet1k_train_random_50000.list";
  param.width = 256;
  param.height = 256;
  param.channels = 3;
  param.num_classes = 1000;
} */

/* void initialize_test_params_imagenet(data_params &param) {
  param.label_path =
      "/home/aref/projects/SGX-ADL/test/config/cifar10/labels.txt";
  param.train_paths =
      "/home/aref/projects/SGX-ADL/test/config/cifar10/test.list";
  param.width = 28;
  param.height = 28;
  param.channels = 3;
  param.num_classes = 10;
  LOG_ERROR("To be implemented!\n");
  abort();
} */

void initialize_data(data_params &tr_pub_params, data_params &test_pub_params, data_params &predict_pub_params,
                     std::vector<trainRecordSerialized> &plain_dataset,
                     std::vector<trainRecordEncrypted> &encrypted_dataset,
                     std::vector<trainRecordSerialized> &test_plain_dataset,
                     std::vector<trainRecordEncrypted> &test_encrypted_dataset,
                     std::vector<trainRecordSerialized> &predict_plain_dataset,
                     std::vector<trainRecordEncrypted> &predict_encrypted_dataset,
                     sgx::untrusted::CryptoEngine<uint8_t> &crypto_engine) {
  
  std::string task = configs["task"];
  std::string sec = configs["security"];
  if (task.compare(std::string("train")) == 0) {
    initialize_train_params(tr_pub_params);
    load_train_test_data(tr_pub_params);
    serialize_train_test_data(tr_pub_params, plain_dataset);
    if (sec.compare(std::string("privacy_integrity")) == 0) {
      encrypt_train_test_data(crypto_engine, plain_dataset, encrypted_dataset);    
    }
  }
  else if (task.compare(std::string("test")) == 0) {
    initialize_test_params(test_pub_params);
    load_train_test_data(test_pub_params);
    serialize_train_test_data(test_pub_params, test_plain_dataset);
    if (sec.compare(std::string("privacy_integrity")) == 0) {
      encrypt_train_test_data(crypto_engine, test_plain_dataset, test_encrypted_dataset);    
    }
  }
  else if (task.compare(std::string("predict")) == 0) {
    initialize_predict_params(predict_pub_params);
    if (configs["data_config"]["is_idash"] && sec.compare(std::string("privacy_integrity")) == 0) {
      handle_idash_encrypted(predict_pub_params, predict_encrypted_dataset);
      return;
    }
    load_train_test_data(predict_pub_params);
    serialize_train_test_data(predict_pub_params, predict_plain_dataset);
    if (sec.compare(std::string("privacy_integrity")) == 0) {
      encrypt_train_test_data(crypto_engine, predict_plain_dataset, predict_encrypted_dataset);    
    }
  }

  /* initialize_train_params_cifar(tr_pub_params);
  load_train_test_data(tr_pub_params);
  serialize_train_test_data(tr_pub_params, plain_dataset);
  encrypt_train_test_data(crypto_engine, plain_dataset, encrypted_dataset);

  initialize_test_params_cifar(test_pub_params);
  load_train_test_data(test_pub_params);
  serialize_train_test_data(test_pub_params, test_plain_dataset);
  encrypt_train_test_data(crypto_engine, test_plain_dataset, test_encrypted_dataset); */

  /* initialize_train_params_imagenet(tr_pub_params);
  load_train_test_data(tr_pub_params);
  serialize_train_test_data(tr_pub_params, plain_dataset);
  encrypt_train_test_data(crypto_engine, plain_dataset, encrypted_dataset); */

  /* initialize_test_params_imagenet(test_pub_params);
  load_train_test_data(test_pub_params);
  serialize_train_test_data(test_pub_params, test_plain_dataset);
  encrypt_train_test_data(crypto_engine, test_plain_dataset, test_encrypted_dataset); */
  //plain_dataset.clear();
}

void random_id_assign(std::vector<trainRecordEncrypted> &encrypted_dataset) {
  LOG_TRACE("entered in random id assign\n");
  constexpr int group_size = 5;
  const int dataset_size = encrypted_dataset.size();
  LOG_INFO("Entered in random_id_assign in untrusted zone for dataset of size "
           "%d each being %d bytes\n",
           dataset_size, sizeof(trainRecordEncrypted));
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
        LOG_ERROR("ecall assign random_id enclave caused problem! the error is "
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
        LOG_ERROR("ecall assign random_id enclave caused problem! the error is "
                  "%#010X   \n",
                  ret);
        abort();
      }

      break;
    }
  }
  LOG_TRACE("finished in random id assign\n");
}


std::vector<uint8_t> read_file_binary(const char* file_name) {
    std::ifstream file(file_name, std::ios::in | std::ios::binary);
    file.unsetf(std::ios::skipws);
    std::streampos fileSize;
    file.seekg(0, std::ios::end);
    fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> contents;
    contents.reserve(fileSize);
    contents.insert(contents.begin(),
                         std::istream_iterator<uint8_t>(file),
                         std::istream_iterator<uint8_t>());
    file.close();
    return contents;
}

bool write_file_binary(const char* file_name, const std::vector<uint8_t>& contents) {
  std::ofstream file(file_name, std::ios::out | std::ios::binary);
  file.write((const char*)contents.data(), contents.size());
  file.close();
  return true;
}

std::vector<std::string> read_file_text(const char* file_name) {
  std::ifstream file(file_name, std::ios::in | std::ios::binary);
  std::vector<std::string> contents;
  copy(std::istream_iterator<std::string>(file),
         std::istream_iterator<std::string>(),
         std::back_inserter(contents));
  return contents;
}
