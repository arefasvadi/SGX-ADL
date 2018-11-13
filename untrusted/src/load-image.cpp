#include "load-image.h"
#include "common.h"
#include <CryptoEngine.hpp>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>

bool load_training_data(training_pub_params &par) {

  par.labels = get_labels((char *)par.label_path.c_str());
  par.plist = get_paths((char *)par.train_paths.c_str());
  par.paths = (char **)list_to_array(par.plist);
  par.total_records = par.plist->size;
  par.input_data = {0};

  par.input_data.X =
      load_image_paths(par.paths, par.total_records, par.width, par.height);
  par.input_data.y = load_labels_paths(par.paths, par.total_records, par.labels,
                                       par.num_classes, NULL);

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
