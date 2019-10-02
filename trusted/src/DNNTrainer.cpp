#include "DNNTrainer.h"
#include "sgx_trts.h"
#include <string>

namespace sgx {
namespace trusted {
namespace darknet {
DNNTrainer::DNNTrainer(const char *config_file_path,
                       const std::string &param_dir_path,
                       const std::string &data_dir_path,
                       SecStrategyType security_mode, int width, int height,
                       int channels, int num_classes, int train_size,
                       int test_size, int predict_size)
    : cryptoEngine_(sgt::CryptoEngine<uint8_t>::Key{
          1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
      configIO_(std::unique_ptr<DNNConfigIO>(
          new DNNConfigIO(std::string(config_file_path), cryptoEngine_))) {
  trainData_.shallow = 0;
  testData_.shallow = 0;

  secMode = security_mode;

  w = width;
  h = height;
  c = channels;
  n_classes = num_classes;

  trainData_.w = width;
  trainData_.h = height;
  testData_.w = width;
  testData_.h = height;
  predictData_.w = width;
  predictData_.h = height;

  trainSize_ = train_size;
  testSize_ = test_size;
  predictSize_ = predict_size;

  predResults_.resize(predictSize_ * n_classes);
}

#if defined(USE_SGX) && defined(USE_SGX_BLOCKING)
bool DNNTrainer::loadNetworkConfigBlocked() {
  LOG_TRACE("entered load network config blocked\n")
  bool res = configIO_->receiveFromUntrusted(ocall_load_net_config);
  if (!res) {
    LOG_ERROR("Cannot properly move config into enclave!\n")
    return false;
  }
  net_blcoked_ = load_network_blocked((char *)configIO_->getNetConfig().c_str(),
                                      nullptr, 1);
  LOG_TRACE("exitted load network config blocked\n")
  return true;
}

void DNNTrainer::loadTrainDataBlocked(
    std::shared_ptr<sgt::BlockedBuffer<float, 2>> XBlocked_,
    std::shared_ptr<sgt::BlockedBuffer<float, 2>> YBlocked_) {
  trainXBlocked_ = XBlocked_;
  trainYBlocked_ = YBlocked_;
}

bool DNNTrainer::prepareBatchTrainBlocked(int start) {
  static int stt = 0;
  // if (start + net_blcoked_->batch <= trainSize_) {
  // LOG_DEBUG("Enetered to get a new batch with satrt %d and batch size
  // %d\n",stt, net_blcoked_->batch)
  BLOCK_ENGINE_INIT_FOR_LOOP(trainXBlocked_, x_valid_range, x_block_val_ptr,
                             float);
  BLOCK_ENGINE_INIT_FOR_LOOP(trainYBlocked_, y_valid_range, y_block_val_ptr,
                             float);
  BLOCK_ENGINE_INIT_FOR_LOOP(net_blcoked_->input, in_valid_range,
                             in_block_val_ptr, float);
  BLOCK_ENGINE_INIT_FOR_LOOP(net_blcoked_->truth, out_valid_range,
                             out_block_val_ptr, float);
  for (int i = 0; i < net_blcoked_->batch; ++i) {
    for (int j = 0; j < w * h * c; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(trainXBlocked_, x_valid_range,
                                          x_block_val_ptr, false, x_index_var,
                                          (stt + i) % trainSize_, j);
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_1D(net_blcoked_->input, in_valid_range,
                                          in_block_val_ptr, true, in_index_var,
                                          i * w * h * c + j);
      *(in_block_val_ptr + in_index_var - in_valid_range.block_requested_ind) =
          *(x_block_val_ptr + x_index_var - x_valid_range.block_requested_ind);
    }
    for (int j = 0; j < NUM_CLASSES; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(trainYBlocked_, y_valid_range,
                                          y_block_val_ptr, false, y_index_var,
                                          (stt + i) % trainSize_, j);
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_1D(net_blcoked_->truth, out_valid_range,
                                          out_block_val_ptr, true,
                                          out_index_var, i * NUM_CLASSES + j);
      *(out_block_val_ptr + out_index_var -
        out_valid_range.block_requested_ind) =
          *(y_block_val_ptr + y_index_var - y_valid_range.block_requested_ind);
    }
  }
  BLOCK_ENGINE_LAST_UNLOCK(trainXBlocked_, x_valid_range)
  BLOCK_ENGINE_LAST_UNLOCK(trainYBlocked_, y_valid_range)
  BLOCK_ENGINE_LAST_UNLOCK(net_blcoked_->input, in_valid_range)
  BLOCK_ENGINE_LAST_UNLOCK(net_blcoked_->truth, out_valid_range)
  stt = stt + net_blcoked_->batch;
  // LOG_DEBUG("Finished to get a new batch with satrt %d and batch size
  // %d\n",stt, net_blcoked_->batch)
  return true;
  //}
  // return false;
}

bool DNNTrainer::prepareBatchTrainBlockedDirect() {
  static int stt = 0;
  // if (start + net_blcoked_->batch <= trainSize_) {
  // LOG_DEBUG("Enetered to get a new batch with satrt %d and batch size
  // %d\n",stt, net_blcoked_->batch)
  BLOCK_ENGINE_INIT_FOR_LOOP(net_blcoked_->input, in_valid_range,
                             in_block_val_ptr, float);
  BLOCK_ENGINE_INIT_FOR_LOOP(net_blcoked_->truth, out_valid_range,
                             out_block_val_ptr, float);
  std::vector<uint8_t> p_data(sizeof(trainRecordSerialized));
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
  for (int i = 0; i < net_blcoked_->batch; ++i) {
    res = ocall_get_records_plain(1, (stt + i) % trainSize_, &p_data[0],
                                  sizeof(trainRecordSerialized));
    if (res !=
          SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
      LOG_ERROR("ocall get records caused problem! the error is "
                "%#010X \n",
                res);
      abort();
    }
    trainRecordSerialized *record = (trainRecordSerialized *)&(p_data[0]);

    for (int j = 0; j < w * h * c; ++j) {

      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_1D(net_blcoked_->input, in_valid_range,
                                          in_block_val_ptr, true, in_index_var,
                                          i * w * h * c + j);
      *(in_block_val_ptr + in_index_var - in_valid_range.block_requested_ind) =
          record->data[j];
    }

    for (int j = 0; j < NUM_CLASSES; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_1D(net_blcoked_->truth, out_valid_range,
                                          out_block_val_ptr, true,
                                          out_index_var, i * NUM_CLASSES + j);
      *(out_block_val_ptr + out_index_var -
        out_valid_range.block_requested_ind) = record->label[j];
    }
  }

  BLOCK_ENGINE_LAST_UNLOCK(net_blcoked_->input, in_valid_range)
  BLOCK_ENGINE_LAST_UNLOCK(net_blcoked_->truth, out_valid_range)
  stt = stt + net_blcoked_->batch;
  // LOG_DEBUG("Finished to get a new batch with satrt %d and batch size
  // %d\n",stt, net_blcoked_->batch)
  return true;
  //}
  // return false;
}

void DNNTrainer::trainBlocked() {
  int start = 0;
  float avg_loss = -1, loss = -1;
  float AVG_ACC = -1;
  int epochs = 0;
  while (get_current_batch_blocked(net_blcoked_) < net_blcoked_->max_batches) {
#ifdef DO_BLOCK_INPUT
    auto prepared = prepareBatchTrainBlocked(start);
#else
    auto prepared = prepareBatchTrainBlockedDirect();
#endif
    /* if (!prepared) {
      //intitialSort();
      start = 0;
      prepared = prepareBatchTrainBlocked(start);
    } */
    // printf("starting iteration for batch number %d\n",
    // get_current_batch(net_));
    loss = train_network_blocked(net_blcoked_);
    // printf("* reported loss is: %f\n ",loss);

    if (avg_loss == -1) {
      avg_loss = loss;
    }

    avg_loss = avg_loss * .9 + loss * .1;
    LOG_INFO("iteration %ld: loss = %f, avg loss = %f avg, learning rate = %f "
             "rate, images processed = %ld images\n",
             get_current_batch_blocked(net_blcoked_), loss, avg_loss,
             (double)get_current_rate_blocked(net_blcoked_),
             *net_blcoked_->seen);
  }
}

#endif
bool DNNTrainer::loadNetworkConfig() {
  LOG_TRACE("entered load network config\n")
  bool res = configIO_->receiveFromUntrusted(ocall_load_net_config);
  if (!res) {
    LOG_ERROR("Cannot properly move config into enclave!\n")
    return false;
  }
  net_ = load_network((char *)configIO_->getNetConfig().c_str(), nullptr, 1);
  LOG_TRACE("exitted load network config\n")
  return true;
}

bool DNNTrainer::prepareBatchTrainEncrypted(int start) {
  static int stt = 0;
  // if (start + net_->batch <= trainSize_) {
  // int candidates[net_->batch];
  // for (int i = 0; i < net_->batch; ++i) {
  //   candidates[i] = rand() % trainSize_;
  // }
  std::vector<uint8_t> enc_data(sizeof(float) * (w * h * c + n_classes) +
                                sizeof(unsigned int));
  std::array<uint8_t, 12> IV;
  std::array<uint8_t, 16> MAC;
  sgx_status_t res = SGX_ERROR_UNEXPECTED;

  trainData_.X.rows = net_->batch;
  trainData_.X.cols = w * h * c;
  trainData_.X.vals = (float **)calloc(trainData_.X.rows, sizeof(float *));

  trainData_.y.rows = net_->batch;
  trainData_.y.cols = n_classes;
  trainData_.y.vals = (float **)calloc(trainData_.y.rows, sizeof(float *));

  for (int i = 0; i < net_->batch; ++i) {
    res = ocall_get_records_encrypted(1, (stt + i) % trainSize_, &enc_data[0],
                                      enc_data.size(), &IV[0], &MAC[0]);
    // res = ocall_get_records_encrypted(1, candidates[i], &enc_data[0],
    //                                   enc_data.size(),&IV[0],&MAC[0]);
    if (res !=
          SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
      LOG_ERROR("ocall get records caused problem! the error is "
                "%#010X \n",
                res);
      abort();
    }

    auto enc_tuple = std::make_tuple(enc_data, IV, MAC);
    auto decrypted = cryptoEngine_.decrypt(enc_tuple);

    trainData_.X.vals[i] = (float *)calloc(w * h * c, sizeof(float));
    std::memcpy(trainData_.X.vals[i], &decrypted[0], w * h * c * sizeof(float));

    trainData_.y.vals[i] = (float *)calloc(n_classes, sizeof(float));
    std::memcpy(trainData_.y.vals[i], &decrypted[w * h * c * sizeof(float)],
                n_classes * sizeof(float));
  }
  stt += net_->batch;
  trainData_.shallow = 0;
  return true;
  //}
  // return false;
}

bool DNNTrainer::prepareBatchTestEncrypted(int start) {
  if (start + net_->batch <= testSize_) {
    // LOG_DEBUG("prepare test encrypted with start index %d\n",start)
    std::vector<uint8_t> enc_data(sizeof(float) * (w * h * c + n_classes) +
                                  sizeof(unsigned int));
    std::array<uint8_t, 12> IV;
    std::array<uint8_t, 16> MAC;
    sgx_status_t res = SGX_ERROR_UNEXPECTED;

    testData_.X.rows = net_->batch;
    testData_.X.cols = w * h * c;
    testData_.X.vals = (float **)calloc(testData_.X.rows, sizeof(float *));

    testData_.y.rows = net_->batch;
    testData_.y.cols = n_classes;
    testData_.y.vals = (float **)calloc(testData_.y.rows, sizeof(float *));

    for (int i = 0; i < net_->batch; ++i) {
      res = ocall_get_records_encrypted(2, start + i, &enc_data[0],
                                        enc_data.size(), &IV[0], &MAC[0]);
      if (res !=
          SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
        LOG_ERROR("ocall get records caused problem! the error is "
                  "%#010X \n",
                  res);
        abort();
      }
      auto enc_tuple = std::make_tuple(enc_data, IV, MAC);
      auto decrypted = cryptoEngine_.decrypt(enc_tuple);

      testData_.X.vals[i] = (float *)calloc(w * h * c, sizeof(float));
      std::memcpy(testData_.X.vals[i], &decrypted[0],
                  w * h * c * sizeof(float));

      testData_.y.vals[i] = (float *)calloc(n_classes, sizeof(float));
      std::memcpy(testData_.y.vals[i], &decrypted[w * h * c * sizeof(float)],
                  n_classes * sizeof(float));
    }
    testData_.shallow = 0;
    return true;
  }
  return false;
}

bool DNNTrainer::prepareBatchPredictEncrypted(int start) {
  if (start + net_->batch <= predictSize_) {
    // LOG_DEBUG("prepare test encrypted with start index %d\n",start)
    std::vector<uint8_t> enc_data(sizeof(float) * (w * h * c + n_classes) +
                                  sizeof(unsigned int));
    std::array<uint8_t, 12> IV;
    std::array<uint8_t, 16> MAC;
    sgx_status_t res = SGX_ERROR_UNEXPECTED;

    predictData_.X.rows = net_->batch;
    predictData_.X.cols = w * h * c;
    predictData_.X.vals =
        (float **)calloc(predictData_.X.rows, sizeof(float *));

    predictData_.y.rows = net_->batch;
    predictData_.y.cols = n_classes;
    predictData_.y.vals =
        (float **)calloc(predictData_.y.rows, sizeof(float *));

    for (int i = 0; i < net_->batch; ++i) {
      res = ocall_get_records_encrypted(3, start + i, &enc_data[0],
                                        enc_data.size(), &IV[0], &MAC[0]);
      if (res !=
          SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
        LOG_ERROR("ocall get records caused problem! the error is "
                  "%#010X \n",
                  res);
        abort();
      }
      auto enc_tuple = std::make_tuple(enc_data, IV, MAC);
      auto decrypted = cryptoEngine_.decrypt(enc_tuple);

      predictData_.X.vals[i] = (float *)calloc(w * h * c, sizeof(float));
      std::memcpy(predictData_.X.vals[i], &decrypted[0],
                  w * h * c * sizeof(float));

      predictData_.y.vals[i] = (float *)calloc(n_classes, sizeof(float));
      std::memcpy(predictData_.y.vals[i], &decrypted[w * h * c * sizeof(float)],
                  n_classes * sizeof(float));
    }
    predictData_.shallow = 0;
    return true;
  }
  return false;
}

bool DNNTrainer::prepareBatchTrainPlain(int start) {
  static int stt = 0;
  // if (start + net_->batch <= trainSize_) {
  // int label_counts[NUM_CLASSES] = {};

  // int candidates[net_->batch];
  // for (int i=0;i<net_->batch;++i) {
  //  candidates[i] = rand() % trainSize_;
  //}
  std::vector<uint8_t> p_data(sizeof(float) * (w * h * c + n_classes));
  sgx_status_t res = SGX_ERROR_UNEXPECTED;

  trainData_.X.rows = net_->batch;
  trainData_.X.cols = w * h * c;
  trainData_.X.vals = (float **)calloc(trainData_.X.rows, sizeof(float *));

  trainData_.y.rows = net_->batch;
  trainData_.y.cols = n_classes;
  trainData_.y.vals = (float **)calloc(trainData_.y.rows, sizeof(float *));

  for (int i = 0; i < net_->batch; ++i) {
    /* res = ocall_get_records_plain(1, start + i, &p_data[0],
                                      sizeof(trainRecordSerialized)); */
    res = ocall_get_records_plain(1, (stt + i) % trainSize_, &p_data[0],
                                  p_data.size());
    /* res = ocall_get_records_plain(1, candidates[i], &p_data[0],
                                      sizeof(trainRecordSerialized)); */

    if (res !=
          SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
      LOG_ERROR("ocall get records caused problem! the error is "
                "%#010X \n",
                res);
      abort();
    }

    trainData_.X.vals[i] = (float *)calloc(w * h * c, sizeof(float));
    std::memcpy(trainData_.X.vals[i], &p_data[0], w * h * c * sizeof(float));

    trainData_.y.vals[i] = (float *)calloc(n_classes, sizeof(float));
    std::memcpy(trainData_.y.vals[i], &p_data[w * h * c * sizeof(float)],
                n_classes * sizeof(float));

    /* for (int kk = 0;kk<NUM_CLASSES;++kk) {
      if (record->label[kk] == 1.0) {
        label_counts[kk]++;
      }
    } */
  }
  stt += net_->batch;
  trainData_.shallow = 0;
  /* std::string counti("Label Counts for this batch: ");
  for (int kk = 0;kk<NUM_CLASSES;++kk) {
      counti += ", " + std::to_string(label_counts[kk]);
  }
  LOG_DEBUG("%s\n",counti.c_str()); */
  return true;
  //}
  // return false;
}

bool DNNTrainer::prepareBatchTestPlain(int start) {
  if (start + net_->batch <= testSize_) {
    std::vector<uint8_t> p_data(sizeof(float) * (w * h * c + n_classes));
    sgx_status_t res = SGX_ERROR_UNEXPECTED;

    testData_.X.rows = net_->batch;
    testData_.X.cols = w * h * c;
    testData_.X.vals = (float **)calloc(testData_.X.rows, sizeof(float *));

    testData_.y.rows = net_->batch;
    testData_.y.cols = n_classes;
    testData_.y.vals = (float **)calloc(testData_.y.rows, sizeof(float *));

    for (int i = 0; i < net_->batch; ++i) {
      res = ocall_get_records_plain(2, start + i, &p_data[0], p_data.size());
      if (res !=
          SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
        LOG_ERROR("ocall get records caused problem! the error is "
                  "%#010X \n",
                  res);
        abort();
      }
      testData_.X.vals[i] = (float *)calloc(w * h * c, sizeof(float));
      std::memcpy(testData_.X.vals[i], &p_data[0], w * h * c * sizeof(float));

      testData_.y.vals[i] = (float *)calloc(n_classes, sizeof(float));
      std::memcpy(testData_.y.vals[i], &p_data[w * h * c * sizeof(float)],
                  n_classes * sizeof(float));
    }
    testData_.shallow = 0;
    return true;
  }
  return false;
}

bool DNNTrainer::prepareBatchPredictPlain(int start) {
  if (start + net_->batch <= predictSize_) {
    std::vector<uint8_t> p_data(sizeof(float) * (w * h * c + n_classes));
    sgx_status_t res = SGX_ERROR_UNEXPECTED;

    predictData_.X.rows = net_->batch;
    predictData_.X.cols = w * h * c;
    predictData_.X.vals =
        (float **)calloc(predictData_.X.rows, sizeof(float *));

    predictData_.y.rows = net_->batch;
    predictData_.y.cols = n_classes;
    predictData_.y.vals =
        (float **)calloc(predictData_.y.rows, sizeof(float *));

    for (int i = 0; i < net_->batch; ++i) {
      res = ocall_get_records_plain(3, start + i, &p_data[0], p_data.size());
      if (res !=
          SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
        LOG_ERROR("ocall get records caused problem! the error is "
                  "%#010X \n",
                  res);
        abort();
      }
      predictData_.X.vals[i] = (float *)calloc(w * h * c, sizeof(float));
      std::memcpy(predictData_.X.vals[i], &p_data[0],
                  w * h * c * sizeof(float));

      predictData_.y.vals[i] = (float *)calloc(n_classes, sizeof(float));
      std::memcpy(predictData_.y.vals[i], &p_data[w * h * c * sizeof(float)],
                  n_classes * sizeof(float));
    }
    predictData_.shallow = 0;
    return true;
  }
  return false;
}

void DNNTrainer::train() {
  int start = 0;
  float avg_loss = -1, loss = -1;
  float AVG_ACC = -1;
  int epochs = 0;
#ifndef USE_SGX_LAYERWISE
  char *mode = "PURE_SGX";
#else
  char *mode = "SGX_LAYERWISE";
#endif
  while (get_current_batch(net_) < net_->max_batches) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    bool prepared = false;
    if (secMode == SecStrategyType::SEC_PLAIN) {
      prepared = prepareBatchTrainPlain(start);
    } else if (secMode == SecStrategyType::SEC_PRIVACY_INTEGRITY) {
      prepared = prepareBatchTrainEncrypted(start);
    }
    /* if (!prepared) {
      //intitialSort();
      start = 0;
      prepared = is_plain ?
    prepareBatchTrainPlain(start):prepareBatchTrainEncrypted(start);
    } */
    // printf("starting iteration for batch number %d\n",
    // get_current_batch(net_));
    loss = train_network(net_, trainData_);
    // printf("* reported loss is: %f\n ",loss);

    if (((*net_->seen) / net_->batch) % net_->subdivisions == 0) {
      if (avg_loss == -1) {
        avg_loss = loss;
      }

      avg_loss = avg_loss * .9 + loss * .1;
      LOG_INFO("mode: %s, iteration %ld: loss = %f, avg loss = %f avg, "
               "learning rate = %f "
               "rate, images processed = %ld images\n",
               mode, get_current_batch(net_), loss, avg_loss,
               (double)get_current_rate(net_), *net_->seen);

      /* AVG_ACC = network_accuracy(net_, trainData_);
      LOG_INFO(
          "iteration %ld: loss = %f, avg loss = %f avg, learning rate = %f "
          "rate, images processed = %ld images, training batch accuracy %f\n",
          get_current_batch(net_), loss, avg_loss,
      (double)get_current_rate(net_), *net_->seen, (double)AVG_ACC); */
    }

    free_data(trainData_);
    /*if (get_current_batch(net_) > 1500 &&
        get_current_batch(net_) % 1500
        //epochs
        == 1) {
      // epochs++;
      int start_test = 0;
      auto prepared_test = is_plain ? prepareBatchTestPlain(start_test)
                                    : prepareBatchTestEncrypted(start_test);
      float test_accuracy = 0.0;

      while (prepared_test) {
        start_test += net_->batch;
        test_accuracy += network_accuracy(net_, testData_) * (net_->batch);
        free_data(testData_);
        prepared_test = is_plain ? prepareBatchTestPlain(start_test)
                                 : prepareBatchTestEncrypted(start_test);
      }
      test_accuracy /= start_test;
      LOG_OUT("iteration %ld: test set accuracy %f\n", get_current_batch(net_),
              test_accuracy);
      }*/
  }
}

void DNNTrainer::test() {
  LOG_ERROR("Not implemented\n")
  abort();
}

void DNNTrainer::predict() {
  // LOG_ERROR("Not implemented\n")
  // abort();
  // int start = 0;
  for (int curr = 0; curr < predictSize_; curr += net_->batch) {
    auto prepared =
        secMode == 0
            ? prepareBatchPredictPlain(curr)
            : secMode == 2 ? prepareBatchPredictEncrypted(curr) : false;
    if (!prepared) {
      break;
    }
    // start++;
    matrix pred = network_predict_data(net_, predictData_);
#if LOG_LEVEL == LOG_LEVEL_DEBUG_BEYOND
    std::string out_str("");
#endif
    for (int i = 0; i < pred.rows; ++i) {
#if LOG_LEVEL == LOG_LEVEL_DEBUG_BEYOND
      out_str +=
          "predicting of item number: " + std::to_string(curr + i) + " :";
#endif
      for (int j = 0; j < pred.cols; ++j) {
        predResults_[(curr + i) * n_classes + j] = pred.vals[i][j];
#if LOG_LEVEL == LOG_LEVEL_DEBUG_BEYOND
        out_str += "\t" + std::to_string(pred.vals[i][j]);
#endif
      }
#if LOG_LEVEL == LOG_LEVEL_DEBUG_BEYOND
      out_str += "\n";
#endif
    }
    LOG_DEBUG("%s", out_str.c_str());
  }
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t> encrypted_res(predResults_.size() * sizeof(float));
  uint8_t KEY[AES_GCM_KEY_SIZE] = {1, 2,  3,  4,  5,  6,  7,  8,
                                   9, 10, 11, 12, 13, 14, 15, 16};
  uint8_t IV[AES_GCM_IV_SIZE];

  ret = sgx_read_rand((unsigned char *)&IV[0], AES_GCM_IV_SIZE);
  CHECK_SGX_SUCCESS(ret, "rad rand caused problems\n")

  uint8_t TAG[AES_GCM_TAG_SIZE];
  ret = sgx_rijndael128GCM_encrypt(
      (const sgx_aes_gcm_128bit_key_t *)KEY, (const uint8_t *)&predResults_[0],
      predResults_.size() * sizeof(float), &encrypted_res[0], &IV[0],
      AES_GCM_IV_SIZE, NULL, 0, (sgx_aes_gcm_128bit_tag_t *)&TAG[0]);
  CHECK_SGX_SUCCESS(ret, "encryption failed\n");

  // LOG_DEBUG("key -> is
  // %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
  //   KEY[0],KEY[1],KEY[2],KEY[3],KEY[4],KEY[5],KEY[6],KEY[7],KEY[8],KEY[9],KEY[10],KEY[11],
  //   KEY[12],KEY[13],KEY[14],KEY[15]);
  // LOG_DEBUG("iv -> is
  // %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
  //   IV[0],IV[1],IV[2],IV[3],IV[4],IV[5],IV[6],IV[7],IV[8],IV[9],IV[10],IV[11]);
  // LOG_DEBUG("tag -> is
  // %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
  //   TAG[0],TAG[1],TAG[2],TAG[3],TAG[4],TAG[5],TAG[6],TAG[7],TAG[8],TAG[9],TAG[10],TAG[11],
  //   TAG[12],TAG[13],TAG[14],TAG[15]);

  ret = ocall_store_preds_encrypted(&encrypted_res[0], encrypted_res.size(),
                                    &IV[0], &TAG[0]);
  CHECK_SGX_SUCCESS(ret, "storing final results failed\n");
}

bool DNNTrainer::loadWeights() {
  if (this->secMode == SecStrategyType::SEC_PLAIN) {
    this->loadWeightsPlain();
  } else if (this->secMode == SecStrategyType::SEC_PRIVACY ||
             this->secMode == SecStrategyType::SEC_PRIVACY_INTEGRITY) {
    this->loadWeightsEncrypted();
  } else {
    LOG_ERROR("load weights for this type has not yet implemmented\n");
    abort();
  }
  return true;
}
bool DNNTrainer::loadWeightsPlain() {
  load_weights(net_);
  return true;
}
bool DNNTrainer::loadWeightsEncrypted() {
#ifdef USE_SGX_LAYERWISE
  LOG_ERROR("This part not yet implemented for layerwise!\n")
  abort();
#endif
  load_weights_encrypted(net_);
  return true;
}

sgt::CryptoEngine<uint8_t> &DNNTrainer::getCryptoEngine() {
  return cryptoEngine_;
};

void DNNTrainer::intitialSort() {
  // BitonicSorter sorter(50000, true, cryptoEngine_);
  // old // BitonicSorter sorter(10000, true, cryptoEngine_);
  // sorter.doSort();
}
} // namespace darknet
} // namespace trusted
} // namespace sgx
