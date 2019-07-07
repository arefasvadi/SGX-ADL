#include "DNNTrainer.h"
#include <string>

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
  //LOG_DEBUG("Enetered to get a new batch with satrt %d and batch size %d\n",stt, net_blcoked_->batch)
  BLOCK_ENGINE_INIT_FOR_LOOP(trainXBlocked_, x_valid_range, x_block_val_ptr,
                             float);
  BLOCK_ENGINE_INIT_FOR_LOOP(trainYBlocked_, y_valid_range, y_block_val_ptr,
                             float);
  BLOCK_ENGINE_INIT_FOR_LOOP(net_blcoked_->input, in_valid_range,
                             in_block_val_ptr, float);
  BLOCK_ENGINE_INIT_FOR_LOOP(net_blcoked_->truth, out_valid_range,
                             out_block_val_ptr, float);
  for (int i = 0; i < net_blcoked_->batch; ++i) {
    for (int j = 0; j < WIDTH_X_HEIGHT_X_CHAN; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(trainXBlocked_, x_valid_range,
                                          x_block_val_ptr, false, x_index_var,
                                          (stt + i) % trainSize_, j);
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_1D(
          net_blcoked_->input, in_valid_range, in_block_val_ptr, true,
          in_index_var, i * WIDTH_X_HEIGHT_X_CHAN + j);
      *(in_block_val_ptr + in_index_var - in_valid_range.block_requested_ind) =
          *(x_block_val_ptr + x_index_var - x_valid_range.block_requested_ind);
    }
    for (int j = 0; j < NUM_CLASSES; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(trainYBlocked_, y_valid_range,
                                          y_block_val_ptr, false, y_index_var,
                                          (stt + i) % trainSize_, j);
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_1D(
          net_blcoked_->truth, out_valid_range, out_block_val_ptr, true,
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
  stt = stt+net_blcoked_->batch;
  //LOG_DEBUG("Finished to get a new batch with satrt %d and batch size %d\n",stt, net_blcoked_->batch)
  return true;
  //}
  // return false;
}

bool DNNTrainer::prepareBatchTrainBlockedDirect() {
  static int stt = 0;
  // if (start + net_blcoked_->batch <= trainSize_) {
  //LOG_DEBUG("Enetered to get a new batch with satrt %d and batch size %d\n",stt, net_blcoked_->batch)
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

    for (int j = 0; j < WIDTH_X_HEIGHT_X_CHAN; ++j) {
      
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_1D(
          net_blcoked_->input, in_valid_range, in_block_val_ptr, true,
          in_index_var, i * WIDTH_X_HEIGHT_X_CHAN + j);
      *(in_block_val_ptr + in_index_var - in_valid_range.block_requested_ind) = record->data[j];
    }

    for (int j = 0; j < NUM_CLASSES; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_1D(
          net_blcoked_->truth, out_valid_range, out_block_val_ptr, true,
          out_index_var, i * NUM_CLASSES + j);
      *(out_block_val_ptr + out_index_var -
        out_valid_range.block_requested_ind) = record->label[j];          
    }
  }

  BLOCK_ENGINE_LAST_UNLOCK(net_blcoked_->input, in_valid_range)
  BLOCK_ENGINE_LAST_UNLOCK(net_blcoked_->truth, out_valid_range)
  stt = stt+net_blcoked_->batch;
  //LOG_DEBUG("Finished to get a new batch with satrt %d and batch size %d\n",stt, net_blcoked_->batch)
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
  // if (start + net_->batch <= trainSize_) {
  int candidates[net_->batch];
  for (int i = 0; i < net_->batch; ++i) {
    candidates[i] = rand() % trainSize_;
  }
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
    /* res = ocall_get_records_encrypted(1, start + i, &enc_payload[0],
                                      sizeof(trainRecordEncrypted)); */
    res = ocall_get_records_encrypted(1, candidates[i], &enc_payload[0],
                                      sizeof(trainRecordEncrypted));
    if (res !=
          SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
      LOG_ERROR("ocall get records caused problem! the error is "
                "%#010X \n",
                res);
      abort();
    }
    trainRecordEncrypted *enc_r = (trainRecordEncrypted *)&(enc_payload[0]);
    std::memcpy(&enc_data[0], &(enc_r->encData), sizeof(trainRecordSerialized));
    std::memcpy(&IV[0], (enc_r->IV), AES_GCM_IV_SIZE);
    std::memcpy(&MAC[0], (enc_r->MAC), AES_GCM_TAG_SIZE);

    auto enc_tuple = std::make_tuple(enc_data, IV, MAC);
    // printf("oblivious compared called for %d times\n",++num_calls);
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
  //}
  // return false;
}

bool DNNTrainer::prepareBatchTestEncrypted(int start) {
  if (start + net_->batch <= testSize_) {
    // LOG_DEBUG("prepare test encrypted with start index %d\n",start)
    std::vector<uint8_t> enc_payload(sizeof(trainRecordEncrypted));
    std::vector<uint8_t> enc_data(sizeof(trainRecordSerialized));
    std::array<uint8_t, 12> IV;
    std::array<uint8_t, 16> MAC;
    sgx_status_t res = SGX_ERROR_UNEXPECTED;

    testData_.X.rows = net_->batch;
    testData_.X.cols = WIDTH_X_HEIGHT_X_CHAN;
    testData_.X.vals = (float **)calloc(testData_.X.rows, sizeof(float *));

    testData_.y.rows = net_->batch;
    testData_.y.cols = NUM_CLASSES;
    testData_.y.vals = (float **)calloc(testData_.y.rows, sizeof(float *));

    for (int i = 0; i < net_->batch; ++i) {
      res = ocall_get_records_encrypted(0, start + i, &enc_payload[0],
                                        sizeof(trainRecordEncrypted));
      if (res !=
          SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
        LOG_ERROR("ocall get records caused problem! the error is "
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
      // printf("oblivious compared called for %d times\n",++num_calls);
      auto decrypted = cryptoEngine_.decrypt(enc_tuple);
      trainRecordSerialized *record = (trainRecordSerialized *)&(decrypted[0]);

      testData_.X.vals[i] =
          (float *)calloc(WIDTH_X_HEIGHT_X_CHAN, sizeof(float));
      std::memcpy(testData_.X.vals[i], record->data,
                  WIDTH_X_HEIGHT_X_CHAN * sizeof(float));

      testData_.y.vals[i] = (float *)calloc(NUM_CLASSES, sizeof(float));
      std::memcpy(testData_.y.vals[i], record->label,
                  NUM_CLASSES * sizeof(float));
    }
    testData_.shallow = 0;
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
  std::vector<uint8_t> p_data(sizeof(trainRecordSerialized));
  sgx_status_t res = SGX_ERROR_UNEXPECTED;

  trainData_.X.rows = net_->batch;
  trainData_.X.cols = WIDTH_X_HEIGHT_X_CHAN;
  trainData_.X.vals = (float **)calloc(trainData_.X.rows, sizeof(float *));

  trainData_.y.rows = net_->batch;
  trainData_.y.cols = NUM_CLASSES;
  trainData_.y.vals = (float **)calloc(trainData_.y.rows, sizeof(float *));

  for (int i = 0; i < net_->batch; ++i) {
    /* res = ocall_get_records_plain(1, start + i, &p_data[0],
                                      sizeof(trainRecordSerialized)); */
    res = ocall_get_records_plain(1, (stt + i) % trainSize_, &p_data[0],
                                  sizeof(trainRecordSerialized));
    /* res = ocall_get_records_plain(1, candidates[i], &p_data[0],
                                      sizeof(trainRecordSerialized)); */

    if (res !=
          SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
      LOG_ERROR("ocall get records caused problem! the error is "
                "%#010X \n",
                res);
      abort();
    }

    trainRecordSerialized *record = (trainRecordSerialized *)&(p_data[0]);

    trainData_.X.vals[i] =
        (float *)calloc(WIDTH_X_HEIGHT_X_CHAN, sizeof(float));
    std::memcpy(trainData_.X.vals[i], record->data,
                WIDTH_X_HEIGHT_X_CHAN * sizeof(float));

    trainData_.y.vals[i] = (float *)calloc(NUM_CLASSES, sizeof(float));
    std::memcpy(trainData_.y.vals[i], record->label,
                NUM_CLASSES * sizeof(float));

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
    std::vector<uint8_t> p_data(sizeof(trainRecordSerialized));
    sgx_status_t res = SGX_ERROR_UNEXPECTED;

    testData_.X.rows = net_->batch;
    testData_.X.cols = WIDTH_X_HEIGHT_X_CHAN;
    testData_.X.vals = (float **)calloc(testData_.X.rows, sizeof(float *));

    testData_.y.rows = net_->batch;
    testData_.y.cols = NUM_CLASSES;
    testData_.y.vals = (float **)calloc(testData_.y.rows, sizeof(float *));

    for (int i = 0; i < net_->batch; ++i) {
      res = ocall_get_records_plain(0, start + i, &p_data[0],
                                    sizeof(trainRecordSerialized));
      if (res !=
          SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
        LOG_ERROR("ocall get records caused problem! the error is "
                  "%#010X \n",
                  res);
        abort();
      }
      trainRecordSerialized *record = (trainRecordSerialized *)&(p_data[0]);

      testData_.X.vals[i] =
          (float *)calloc(WIDTH_X_HEIGHT_X_CHAN, sizeof(float));
      std::memcpy(testData_.X.vals[i], record->data,
                  WIDTH_X_HEIGHT_X_CHAN * sizeof(float));

      testData_.y.vals[i] = (float *)calloc(NUM_CLASSES, sizeof(float));
      std::memcpy(testData_.y.vals[i], record->label,
                  NUM_CLASSES * sizeof(float));
    }
    testData_.shallow = 0;
    return true;
  }
  return false;
}

void DNNTrainer::train(bool is_plain) {
  int start = 0;
  float avg_loss = -1, loss = -1;
  float AVG_ACC = -1;
  int epochs = 0;
  while (get_current_batch(net_) < net_->max_batches) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    auto prepared = is_plain ? prepareBatchTrainPlain(start)
                             : prepareBatchTrainEncrypted(start);
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

    if(((*net_->seen)/net_->batch)%net_->subdivisions == 0) {
      if (avg_loss == -1) {
        avg_loss = loss;
      }

      avg_loss = avg_loss * .9 + loss * .1;
      LOG_INFO(
          "iteration %ld: loss = %f, avg loss = %f avg, learning rate = %f "
          "rate, images processed = %ld images\n",
          get_current_batch(net_), loss, avg_loss, (double)get_current_rate(net_),
          *net_->seen);

      /* AVG_ACC = network_accuracy(net_, trainData_);
      LOG_INFO(
          "iteration %ld: loss = %f, avg loss = %f avg, learning rate = %f "
          "rate, images processed = %ld images, training batch accuracy %f\n",
          get_current_batch(net_), loss, avg_loss, (double)get_current_rate(net_),
          *net_->seen, (double)AVG_ACC); */
    }

    free_data(trainData_);
    if (get_current_batch(net_) > 1500 &&
        get_current_batch(net_) % 1500 /*epochs*/ == 1) {
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
    }
  }
}

void DNNTrainer::intitialSort() {
  BitonicSorter sorter(50000, true, cryptoEngine_);
  // BitonicSorter sorter(10000, true, cryptoEngine_);
  sorter.doSort();
}
} // namespace darknet
} // namespace trusted
} // namespace sgx
