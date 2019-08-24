#include "enclave-app.h"
#include "DNNTrainer.h"
#include "darknet-addons.h"
#include "enclave_t.h"
#include "util.h"
#include <BlockEngine.hpp>
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <set>
#include <sgx_trts.h>
#include <string>
#include <tuple>
/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */

namespace sgt = ::sgx::trusted;
/* sgt::darknet::DNNTrainer
    trainer("/home/aref/projects/SGX-ADL/test/config/cifar10/cifar_small.cfg",
            "", "");
 */
/* sgt::darknet::DNNTrainer
    trainer("/home/aref/projects/SGX-ADL/test/config/imagenet_sample/vgg-16.cfg",
            "", ""); */

sgt::darknet::DNNTrainer *trainer = nullptr;

int gpu_index = -1;

static std::shared_ptr<sgt::BlockedBuffer<float, 2>> plain_ds_2d_x;
static std::shared_ptr<sgt::BlockedBuffer<float, 2>> plain_ds_2d_y;
static std::shared_ptr<sgt::BlockedBuffer<float, 1>> plain_ds_1d_x;
static std::shared_ptr<sgt::BlockedBuffer<float, 1>> plain_ds_1d_y;

int total_items = 0;
int single_len_x = 0;
int single_leb_y = 0;

int printf(const char *fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_print_string(buf);
  return 0;
}

void ecall_enclave_init(const char *net_conf_file,const char *task,const char* sec_mode, int width, 
                     int height, int channels, int num_classes, int train_size, int test_size,int predict_size) {
  LOG_TRACE("entered enclave_init!\n");
  int s_mode = -1;
  if (strcmp(sec_mode, "plain") == 0) {
    s_mode = 0;
  } else if (strcmp(sec_mode, "integrity") == 0) {
    s_mode = 1;
    LOG_ERROR("Not implemented!\n")
    abort();
  } else if (strcmp(sec_mode, "privacy_integrity") == 0) {
    s_mode = 2;
  } else {
    LOG_ERROR("Wrong security mode option!\n")
    abort();
  }
  if (strcmp(task, "train")) {
    global_training = true;
  }
  else {
    global_training = false;
  }
  trainer = new sgt::darknet::DNNTrainer(net_conf_file, "", "",s_mode,width,height,channels,num_classes,train_size,test_size,predict_size);

  sgx_status_t result = SGX_ERROR_UNEXPECTED;
  uint64_t seed1;
  result = sgx_read_rand((unsigned char *)&seed1, 8);
  if (result != SGX_SUCCESS) {
    LOG_ERROR("reading random number was not successful! Error code is %#010\n",
              result);
    abort();
  }
  uint64_t seed2;
  result = sgx_read_rand((unsigned char *)&seed2, 8);
  if (result != SGX_SUCCESS) {
    LOG_ERROR("reading random number was not successful! Error code is %#010\n",
              result);
    abort();
  }

  // set_random_seed(seed1, seed2);
  set_random_seed(1, 2);
  LOG_TRACE("finished enclave_init!\n");
}

void ecall_init_ptext_imgds_blocking2D(int single_size_x_bytes,
                                       int single_size_y_bytes,
                                       int total_items) {
  LOG_TRACE("entered init ptext image data set blocking\n");
  
#if defined(USE_SGX) && defined(USE_SGX_BLOCKING) && defined(DO_BLOCK_INPUT)
  LOG_ERROR("This part needs change!\n");
  abort();
  int64_t num_pixels = single_size_x_bytes / sizeof(float);
  int64_t num_labels = single_size_y_bytes / sizeof(float);
  plain_ds_2d_x = sgt::BlockedBuffer<float, 2>::MakeBlockedBuffer(
      {total_items, num_pixels});
  LOG_DEBUG("Blocked buffer for plaintext X instantiated! for %d images with "
            "%d pixels\n",
            total_items, num_pixels);
  plain_ds_2d_y = sgt::BlockedBuffer<float, 2>::MakeBlockedBuffer(
      {total_items, num_labels});
  LOG_DEBUG("Blocked buffer for plaintext Y instantiated! for %d images with "
            "%d labels\n",
            total_items, num_labels);

  BLOCK_ENGINE_INIT_FOR_LOOP(plain_ds_2d_x, x_valid_range, block_val_x, float)
  BLOCK_ENGINE_INIT_FOR_LOOP(plain_ds_2d_y, y_valid_range, block_val_y, float)

  const int total_single_size = single_size_x_bytes + single_size_y_bytes;
  unsigned char *buff = new unsigned char[total_single_size];
  float *buff_val = nullptr;

  for (int64_t i = 0; i < total_items; ++i) {
    // LOG_DEBUG("processing image %d\n", i);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ocall_get_ptext_img(i, buff, total_single_size);
    CHECK_SGX_SUCCESS(ret, "ocall get ptext img was not successful\n");
    buff_val = reinterpret_cast<float *>(buff);
    for (int64_t j = 0; j < num_pixels; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(plain_ds_2d_x, x_valid_range,
                                          block_val_x, true, current_ind, i, j)
      *(block_val_x + (current_ind) - (x_valid_range.block_requested_ind)) =
          *(buff_val + j);
    }
    // LOG_DEBUG("processing image %d finished X\n", i);
    buff_val += single_size_x_bytes / sizeof(float);
    for (int64_t j = 0; j < num_labels; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(plain_ds_2d_y, y_valid_range,
                                          block_val_y, true, current_ind, i, j)
      *(block_val_y + (current_ind) - (y_valid_range.block_requested_ind)) =
          *(buff_val + j);
    }
    // LOG_DEBUG("processing image %d finished Y\n", i);
  }
  BLOCK_ENGINE_LAST_UNLOCK(plain_ds_2d_x, x_valid_range)
  BLOCK_ENGINE_LAST_UNLOCK(plain_ds_2d_y, y_valid_range)

  delete[] buff;
#endif
  LOG_TRACE("finished init ptext image data set blocking\n");
}

void ecall_init_ptext_imgds_blocking1D(int single_size_x_bytes,
                                       int single_size_y_bytes,
                                       int total_items) {
  
  LOG_ERROR("This part needs change!\n");
  abort();
  /* LOG_TRACE("entered init ptext image data set blocking\n");
  int64_t num_pixels = single_size_x_bytes / sizeof(float);
  int64_t num_labels = single_size_y_bytes / sizeof(float);
  plain_ds_1d_x = sgt::BlockedBuffer<float, 1>::MakeBlockedBuffer(
      {total_items, num_pixels});
  LOG_DEBUG("Blocked buffer for plaintext X instantiated!\n");
  plain_ds_1d_y = sgt::BlockedBuffer<float, 1>::MakeBlockedBuffer(
      {total_items, num_labels});
  LOG_DEBUG("Blocked buffer for plaintext Y instantiated!\n");

  BLOCK_ENGINE_INIT_FOR_LOOP(plain_ds_1d_x, x_valid_range, block_val_x, float)
  BLOCK_ENGINE_INIT_FOR_LOOP(plain_ds_1d_y, y_valid_range, block_val_y, float)

  const int total_single_size = single_size_x_bytes + single_size_y_bytes;
  unsigned char *buff = new unsigned char[total_single_size];
  float *buff_val = nullptr;

  for (int64_t i = 0; i < total_items; ++i) {
    // LOG_DEBUG("processing image %d\n", i);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ocall_get_ptext_img(i, buff, total_single_size);
    CHECK_SGX_SUCCESS(ret, "ocall get ptext img was not successful\n");
    buff_val = reinterpret_cast<float *>(buff);

    for (int64_t j = 0; j < num_pixels; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(plain_ds_1d_x, x_valid_range,
                                          block_val_x, true, current_ind, i, j)
      *(block_val_x + (current_ind) - (x_valid_range.block_requested_ind)) =
          *(buff_val + j);
    }
    // LOG_DEBUG("processing image %d finished X\n", i);
    buff_val += single_size_x_bytes / sizeof(float);
    for (int64_t j = 0; j < num_labels; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(plain_ds_1d_y, y_valid_range,
                                          block_val_y, true, current_ind, i, j)
      *(block_val_y + (current_ind) - (y_valid_range.block_requested_ind)) =
          *(buff_val + j);
    }
    // LOG_DEBUG("processing image %d finished Y\n", i);
  }
  BLOCK_ENGINE_LAST_UNLOCK(plain_ds_1d_x, x_valid_range)
  BLOCK_ENGINE_LAST_UNLOCK(plain_ds_1d_y, y_valid_range)

  delete[] buff;
  LOG_TRACE("finished init ptext image data set blocking\n"); */
}

void ecall_assign_random_id(unsigned char *tr_records, size_t len) {
  LOG_ERROR("This part needs change!\n");
  abort();
  LOG_TRACE("entered ecall assign random id\n");
  // printf("called with length %d\n", len);
  
  // trainRecordEncrypted *ptr_records = (trainRecordEncrypted *)tr_records;
  // size_t size = len / sizeof(trainRecordEncrypted);
  // auto &crypto_engine = trainer->getCryptoEngine();

  // for (int i = 0; i < size; ++i) {
  //   std::vector<uint8_t> encData(sizeof(trainRecordSerialized));
  //   std::memcpy(&encData[0], &(ptr_records[i].encData),
  //               sizeof(trainRecordSerialized));
  //   std::array<uint8_t, 12> IV;
  //   std::memcpy(&IV[0], (ptr_records[i].IV), 12);
  //   std::array<uint8_t, 16> MAC;
  //   std::memcpy(&MAC[0], (ptr_records[i].MAC), 16);

  //   auto enc_tuple = std::make_tuple(encData, IV, MAC);
  //   auto decrypted = crypto_engine.decrypt(enc_tuple);
  //   trainRecordSerialized *ptr_record = (trainRecordSerialized *)&decrypted[0];
  //   ptr_record->shuffleID = (unsigned int)rand();

  //   auto encrypted = crypto_engine.encrypt(decrypted);
  //   encData = std::get<0>(encrypted);
  //   std::memcpy(&(ptr_records[i].encData), &encData[0],
  //               sizeof(trainRecordSerialized));
  //   IV = std::get<1>(encrypted);
  //   std::memcpy(&(ptr_records[i].IV[0]), &IV[0], 12);
  //   MAC = std::get<2>(encrypted);
  //   std::memcpy(&(ptr_records[i].MAC[0]), &MAC[0], 16);

    
    // std::vector<uint8_t> encDatak(sizeof(trainRecordSerialized));
    // std::memcpy(&encDatak[0], &(ptr_records[i].encData),
    // sizeof(trainRecordSerialized));
    // std::array<uint8_t, 12> IVk;
    // std::memcpy(&IVk[0], &(ptr_records[i].IV[0]) , 12);
    // std::array<uint8_t, 16> MACk;
    // std::memcpy(&MACk[0], &(ptr_records[i].MAC[0]), 16);

    // auto enc_tuplek = std::make_tuple(encDatak, IVk, MACk);
    // auto decryptedk = crypto_engine.decrypt(enc_tuplek);
    // printf("waiting for illegal!\n");

    LOG_TRACE("finished ecall assign random id\n");
  //}
}

void ecall_check_for_sort_correctness() {
  LOG_ERROR("This part needs change!\n");
  abort();
  LOG_TRACE("entered ecall check for sort correctness\n");
  /* auto &crypto_engine = trainer->getCryptoEngine();
  uint32_t total_data = 50000;
  uint32_t shuffle_id = 0;
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t> enc_payload(sizeof(trainRecordEncrypted));
  std::vector<uint8_t> enc_data(sizeof(trainRecordSerialized));
  std::array<uint8_t, 12> IV;
  std::array<uint8_t, 16> MAC;

  for (int ind = 0; ind < total_data; ++ind) {

    res = ocall_get_records_encrypted(1, ind, &enc_payload[0],
                                      sizeof(trainRecordEncrypted));
    if (res != SGX_SUCCESS) {
      printf("ocall get records caused problem! the error is "
             "%#010X \n",
             res);
      abort();
    }
    trainRecordEncrypted *enc_r = (trainRecordEncrypted *)&(enc_payload[0]);
    std::memcpy(&enc_data[0], &(enc_r->encData), sizeof(trainRecordSerialized));
    std::memcpy(&IV[0], (enc_r->IV), AES_GCM_IV_SIZE);
    std::memcpy(&MAC[0], (enc_r->MAC), AES_GCM_TAG_SIZE);

    auto enc_tuple = std::make_tuple(enc_data, IV, MAC);
    auto decrypted = crypto_engine.decrypt(enc_tuple);
    trainRecordSerialized *record = (trainRecordSerialized *)&(decrypted[0]);
    if (record->shuffleID < shuffle_id) {
      printf("Unexpected shuffle value for current record and previous one: "
             "%u vs %u\n");
      abort();
    }
    shuffle_id = record->shuffleID;
  } */
  LOG_TRACE("finished ecall check for sort correctness\n");
}

void ecall_initial_sort() {
  LOG_ERROR("This part needs change!\n");
  abort();
  LOG_TRACE("entered ecall initial sorrt\n");
  trainer->intitialSort();
  LOG_TRACE("finished ecall initial sorrt\n");
}

void ecall_start_training() {
  LOG_TRACE("entered in %s\n", __func__)
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

#if defined(USE_SGX) && defined(USE_SGX_BLOCKING)
  bool res = trainer->loadNetworkConfigBlocked();
  LOG_DEBUG("blocked network config file loaded\n")
#ifdef DO_BLOCK_INPUT
  trainer->loadTrainDataBlocked(plain_ds_2d_x, plain_ds_2d_y);
#endif
  trainer->trainBlocked();
#else

  bool res = trainer->loadNetworkConfig();
  LOG_DEBUG("network config file loaded\n")
  trainer->train(false);
#endif
  LOG_TRACE("finished in %s\n", __func__);
}

void ecall_start_predicting() {
  LOG_TRACE("entered in %s\n", __func__)
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  bool res = trainer->loadNetworkConfig();
  LOG_INFO("network config file loaded\n")
  if (trainer->secMode == 0) {
    trainer->loadWeightsPlain();
  } else if (trainer->secMode == 2) {
    trainer->loadWeightsEncrypted();
  }
  
  LOG_INFO("weights loaded\n")
  trainer->predict(false);
  LOG_INFO("predictions Done!\n")
  LOG_TRACE("finished in %s\n", __func__)
}

void ecall_handle_gemm_cpu_first_mult(int starter_M, int M, int N, float BETA,
                                      int ldc, size_t new_address_of_C) {
  float *C = (float *)new_address_of_C;
  int i, j;
  for (i = starter_M; i < M; ++i) {
    for (j = 0; j < N; ++j) {
      C[i * ldc + j] *= BETA;
    }
  }
}

void ecall_handle_gemm_all(int starter_M, int TA, int TB, int M, int N, int K,
                           float ALPHA, size_t addr_A, int lda, size_t addr_B,
                           int ldb, size_t addr_C, int ldc) {
  float *A = (float *)addr_A;
  float *B = (float *)addr_B;
  float *C = (float *)addr_C;
  if (!TA && !TB) {
    //gemm_nn(M, N, K, ALPHA, A, lda, B, ldb, C, ldc);
    int i,j,k;
    for(i = starter_M; i < M; ++i){
        for(k = 0; k < K; ++k){
            register float A_PART = ALPHA*A[i*lda+k];
            for(j = 0; j < N; ++j){
                C[i*ldc+j] += A_PART*B[k*ldb+j];
            }
        }
    }
  }
  else if (TA && !TB) {
    //gemm_tn(M, N, K, ALPHA, A, lda, B, ldb, C, ldc);
    int i,j,k;
    for(i = starter_M; i < M; ++i){
        for(k = 0; k < K; ++k){
            register float A_PART = ALPHA*A[k*lda+i];
            for(j = 0; j < N; ++j){
                C[i*ldc+j] += A_PART*B[k*ldb+j];
            }
        }
    }
  }
  else if (!TA && TB) {
    //gemm_nt(M, N, K, ALPHA, A, lda, B, ldb, C, ldc);
    int i,j,k;
    for(i = starter_M; i < M; ++i){
        for(j = 0; j < N; ++j){
            register float sum = 0;
            for(k = 0; k < K; ++k){
                sum += ALPHA*A[i*lda+k]*B[j*ldb + k];
            }
            C[i*ldc+j] += sum;
        }
    }
  }
  else {
    //gemm_tt(M, N, K, ALPHA, A, lda, B, ldb, C, ldc);
    int i,j,k;
    for(i = starter_M; i < M; ++i){
        for(j = 0; j < N; ++j){
            register float sum = 0;
            for(k = 0; k < K; ++k){
                sum += ALPHA*A[i+k*lda]*B[k+j*ldb];
            }
            C[i*ldc+j] += sum;
        }
    }
  }
}
