#include "enclave-app.h"

#include "DNNTrainer.h"
#include "darknet-addons.h"
#include "enclave_t.h"
#include <BlockEngine.hpp>
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <sgx_trts.h>
#include <string>
#include <tuple>
/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */

/* namespace sgt = ::sgx::trusted;
sgt::darknet::DNNTrainer
    trainer("/home/aref/projects/SGX-ADL/test/config/cifar10/cifar_small.cfg",
            "", ""); */

int gpu_index = -1;

void my_printf(const char *fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_print_string(buf);
}

void ecall_singal_convolution(int size1, int size2) {
  my_printf("ecall_signal_con gets called %d, %d\n", size1, size2);
  double sum = 0;
  if (1) {
    auto vec1 =
        ::sgx::trusted::BlockedBuffer<double, 1>::MakeBlockedBuffer({size1});
    auto vec2 =
        ::sgx::trusted::BlockedBuffer<double, 1>::MakeBlockedBuffer({size2});

    for (int i = 0; i < size1; ++i) {
      vec1->SetItemAt({i}, 1.0);
    }
    for (int i = 0; i < size2; ++i) {
      vec2->SetItemAt({i}, 1.0);
    }

    int const n = size1 + size2 - 1;
    auto out = ::sgx::trusted::BlockedBuffer<double, 1>::MakeBlockedBuffer(
        std::vector<int64_t>{n});
    for (auto i(0); i < n; ++i) {
      // my_printf("outer loop %d\n", i);
      int const jmn = (i >= size2 - 1) ? i - (size2 - 1) : 0;
      int const jmx = (i < size1 - 1) ? i : size1 - 1;
      for (auto j(jmn); j <= jmx; ++j) {
        out->SetItemAt({i}, out->GetItemAt({i}) + (vec1->GetItemAt({j}) *
                                                   vec2->GetItemAt({i - j})));
      }
    }
    
    for (int i = 0; i < n; ++i) {
      sum += out->GetItemAt({i});
    }
  } else if (0) {
    auto vec1 = std::vector<double>(size1);
    auto vec2 = std::vector<double>(size2);

    for (int i = 0; i < size1; ++i) {
      vec1[i] = 1.0;
    }
    for (int i = 0; i < size2; ++i) {
      vec2[i] = 1.0;
    }

    int const n = size1 + size2 - 1;
    auto out = std::vector<double>(n, 0.0);
    for (auto i(0); i < n; ++i) {
      // my_printf("outer loop %d\n", i);
      int const jmn = (i >= size2 - 1) ? i - (size2 - 1) : 0;
      int const jmx = (i < size1 - 1) ? i : size1 - 1;
      for (auto j(jmn); j <= jmx; ++j) {
        out[i] += vec1[j] * vec2[i - j];
      }
    }
    for (int i = 0; i < n; ++i) {
      sum += out[i];
    }
  }
  my_printf("total sum is %d\n", sum);
}

void ecall_enclave_init() {
  /* my_printf("enclave_init is called!\n");
  // sgt::darknet::DNNTrainer trainer(
  //     "/home/aref/projects/SGX-DDL/test/config/cifar10/cifar_small.cfg", "",
  //     "");
  sgx_status_t result = SGX_ERROR_UNEXPECTED;
  uint64_t seed1;
  result = sgx_read_rand((unsigned char *)&seed1, 8);
  if (result != SGX_SUCCESS) {
    my_printf("reading random number was not successful! Error code is %#010\n",
              result);
    abort();
  }
  uint64_t seed2;
  result = sgx_read_rand((unsigned char *)&seed2, 8);
  if (result != SGX_SUCCESS) {
    my_printf("reading random number was not successful! Error code is %#010\n",
              result);
    abort();
  }

  set_random_seed(seed1, seed2); */
}

void ecall_assign_random_id(unsigned char *tr_records, size_t len) {
  // my_printf("called with length %d\n", len);
  /* trainRecordEncrypted *ptr_records = (trainRecordEncrypted *)tr_records;
  size_t size = len / sizeof(trainRecordEncrypted);
  auto &crypto_engine = trainer.getCryptoEngine();

  for (int i = 0; i < size; ++i) {
    std::vector<uint8_t> encData(sizeof(trainRecordSerialized));
    std::memcpy(&encData[0], &(ptr_records[i].encData),
                sizeof(trainRecordSerialized));
    std::array<uint8_t, 12> IV;
    std::memcpy(&IV[0], (ptr_records[i].IV), 12);
    std::array<uint8_t, 16> MAC;
    std::memcpy(&MAC[0], (ptr_records[i].MAC), 16);

    auto enc_tuple = std::make_tuple(encData, IV, MAC);
    auto decrypted = crypto_engine.decrypt(enc_tuple);
    trainRecordSerialized *ptr_record = (trainRecordSerialized *)&decrypted[0];
    ptr_record->shuffleID = (unsigned int)rand();

    auto encrypted = crypto_engine.encrypt(decrypted);
    encData = std::get<0>(encrypted);
    std::memcpy(&(ptr_records[i].encData), &encData[0],
                sizeof(trainRecordSerialized));
    IV = std::get<1>(encrypted);
    std::memcpy(&(ptr_records[i].IV[0]), &IV[0], 12);
    MAC = std::get<2>(encrypted);
    std::memcpy(&(ptr_records[i].MAC[0]), &MAC[0], 16);

    // std::vector<uint8_t> encDatak(sizeof(trainRecordSerialized));
    // std::memcpy(&encDatak[0], &(ptr_records[i].encData),
    // sizeof(trainRecordSerialized));
    // std::array<uint8_t, 12> IVk;
    // std::memcpy(&IVk[0], &(ptr_records[i].IV[0]) , 12);
    // std::array<uint8_t, 16> MACk;
    // std::memcpy(&MACk[0], &(ptr_records[i].MAC[0]), 16);

    // auto enc_tuplek = std::make_tuple(encDatak, IVk, MACk);
    // auto decryptedk = crypto_engine.decrypt(enc_tuplek);
    // my_printf("waiting for illegal!\n");
  }*/
}

void ecall_check_for_sort_correctness() {

  /* auto &crypto_engine = trainer.getCryptoEngine();
  uint32_t total_data = 50000;
  uint32_t shuffle_id = 0;
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t> enc_payload(sizeof(trainRecordEncrypted));
  std::vector<uint8_t> enc_data(sizeof(trainRecordSerialized));
  std::array<uint8_t, 12> IV;
  std::array<uint8_t, 16> MAC;

  for (int ind = 0; ind < total_data; ++ind) {

    res = ocall_get_records(ind, &enc_payload[0], sizeof(trainRecordEncrypted));
    if (res != SGX_SUCCESS) {
      my_printf("ocall get records caused problem! the error is "
                "%#010X \n",
                res);
      abort();
    }
    trainRecordEncrypted *enc_r = (trainRecordEncrypted *)&(enc_payload[0]);
    std::memcpy(&enc_data[0], &(enc_r->encData), sizeof(trainRecordSerialized));
    std::memcpy(&IV[0], (enc_r->IV), AES_GCM_IV_SIZE);
    std::memcpy(&MAC[0], (enc_r->MAC), AES_GCM_TAG_SIZE);

    auto enc_tuple = std::make_tuple(enc_data, IV, MAC);
    // my_printf("oblivious compared called for %d times\n",++num_calls);
    auto decrypted = crypto_engine.decrypt(enc_tuple);
    trainRecordSerialized *record = (trainRecordSerialized *)&(decrypted[0]);
    if (record->shuffleID < shuffle_id) {
      my_printf("Unexpected shuffle value for current record and previous one: "
                "%u vs %u\n");
      abort();
    }
    shuffle_id = record->shuffleID;
  } */
}

void ecall_initial_sort() {
  /* my_printf("Starting the initial_sort\n");
  trainer.intitialSort(); */
}

void ecall_start_training() {
  /* sgx_status_t ret  = SGX_ERROR_UNEXPECTED;
  char* time_id = "network_config_time";

  ret = ocall_set_timing(time_id,strlen(time_id)+1,1);
  if (ret != SGX_SUCCESS) {
    printf("ocall for timing caused problem! Error code is %#010\n", ret);
    abort();
  }
  bool res = trainer.loadNetworkConfig();
  ret = ocall_set_timing(time_id,strlen(time_id)+1,0);
  if (ret != SGX_SUCCESS) {
    printf("ocall for timing caused problem! Error code is %#010\n", ret);
    abort();
  }

  my_printf("%s:%d@%s =>  enclave_init finished loading network config!\n",
            __FILE__, __LINE__, __func__);
  if (!res) {
    my_printf("%s:%d@%s =>  trainer.loadNetworkConfig returned false\n",
              __FILE__, __LINE__, __func__);
  } else {
    my_printf("%s:%d@%s =>  trainer.loadNetworkConfig returned true\n",
              __FILE__, __LINE__, __func__);
  }

  trainer.train(); */
}
