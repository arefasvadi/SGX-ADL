#include "enclave-app.h"

#include "DNNTrainer.h"
#include "darknet-addons.h"
#include "enclave_t.h"
#include <BlockEngine.hpp>
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <set>
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

void ecall_matrix_mult(int row1, int col1, int row2, int col2) {
  if (col1 != row2) {
    my_printf("Sizes for matrix mult do not match!");
    abort();
  }
  int out_row = row1;
  int out_col = col2;

  auto m1 = ::sgx::trusted::BlockedBuffer<double, 2>::MakeBlockedBuffer(
      std::vector<int64_t>{row1, col1});
  auto m1_valid_range = m1->GetEmptyValidRangeData();
  auto index_val_ptr =
      m1->GetItemAt(m1->nDIndexToFlattend({0, 0}), m1_valid_range, true);
  for (int i = 0; i < row1; ++i) {
    for (int j = 0; j < col1; ++j) {
      // m1[i][j] = 1.0;
      int64_t current_ind = m1->nDIndexToFlattend({i, j});
      if (current_ind < m1_valid_range.block_begin_ind ||
          current_ind > m1_valid_range.block_end_ind) {
        if (m1_valid_range.block_requested_ind >= 0) {
          m1->unlockBlock(m1_valid_range.block_requested_ind);
        }
        index_val_ptr = m1->GetItemAt(current_ind, m1_valid_range, true);
      }
      *(index_val_ptr + (current_ind) - (m1_valid_range.block_requested_ind)) =
          1.0;
    }
  }
  if (m1_valid_range.block_requested_ind >= 0) {
    m1->unlockBlock(m1_valid_range.block_requested_ind);
  }
  /* for (int i = 0; i < row1; ++i) {
    for (int j = 0; j < col1; ++j) {
      my_printf("m1[%d][%d] : %f\n",i,j,*(m1->GetItemAt({i, j},false)));
    }
  } */
  my_printf("m1 vals are initialized \n");

  auto m2 = ::sgx::trusted::BlockedBuffer<double, 2>::MakeBlockedBuffer(
      std::vector<int64_t>{row2, col2});
  auto m2_valid_range = m2->GetEmptyValidRangeData();
  index_val_ptr =
      m2->GetItemAt(m2->nDIndexToFlattend({0, 0}), m2_valid_range, true);
  for (int i = 0; i < row1; ++i) {
    for (int j = 0; j < col1; ++j) {
      int64_t current_ind = m2->nDIndexToFlattend({i, j});
      if (current_ind < m2_valid_range.block_begin_ind ||
          current_ind > m2_valid_range.block_end_ind) {
        if (m2_valid_range.block_requested_ind >= 0) {
          m2->unlockBlock(m2_valid_range.block_requested_ind);
        }
        index_val_ptr = m2->GetItemAt(current_ind, m2_valid_range, true);
      }
      *(index_val_ptr + (current_ind) - (m2_valid_range.block_requested_ind)) =
          1.0;
    }
  }
  if (m2_valid_range.block_requested_ind >= 0) {
    m2->unlockBlock(m1_valid_range.block_requested_ind);
  }
  /* for (int i = 0; i < row2; ++i) {
    for (int j = 0; j < col2; ++j) {
      my_printf("m2[%d][%d] : %f\n",i,j,*(m2->GetItemAt({i, j},false)));
    }
  } */
  my_printf("m2 vals are initialized \n");

  auto out = ::sgx::trusted::BlockedBuffer<double, 2>::MakeBlockedBuffer(
      std::vector<int64_t>{out_row, out_col});
  auto out_valid_range = out->GetEmptyValidRangeData();
  index_val_ptr =
      out->GetItemAt(out->nDIndexToFlattend({0, 0}), out_valid_range, true);
  for (int i = 0; i < out_row; ++i) {
    for (int j = 0; j < out_col; ++j) {
      int64_t current_ind = out->nDIndexToFlattend({i, j});
      if (current_ind < out_valid_range.block_begin_ind ||
          current_ind > out_valid_range.block_end_ind) {
        if (out_valid_range.block_requested_ind >= 0) {
          out->unlockBlock(out_valid_range.block_requested_ind);
        }
        index_val_ptr = out->GetItemAt(current_ind, out_valid_range, true);
      }
      *(index_val_ptr + (current_ind) - (out_valid_range.block_requested_ind)) =
          0.0;
    }
  }
  if (out_valid_range.block_requested_ind >= 0) {
    out->unlockBlock(out_valid_range.block_requested_ind);
  }
  /* for (int i = 0; i < out_row; ++i) {
    for (int j = 0; j < out_col; ++j) {
      my_printf("out[%d][%d] : %f\n",i,j,*(out->GetItemAt({i, j},false)));
    }
  } */
  my_printf("output vals are initialized \n");

  m1_valid_range = m1->GetEmptyValidRangeData();
  double *m1_ptr =
      m1->GetItemAt(m1->nDIndexToFlattend({0, 0}), m1_valid_range, false);
  m2_valid_range = m2->GetEmptyValidRangeData();
  double *m2_ptr =
      m2->GetItemAt(m2->nDIndexToFlattend({0, 0}), m2_valid_range, false);
  out_valid_range = out->GetEmptyValidRangeData();
  double *out_ptr =
      out->GetItemAt(out->nDIndexToFlattend({0, 0}), out_valid_range, true);

  for (int64_t i = 0; i < out_row; ++i) {
    for (int64_t j = 0; j < out_col; ++j) {
      int64_t out_current_ind = out->nDIndexToFlattend({i, j});
      if (out_current_ind < out_valid_range.block_begin_ind ||
          out_current_ind > out_valid_range.block_end_ind) {
        if (out_valid_range.block_requested_ind >= 0) {
          out->unlockBlock(out_valid_range.block_requested_ind);
        }
        out_ptr = out->GetItemAt(out_current_ind, out_valid_range, true);
      }
      for (int64_t k = 0; k < col1; ++k) {
        // mult[i][j] += a[i][k] * b[k][j];
        int64_t m1_current_ind = m1->nDIndexToFlattend({i, k});
        if (m1_current_ind < m1_valid_range.block_begin_ind ||
            m1_current_ind > m1_valid_range.block_end_ind) {
          if (m1_valid_range.block_requested_ind >= 0) {
            m1->unlockBlock(m1_valid_range.block_requested_ind);
          }
          m1_ptr = m1->GetItemAt(m1_current_ind, m1_valid_range, false);
        }
        int64_t m2_current_ind = m2->nDIndexToFlattend({k, j});
        if (m2_current_ind < m2_valid_range.block_begin_ind ||
            m2_current_ind > m2_valid_range.block_end_ind) {
          if (m2_valid_range.block_requested_ind >= 0) {
            m2->unlockBlock(m2_valid_range.block_requested_ind);
          }
          m2_ptr = m2->GetItemAt(m2_current_ind, m2_valid_range, false);
        }
        *(out_ptr + out_current_ind - out_valid_range.block_requested_ind) +=
            *(m1_ptr + m1_current_ind - m1_valid_range.block_requested_ind) *
            *(m2_ptr + m2_current_ind - m2_valid_range.block_requested_ind);
      }
    }
  }
  if (m1_valid_range.block_requested_ind >= 0) {
    m1->unlockBlock(m1_valid_range.block_requested_ind);
  }
  if (m2_valid_range.block_requested_ind >= 0) {
    m2->unlockBlock(m1_valid_range.block_requested_ind);
  }
  if (out_valid_range.block_requested_ind >= 0) {
    out->unlockBlock(out_valid_range.block_requested_ind);
  }

  std::set<double> unique_vals;
  out_valid_range = out->GetEmptyValidRangeData();
  out_ptr =
      out->GetItemAt(out->nDIndexToFlattend({0, 0}), out_valid_range, false);
  for (int i = 0; i < out_row; ++i) {
    for (int j = 0; j < out_col; ++j) {
      int64_t out_current_ind = out->nDIndexToFlattend({i, j});
      if (out_current_ind < out_valid_range.block_begin_ind ||
          out_current_ind > out_valid_range.block_end_ind) {
        if (out_valid_range.block_requested_ind >= 0) {
          out->unlockBlock(out_valid_range.block_requested_ind);
        }
        out_ptr = out->GetItemAt(out_current_ind, out_valid_range, false);
      }
      unique_vals.insert(*(out_ptr + (out_current_ind) -
                           (out_valid_range.block_requested_ind)));
    }
  }
  if (out_valid_range.block_requested_ind >= 0) {
    out->unlockBlock(out_valid_range.block_requested_ind);
  }
  my_printf("unique vals are: \n");
  for (const auto &a : unique_vals) {
    my_printf("%f\n", a);
  }
}

void ecall_singal_convolution(int size1, int size2) {
  /* my_printf("ecall_signal_con gets called %d, %d\n", size1, size2);
  double sum = 0;
  if (1) {
    int const n = size1 + size2 - 1;
    auto out = ::sgx::trusted::BlockedBuffer<double, 1>::MakeBlockedBuffer(
        std::vector<int64_t>{n});
    auto vec1 =
        ::sgx::trusted::BlockedBuffer<double, 1>::MakeBlockedBuffer({size1});
    auto vec2 =
        ::sgx::trusted::BlockedBuffer<double, 1>::MakeBlockedBuffer({size2});

    size_t i_val_len = 0;
    double *i_val_ptr = nullptr;
    for (int i = 0; i < size2; ++i) {
      if (i_val_len == 0) {
        i_val_ptr = vec2->GetItemAt({i}, &i_val_len, true);
      }
      *i_val_ptr = 1.0;
      i_val_ptr++;
      i_val_len--;
    }

    i_val_len = 0;
    i_val_ptr = nullptr;

    for (int i = 0; i < n; ++i) {
      if (i_val_len == 0) {
        i_val_ptr = out->GetItemAt({i}, &i_val_len, true);
      }
      *i_val_ptr = 0.0;
      i_val_ptr++;
      i_val_len--;
    }

    size_t vec1_val_len = 0;
    double *vec1_val_ptr = nullptr;
    size_t vec2_val_len = 0;
    double *vec2_val_ptr = nullptr;
    size_t out_val_len = 0;
    double *out_val_ptr = nullptr;

    i_val_len = 0;
    i_val_ptr = nullptr;
    for (int i = 0; i < size1; ++i) {
      if (i_val_len == 0) {
        i_val_ptr = vec1->GetItemAt({i}, &i_val_len, true);
      }
      *i_val_ptr = 1.0;
      i_val_ptr++;
      i_val_len--;
    }

    for (auto i(0); i < n; ++i) {
      // my_printf("outer loop %d\n", i);
      if (out_val_len == 0) {
        out_val_ptr = out->GetItemAt({i}, &out_val_len, true);
      }
      int const jmn = (i >= size2 - 1) ? i - (size2 - 1) : 0;
      int const jmx = (i < size1 - 1) ? i : size1 - 1;
      for (auto j(jmn); j <= jmx; ++j) {
        if (vec1_val_len == 0) {
          vec1_val_ptr = vec1->GetItemAt({j}, &vec1_val_len, false);
        }
        if (vec2_val_len == 0) {
          vec2_val_ptr = vec2->GetItemAt({i - j}, &vec2_val_len, false);
        }
        (*out_val_ptr) += (*vec1_val_ptr) * (*vec2_val_ptr);

        vec1_val_ptr++;
        vec1_val_len--;
        vec2_val_ptr++;
        vec2_val_len--;
      }
      out_val_ptr++;
      out_val_len--;
    }

    out_val_ptr = nullptr;
    out_val_len = 0;
    for (int i = 0; i < n; ++i) {
      if (out_val_len == 0) {
        out_val_ptr = out->GetItemAt({i}, &out_val_len, false);
      }
      sum += *out_val_ptr;
      out_val_ptr++;
      out_val_len--;
    }
  } else {
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
  my_printf("total sum is %f\n", sum); */
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
