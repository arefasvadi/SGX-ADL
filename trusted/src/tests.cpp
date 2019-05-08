#include "tests.h"
//#include "enclave-app.h"
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <string>
#include <tuple>

void ecall_singal_convolution(int size1, int size2) {
  /* printf("ecall_signal_con gets called %d, %d\n", size1, size2);
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
      // printf("outer loop %d\n", i);
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
      // printf("outer loop %d\n", i);
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
  printf("total sum is %f\n", sum); */
}

void ecall_matrix_mult(int row1, int col1, int row2, int col2) {
  LOG_TRACE("Starting matrix mult!\n");
  if (col1 != row2) {
    LOG_ERROR("Sizes for matrix mult do not match!\n");
    printf("Sizes for matrix mult do not match!\n");
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
      printf("m1[%d][%d] : %f\n",i,j,*(m1->GetItemAt({i, j},false)));
    }
  } */
  printf("m1 vals are initialized \n");

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
      printf("m2[%d][%d] : %f\n",i,j,*(m2->GetItemAt({i, j},false)));
    }
  } */
  printf("m2 vals are initialized \n");

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
      printf("out[%d][%d] : %f\n",i,j,*(out->GetItemAt({i, j},false)));
    }
  } */
  printf("output vals are initialized \n");

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
  printf("unique vals are: \n");
  for (const auto &a : unique_vals) {
    printf("%f\n", a);
  }
  LOG_TRACE("Finished matrix mult!\n");
}
