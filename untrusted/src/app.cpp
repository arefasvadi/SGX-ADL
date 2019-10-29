#include "app.h"

#include <assert.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <sstream>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include "Record/VectorRecordSet.h"

#define MAX_PATH FILENAME_MAX

//#include "Channel/BasicChannel.hpp"
//#include "Channel/IChannel.hpp"
#include "CryptoEngine.hpp"
#include "Record/ImageRecord.h"
#include "Record/ImageWithLabelRecord.h"

// sgx::common::ImageRecord* imr = new sgx::common::ImageRecord(2,6,8);
// std::unique_ptr<sgx::common::ImageRecord> tempImg(new
// sgx::common::ImageRecord(2,6,8));
// std::unique_ptr<sgx::common::ImageWLabelRecord> tempImgLabel(new
// sgx::common::ImageWLabelRecord(10,std::move(tempImg)));
using json = nlohmann::json;

using timeTracker
    = std::pair<std::chrono::time_point<std::chrono::high_resolution_clock>,
                std::chrono::time_point<std::chrono::high_resolution_clock>>;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

sgx::untrusted::CryptoEngine<uint8_t> crypto_engine(
    sgx::untrusted::CryptoEngine<uint8_t>::Key{
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});

data_params                        tr_pub_params;
std::vector<trainRecordSerialized> plain_dataset;
std::vector<trainRecordEncrypted>  encrypted_dataset;

data_params                        test_pub_params;
std::vector<trainRecordSerialized> plain_test_dataset;
std::vector<trainRecordEncrypted>  encrypted_test_dataset;

data_params                        predict_pub_params;
std::vector<trainRecordSerialized> plain_predict_dataset;
std::vector<trainRecordEncrypted>  encrypted_predict_dataset;

std::vector<uint8_t> plain_weights;

std::vector<uint8_t> encrypted_weights;
std::vector<uint8_t> iv_weights;
std::vector<uint8_t> tag_weights;

// json configs;
RunConfig run_config;
// std::unordered_map<std::string, timeTracker> grand_timer;
std::map<std::string, timeTracker> grand_timer;
std::map<std::string, double>      duration_map;

std::unordered_map<uint32_t, std::vector<unsigned char>> layerwise_contents;
std::unordered_map<int64_t, std::vector<unsigned char>>  all_blocks;

typedef struct _sgx_errlist_t {
  sgx_status_t err;
  const char * msg;
  const char * sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED, "Unexpected error occurred.", NULL},
    {SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL},
    {SGX_ERROR_OUT_OF_MEMORY, "Out of memory.", NULL},
    {SGX_ERROR_ENCLAVE_LOST,
     "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.", NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification.", NULL},
    {SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature.", NULL},
    {SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.", NULL},
    {SGX_ERROR_NO_DEVICE,
     "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX "
     "driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.", NULL},
    {SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata.", NULL},
    {SGX_ERROR_DEVICE_BUSY, "SGX device was busy.", NULL},
    {SGX_ERROR_INVALID_VERSION, "Enclave version was invalid.", NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE, "Enclave was not authorized.", NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file.", NULL},
    {SGX_ERROR_NDEBUG_ENCLAVE,
     "The enclave is signed as product enclave, and can not be created as "
     "debuggable enclave.",
     NULL},
};

/* Check error conditions for loading enclave */
void
print_error_message(sgx_status_t ret) {
  size_t idx = 0;
  size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

  for (idx = 0; idx < ttl; idx++) {
    if (ret == sgx_errlist[idx].err) {
      if (NULL != sgx_errlist[idx].sug)
        printf("Info: %s\n", sgx_errlist[idx].sug);
      printf("Error: %s\n", sgx_errlist[idx].msg);
      break;
    }
  }

  if (idx == ttl)
    printf("Error: Unexpected error occurred.\n");
}

// http://coliru.stacked-crooked.com/a/98db840b238d3ce7
// Returns year/month/day triple in civil calendar
// Preconditions:  z is number of days since 1970-01-01 and is in the range:
//                   [numeric_limits<Int>::min(),
//                   numeric_limits<Int>::max()-719468].
template <class Int>
constexpr std::tuple<Int, unsigned, unsigned>
civil_from_days(Int z) noexcept {
  static_assert(
      std::numeric_limits<unsigned>::digits >= 18,
      "This algorithm has not been ported to a 16 bit unsigned integer");
  static_assert(
      std::numeric_limits<Int>::digits >= 20,
      "This algorithm has not been ported to a 16 bit signed integer");
  z += 719468;
  const Int      era = (z >= 0 ? z : z - 146096) / 146097;
  const unsigned doe = static_cast<unsigned>(z - era * 146097);  // [0, 146096]
  const unsigned yoe
      = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;  // [0, 399]
  const Int      y   = static_cast<Int>(yoe) + era * 400;
  const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);  // [0, 365]
  const unsigned mp  = (5 * doy + 2) / 153;                      // [0, 11]
  const unsigned d   = doy - (153 * mp + 2) / 5 + 1;             // [1, 31]
  const unsigned m   = (mp < 10 ? mp + 3 : mp - 9);              // [1, 12]
  return std::tuple<Int, unsigned, unsigned>(y + (m <= 2), m, d);
}

template <typename Duration = std::chrono::hours>
void
print_time(Duration timezone_adjustment = std::chrono::hours(0)) {
  using namespace std;
  using namespace std::chrono;
  typedef duration<int, ratio_multiply<hours::period, ratio<24>>::type> days;
  system_clock::time_point now = system_clock::now();
  system_clock::duration   tp  = now.time_since_epoch();

  tp += timezone_adjustment;

  days d = duration_cast<days>(tp);
  tp -= d;
  hours h = duration_cast<hours>(tp);
  tp -= h;
  minutes m = duration_cast<minutes>(tp);
  tp -= m;
  seconds s = duration_cast<seconds>(tp);
  tp -= s;

  auto date = civil_from_days(d.count());  // assumes that system_clock uses
                                           // 1970-01-01 0:0:0 UTC as the epoch,
                                           // and does not count leap seconds.

  std::fprintf(stderr,
               "[%04u-%02u-%02u %02lu:%02lu:%02llu.%03llu]\n",
               std::get<0>(date),
               std::get<1>(date),
               std::get<2>(date),
               h.count(),
               m.count(),
               s.count(),
               tp / milliseconds(1));
}

void
print_log(const char *str) {
  // time_t now = time(0);
  // struct tm *ltm = localtime(&now);
  // fprintf(stderr, "%s", asctime(ltm));
  print_time(std::chrono::hours(-5));
  fprintf(stderr, "%s\n", str);
}

void
main_logger(int level, const char *file, int line, const char *format, ...) {
  char    buf[BUFSIZ] = {'\0'};
  char *  buf_ptr     = buf;
  va_list ap;
  size_t  size = 0;
  switch (level) {
    case LOG_TYPE_TRACE:
      size    = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_CYAN
                      "-------------------------" ANSI_COLOR_RESET "\n");
      buf_ptr = buf_ptr + size;
      size    = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_CYAN "[TRACE] -- %s:%d" ANSI_COLOR_RESET "\n",
                      file,
                      line);
      buf_ptr = buf_ptr + size;

      va_start(ap, format);
      size    = vsnprintf(buf_ptr, 4096, format, ap);
      buf_ptr = buf_ptr + size;
      va_end(ap);
      size = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_CYAN
                      "-------------------------" ANSI_COLOR_RESET "\n");
      print_log(buf);
      break;
    case LOG_TYPE_DEBUG:
      size    = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_MAGENTA
                      "-------------------------" ANSI_COLOR_RESET "\n");
      buf_ptr = buf_ptr + size;
      size    = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_MAGENTA "[DEBUG] -- %s:%d" ANSI_COLOR_RESET
                                         "\n",
                      file,
                      line);
      buf_ptr = buf_ptr + size;
      va_start(ap, format);
      size    = vsnprintf(buf_ptr, 4096, format, ap);
      buf_ptr = buf_ptr + size;
      va_end(ap);
      size = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_MAGENTA
                      "-------------------------" ANSI_COLOR_RESET "\n");
      print_log(buf);
      break;

    case LOG_TYPE_INFO:
      size    = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_BLUE
                      "-------------------------" ANSI_COLOR_RESET "\n");
      buf_ptr = buf_ptr + size;
      size    = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_BLUE "[INFO] -- %s:%d" ANSI_COLOR_RESET "\n",
                      file,
                      line);
      buf_ptr = buf_ptr + size;
      va_start(ap, format);
      size    = vsnprintf(buf_ptr, 4096, format, ap);
      buf_ptr = buf_ptr + size;
      va_end(ap);
      size = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_BLUE
                      "-------------------------" ANSI_COLOR_RESET "\n");
      print_log(buf);
      break;

    case LOG_TYPE_WARN:
      size    = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_YELLOW
                      "-------------------------" ANSI_COLOR_RESET "\n");
      buf_ptr = buf_ptr + size;
      size    = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_YELLOW "[WARNING] -- %s:%d" ANSI_COLOR_RESET
                                        "\n",
                      file,
                      line);
      buf_ptr = buf_ptr + size;
      va_start(ap, format);
      size    = vsnprintf(buf_ptr, 4096, format, ap);
      buf_ptr = buf_ptr + size;
      va_end(ap);
      size = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_YELLOW
                      "-------------------------" ANSI_COLOR_RESET "\n");
      print_log(buf);
      break;
    case LOG_TYPE_ERROR:
      size    = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_RED
                      "-------------------------" ANSI_COLOR_RESET "\n");
      buf_ptr = buf_ptr + size;
      size    = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_RED "[ERROR] -- %s:%d" ANSI_COLOR_RESET "\n",
                      file,
                      line);
      buf_ptr = buf_ptr + size;
      va_start(ap, format);
      size    = vsnprintf(buf_ptr, 4096, format, ap);
      buf_ptr = buf_ptr + size;
      va_end(ap);
      size = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_RED
                      "-------------------------" ANSI_COLOR_RESET "\n");
      print_log(buf);
      break;
    case LOG_TYPE_OUT:
      size    = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_GREEN
                      "-------------------------" ANSI_COLOR_RESET "\n");
      buf_ptr = buf_ptr + size;
      size    = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_GREEN "[OUT] -- %s:%d" ANSI_COLOR_RESET "\n",
                      file,
                      line);
      buf_ptr = buf_ptr + size;
      va_start(ap, format);
      size    = vsnprintf(buf_ptr, 4096, format, ap);
      buf_ptr = buf_ptr + size;
      va_end(ap);
      size = snprintf(buf_ptr,
                      4096,
                      ANSI_COLOR_GREEN
                      "-------------------------" ANSI_COLOR_RESET "\n");
      print_log(buf);
      break;
    default:
      break;
  }
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int
initialize_enclave(void) {
  sgx_launch_token_t token   = {0};
  sgx_status_t       ret     = SGX_ERROR_UNEXPECTED;
  int                updated = 0;

  /* Call sgx_create_enclave to initialize an enclave instance */
  /* Debug Support: set 2nd parameter to 1 */
  // SGX_DEBUG_FLAG
  ret = sgx_create_enclave(
      ENCLAVE_FILENAME, 1, &token, &updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
    LOG_ERROR("Error code is %#010X\n", ret);
    return -1;
  }

  return 0;
}

sgx_status_t
dest_enclave(const sgx_enclave_id_t enclave_id) {
  return sgx_destroy_enclave(global_eid);
}

/* OCall functions */
void
ocall_print_string(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
}

void
ocall_print_log(const char *str) {
  print_log(str);
}

void
ocall_get_record_sort(int            i,
                      unsigned char *tr_record_i,
                      size_t         len_i,
                      int            j,
                      unsigned char *tr_record_j,
                      size_t         len_j) {
  // tr_record_i =(unsigned char*) &encrypted_dataset[i];
  std::memcpy(
      tr_record_i, &(encrypted_dataset[i]), sizeof(trainRecordEncrypted));
  len_i = sizeof(trainRecordEncrypted);

  std::memcpy(
      tr_record_j, &(encrypted_dataset[j]), sizeof(trainRecordEncrypted));
  // tr_record_j =(unsigned char*) &encrypted_dataset[j];
  len_j = sizeof(trainRecordEncrypted);
}

void
ocall_get_ptext_img(int loc, unsigned char *buff, size_t len) {
  unsigned char *val_buf
      = reinterpret_cast<unsigned char *>(&plain_dataset[loc].data[0]);
  std::memcpy(buff, val_buf, (plain_dataset[loc].data.size()) * sizeof(float));
  val_buf = reinterpret_cast<unsigned char *>(&plain_dataset[loc].label[0]);
  std::memcpy(buff + (plain_dataset[loc].data.size()) * sizeof(float),
              val_buf,
              plain_dataset[loc].label.size() * sizeof(float));
}

void
ocall_set_record_sort(int            i,
                      unsigned char *tr_record_i,
                      size_t         len_i,
                      int            j,
                      unsigned char *tr_record_j,
                      size_t         len_j) {
  LOG_ERROR("This part is not ready yet!\n")
  abort();
  /* trainRecordEncrypted *tr_rec_i = (trainRecordEncrypted *)tr_record_i;
  encrypted_dataset[i] = *tr_rec_i;
  trainRecordEncrypted *tr_rec_j = (trainRecordEncrypted *)tr_record_j;
  encrypted_dataset[j] = *tr_rec_j; */
}

void
ocall_get_records_encrypted(int            train_or_test,
                            size_t         i,
                            unsigned char *tr_record_i,
                            size_t         len_i,
                            unsigned char *_iv,
                            unsigned char *_tag) {
  // 1: train
  // 2: test
  // 3: predict
  if (train_or_test == 1) {  // train
    std::memcpy(tr_record_i, &(encrypted_dataset[i].encData[0]), len_i);
    std::memcpy(_iv, (encrypted_dataset[i].IV), AES_GCM_IV_SIZE);
    std::memcpy(_tag, (encrypted_dataset[i].MAC), AES_GCM_TAG_SIZE);
  } else if (train_or_test == 2) {
    std::memcpy(tr_record_i, &(encrypted_test_dataset[i].encData[0]), len_i);
    std::memcpy(_iv, (encrypted_test_dataset[i].IV), AES_GCM_IV_SIZE);
    std::memcpy(_tag, (encrypted_test_dataset[i].MAC), AES_GCM_TAG_SIZE);
  } else if (train_or_test == 3) {
    std::memcpy(tr_record_i, &(encrypted_predict_dataset[i].encData[0]), len_i);
    std::memcpy(_iv, (encrypted_predict_dataset[i].IV), AES_GCM_IV_SIZE);
    std::memcpy(_tag, (encrypted_predict_dataset[i].MAC), AES_GCM_TAG_SIZE);
  }
}

void
ocall_set_records_encrypted(int            train_or_test,
                            size_t         i,
                            unsigned char *tr_record_i,
                            size_t         len_i,
                            unsigned char *_iv,
                            unsigned char *_tag) {
  // 1: train
  // 2: test
  // 3: predict
  if (train_or_test == 1) {  // train
    std::memcpy(&(encrypted_dataset[i].encData[0]), tr_record_i, len_i);
    std::memcpy((encrypted_dataset[i].IV), _iv, AES_GCM_IV_SIZE);
    std::memcpy((encrypted_dataset[i].MAC), _tag, AES_GCM_TAG_SIZE);
  } else if (train_or_test == 2) {
    std::memcpy(&(encrypted_test_dataset[i].encData[0]), tr_record_i, len_i);
    std::memcpy((encrypted_test_dataset[i].IV), _iv, AES_GCM_IV_SIZE);
    std::memcpy((encrypted_test_dataset[i].MAC), _tag, AES_GCM_TAG_SIZE);
  } else if (train_or_test == 3) {
    std::memcpy(&(encrypted_predict_dataset[i].encData[0]), tr_record_i, len_i);
    std::memcpy((encrypted_predict_dataset[i].IV), _iv, AES_GCM_IV_SIZE);
    std::memcpy((encrypted_predict_dataset[i].MAC), _tag, AES_GCM_TAG_SIZE);
  }
}

void
ocall_get_records_plain(int            train_or_test,
                        size_t         i,
                        unsigned char *tr_record_i,
                        size_t         len_i) {
  // 1: train
  // 2: test
  // 3: predict
  if (train_or_test == 1) {  // train
    std::memcpy(tr_record_i,
                &(plain_dataset[i].data[0]),
                sizeof(float) * plain_dataset[i].data.size());
    std::memcpy(tr_record_i + sizeof(float) * plain_dataset[i].data.size(),
                &(plain_dataset[i].label[0]),
                sizeof(float) * plain_dataset[i].label.size());
  } else if (train_or_test == 2) {
    std::memcpy(tr_record_i,
                &(plain_test_dataset[i].data[0]),
                sizeof(float) * plain_test_dataset[i].data.size());
    std::memcpy(tr_record_i + sizeof(float) * plain_test_dataset[i].data.size(),
                &(plain_test_dataset[i].label[0]),
                sizeof(float) * plain_test_dataset[i].label.size());
  } else if (train_or_test == 3) {
    std::memcpy(tr_record_i,
                &(plain_predict_dataset[i].data[0]),
                sizeof(float) * plain_predict_dataset[i].data.size());
    std::memcpy(
        tr_record_i + sizeof(float) * plain_predict_dataset[i].data.size(),
        &(plain_predict_dataset[i].label[0]),
        sizeof(float) * plain_predict_dataset[i].label.size());
  }
}

void
ocall_set_records_plain(int            train_or_test,
                        size_t         i,
                        unsigned char *tr_record_i,
                        size_t         len_i) {
  // 1: train
  // 2: test
  // 3: predict
  if (train_or_test == 1) {  // train
    std::memcpy(&(plain_dataset[i]), tr_record_i, len_i);
  } else if (train_or_test == 2) {
    std::memcpy(&(plain_test_dataset[i]), tr_record_i, len_i);
  } else if (train_or_test == 3) {
    std::memcpy(&(plain_predict_dataset[i]), tr_record_i, len_i);
  }
}

void
ocall_set_timing(const char *time_id,
                 size_t      len,
                 int         is_it_first_call,
                 int         is_it_last_call) {
  timeTracker temp;
  if (grand_timer.find(std::string(time_id)) != grand_timer.end()) {
    if (is_it_first_call == 1) {
      temp.first  = std::chrono::high_resolution_clock::now();
      temp.second = std::chrono::high_resolution_clock::now();
      grand_timer[std::string(time_id)] = temp;
    } else {
      temp         = grand_timer[std::string(time_id)];
      temp.second  = std::chrono::high_resolution_clock::now();
      auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                         temp.second - temp.first)
                         .count();
      duration_map[std::string(time_id)] += (double)elapsed;
      temp.first = std::chrono::high_resolution_clock::now();
      grand_timer[std::string(time_id)] = temp;
    }
  } else {
    temp.first  = std::chrono::high_resolution_clock::now();
    temp.second = std::chrono::high_resolution_clock::now();
    grand_timer[std::string(time_id)]  = temp;
    duration_map[std::string(time_id)] = 0.0;
  }
}

void
ocall_write_block(int64_t        block_id,
                  size_t         index,
                  unsigned char *buff,
                  size_t         len) {
  std::vector<unsigned char> temp(len, 0);
  std::memcpy(&temp[index], buff, len);
  all_blocks[block_id] = std::move(temp);
}

void
ocall_read_block(int64_t        block_id,
                 size_t         index,
                 unsigned char *buff,
                 size_t         len) {
  // std::vector<unsigned char> temp(all_blocks[block_id]);
  std::memcpy(buff, &(all_blocks[block_id][index]), len);
}

void
ocall_load_net_config(const unsigned char *path,
                      size_t               path_len,
                      char *               config,
                      size_t               config_len,
                      unsigned int *       real_len,
                      unsigned char *      config_iv,
                      unsigned char *      config_mac) {
  LOG_TRACE("ocall_load_net_config started! for file %s with size %zu\n",
            (char *)path,
            path_len);
  std::ifstream f((const char *)path, std::ios::in | std::ios::binary);

  if (!f.is_open()) {
    throw std::runtime_error("Could not read network config file!");
  }

  std::vector<uint8_t> config_content{std::istreambuf_iterator<char>(f),
                                      std::istreambuf_iterator<char>()};
  f.close();

  const auto encrypted          = crypto_engine.encrypt(config_content);
  const auto config_content_enc = std::get<0>(encrypted);
  const auto config_content_iv  = std::get<1>(encrypted);
  const auto config_content_mac = std::get<2>(encrypted);

  *real_len = config_content_enc.size();
  memcpy(config, config_content_enc.data(), *real_len);
  memcpy(config_iv, config_content_iv.data(), AES_GCM_IV_SIZE);
  memcpy(config_mac, config_content_mac.data(), AES_GCM_TAG_SIZE);

  LOG_TRACE(
      "ocall_load_net_config finished successfully for size of "
      "%zu bytes!\n",
      *real_len);
}

void
ocall_load_weights_plain(int            start,
                         unsigned char *weight_arr,
                         size_t         weight_len) {
  static bool first_call = true;
  if (first_call) {
    first_call = false;
    std::string weights_file_str
        = std::string(run_config.finalized_weights_file_path);
    plain_weights = read_file_binary(weights_file_str.c_str());
  }
  std::memcpy(weight_arr, &plain_weights[start], weight_len);
}

void
ocall_load_weights_encrypted(int            start,
                             unsigned char *weight_arr,
                             size_t         weight_len,
                             unsigned char *weights_iv,
                             unsigned char *weights_mac,
                             int            final_round) {
  LOG_ERROR("ocall load weights encrypted not entirely implemented!\n");
  abort();
  /*static bool first_call = true;
  if (first_call) {
    first_call = false;
    std::string weights_file_str =
  std::string(run_config.finalized_weights_file_path); plain_weights =
  read_file_binary(weights_file_str.c_str());
  }
  std::memcpy(weight_arr, &plain_weights[start], weight_len);*/
}

void
ocall_init_buffer_layerwise(uint32_t buff_id, size_t buff_size) {
  /* if (buff_id == 1) {
    auto aaa = 0;
  } */
  layerwise_contents[buff_id] = std::vector<unsigned char>(buff_size, 0);
}

void
ocall_get_buffer_layerwise(uint32_t       buff_id,
                           uint32_t       start,
                           uint32_t       end,
                           unsigned char *temp_buff,
                           size_t         temp_buff_len) {
  assert((end - start) == temp_buff_len);
  std::memcpy(
      temp_buff, &((layerwise_contents[buff_id])[start]), temp_buff_len);
}

void
ocall_set_buffer_layerwise(uint32_t       buff_id,
                           uint32_t       start,
                           uint32_t       end,
                           unsigned char *temp_buff,
                           size_t         temp_buff_len) {
  assert((end - start) == temp_buff_len);
  std::memcpy(
      &((layerwise_contents[buff_id])[start]), temp_buff, temp_buff_len);
}

void
ocall_store_preds_encrypted(unsigned char *enc_buff,
                            size_t         len,
                            unsigned char *enc_iv,
                            unsigned char *enc_mac) {
  static int         counter        = 0;
  static std::string enc_preds_path = run_config.predict_file_path;

  std::vector<uint8_t> contents_enc, iv, mac;
  LOG_ERROR("This function needs reimplementing\n");
  abort();
  std::string f_name
      = enc_preds_path + std::to_string(counter) + std::string(".enc");
  contents_enc.resize(len);
  std::memcpy(&contents_enc[0], enc_buff, len);
  write_file_binary(f_name.c_str(), contents_enc);

  f_name = enc_preds_path + std::to_string(counter) + std::string(".iv");
  iv.resize(AES_GCM_IV_SIZE);
  std::memcpy(&iv[0], enc_iv, AES_GCM_IV_SIZE);
  write_file_binary(f_name.c_str(), iv);

  f_name = enc_preds_path + std::to_string(counter) + std::string(".tag");
  mac.resize(AES_GCM_TAG_SIZE);
  std::memcpy(&mac[0], enc_mac, AES_GCM_TAG_SIZE);
  write_file_binary(f_name.c_str(), mac);

  counter++;
}

void
ocall_handle_gemm_cpu_first_mult(int total_threads) {
#ifdef USE_GEMM_THREADING_SGX
  std::future<sgx_status_t> returns[total_threads];

  for (int i = 0; i < total_threads; ++i) {
    returns[i] = std::async(
        std::launch::async, &ecall_handle_gemm_cpu_first_mult, global_eid, i);
  }
  for (int i = 0; i < total_threads; ++i) {
    auto res = returns[i].get();
    CHECK_SGX_SUCCESS(
        res, "call to ecall_handle_gemm_cpu_first_mult caused problem!!");
  }
#endif
}

void
ocall_handle_gemm_all(int total_threads) {
#ifdef USE_GEMM_THREADING_SGX
  std::future<sgx_status_t> returns[total_threads];
  for (int i = 0; i < total_threads; ++i) {
    returns[i]
        = std::async(std::launch::async, &ecall_handle_gemm_all, global_eid, i);
  }
  for (int i = 0; i < total_threads; ++i) {
    auto res = returns[i].get();
    CHECK_SGX_SUCCESS(res, "call to ecall_handle_gemm_all caused problem!!");
  }
#endif
}

uint8_t *lbtest_iv  = nullptr;
uint8_t *lbtest_tag = nullptr;
uint8_t *lbtest_enc = nullptr;
void
ocall_test_long_buffer_encrypt_store(int            first,
                                     int            final,
                                     size_t         complete_len,
                                     unsigned char *enc,
                                     size_t         enc_len,
                                     unsigned char *IV,
                                     unsigned char *TAG) {
  static size_t curr = 0;
  if (first) {
    lbtest_iv  = new uint8_t[AES_GCM_IV_SIZE];
    lbtest_enc = new uint8_t[complete_len];
    if (lbtest_enc == NULL) {
      LOG_ERROR("Could not allocate memory for encrypted buffer");
    }
    memcpy(lbtest_iv, IV, AES_GCM_IV_SIZE);
  }

  if (final) {
    lbtest_tag = new uint8_t[AES_GCM_TAG_SIZE];
    memcpy(lbtest_tag, TAG, AES_GCM_TAG_SIZE);
  } else {
    memcpy(lbtest_enc + curr, enc, enc_len);
    curr += enc_len;
  }
}

void
ocall_test_long_buffer_decrypt_retrieve(int            first,
                                        size_t         index,
                                        unsigned char *enc,
                                        size_t         enc_len,
                                        unsigned char *IV,
                                        unsigned char *TAG) {
  //
  if (first) {
    std::memcpy(IV, lbtest_iv, AES_GCM_IV_SIZE);
    // just checking if tag comparison works
    // lbtest_tag[0] = ~lbtest_tag[0];
    std::memcpy(TAG, lbtest_tag, AES_GCM_TAG_SIZE);

  } else {
    std::memcpy(enc, lbtest_enc + index, enc_len);
  }
}

void
print_timers() {
  for (const auto &s : duration_map) {
    LOG_WARN("++ Item %s took about %f seconds\n",
             s.first.c_str(),
             s.second / 1000000.0)
  }
}

void
test_long_buffer() {
  const size_t comp_len = 523 * ONE_MB;
  sgx_status_t ret      = SGX_ERROR_UNEXPECTED;

  ret = ecall_test_long_buffer_encrypt(global_eid, comp_len);
  CHECK_SGX_SUCCESS(ret, "ecall for long buffer enc caused problem\n")
  ret = ecall_test_long_buffer_decrypt(global_eid, comp_len);
  CHECK_SGX_SUCCESS(ret, "ecall for long buffer dec caused problem\n")

  delete[] lbtest_iv;
  delete[] lbtest_enc;
  delete[] lbtest_tag;
}

void
ocall_setup_channel(uint64_t chan_id, int channel_type) {
  // TODO: Later try to choose the correct implementation of channel with
  // templates

  // if (channel_type == ChannelType::TwoWay) {
  //   BasicChannel<ChannelType::TwoWay>::AddNewChannelToRegistery(
  //       std::make_unique<BasicChannel<ChannelType::TwoWay>>(chan_id));
  // }
  // else if (channel_type == ChannelType::OneWayReceiver) {
  //   BasicChannel<ChannelType::OneWayReceiver>::AddNewChannelToRegistery(
  //       std::make_unique<BasicChannel<ChannelType::OneWayReceiver>>(chan_id));
  // } else if (channel_type == ChannelType::OneWaySender) {
  //   BasicChannel<ChannelType::OneWaySender>::AddNewChannelToRegistery(
  //       std::make_unique<BasicChannel<ChannelType::OneWaySender>>(chan_id));
  // }
}

void
ocall_tearup_channel(uint64_t chan_id) {
}

void
ocall_send_to_channel(uint64_t chan_id, unsigned char *buff, size_t len) {
  LOG_DEBUG("Channel %u received a buffer with %u bytes from enclave!\n",
            chan_id,
            len);
}

void
ocall_receive_from_channel(uint64_t chan_id, unsigned char *buff, size_t len) {
  LOG_DEBUG("Channel %u is about to send a buffer with %u bytes to enclave!\n",
            chan_id,
            len);
}

void
ocall_get_size_rec_from_recset(size_t  rec_set_id,
                               size_t  rec_id,
                               size_t *rec_size) {
}

void
ocall_get_serialized_rec_from_recset(size_t   rec_set_id,
                                     size_t   rec_id,
                                     uint8_t *buff,
                                     size_t   buff_len) {
}

void
ocall_generate_recset(size_t function_handler_id, size_t *rec_set_id) {
}

void
ocall_generate_recset(int         rec_set_type,
                      const char *name,
                      int         rec_type,
                      size_t *    rec_set_id,
                      int         rec_set_gen_func) {
}

RunConfig
process_json_config(const std::string &f_path) {
  std::ifstream json_in(f_path);
  json          configs;
  json_in >> configs;
  LOG_DEBUG("The loaded config file is:\n%s\n", configs.dump(2).c_str());
  RunConfig run_config = {};

  bool GPU_SGX_verify = false;
  if (configs.find("GPU_SGX_verify") != configs.end()) {
    GPU_SGX_verify = configs["GPU_SGX_verify"];
  }
  if (configs.find("task") == configs.end()) {
    LOG_ERROR("You need to define the DNNTask\n");
    abort();
  }

  std::string task = configs["task"];
  if (task.compare(std::string("train")) == 0) {
    if (GPU_SGX_verify) {
      run_config.common_config.task = DNNTaskType::TASK_TRAIN_GPU_VERIFY_SGX;
    } else {
      run_config.common_config.task = DNNTaskType::TASK_TRAIN_SGX;
    }
  } else if (task.compare(std::string("test")) == 0) {
    if (GPU_SGX_verify) {
      run_config.common_config.task = DNNTaskType::TASK_TEST_GPU_VERIFY_SGX;
    } else {
      run_config.common_config.task = DNNTaskType::TASK_TEST_SGX;
    }
  } else if (task.compare(std::string("predict")) == 0) {
    if (GPU_SGX_verify) {
      run_config.common_config.task = DNNTaskType::TASK_INFER_GPU_VERIFY_SGX;
    } else {
      run_config.common_config.task = DNNTaskType::TASK_INFER_SGX;
    }
  }

  if (configs.find("network_config") == configs.end()) {
    LOG_ERROR("You need to define the network_config field\n");
    abort();
  }
  std::string network_arch_string = configs["network_config"];
  if (network_arch_string.size() > 255) {
    LOG_ERROR(
        "network_config file path must not be more than 255 characters\n");
    abort();
  }
  strcpy(run_config.common_config.network_arch_file,
         network_arch_string.c_str());

  if (configs.find("security") == configs.end()) {
    LOG_ERROR("You need to define the security field\n");
    abort();
  }
  std::string sec_mode = configs["security"];
  if (sec_mode.compare("plain") == 0) {
    run_config.common_config.sec_strategy = SecStrategyType::SEC_PLAIN;
  } else if (sec_mode.compare("integrity") == 0) {
    run_config.common_config.sec_strategy = SecStrategyType::SEC_INTEGRITY;
  } else if (sec_mode.compare("privacy") == 0) {
    run_config.common_config.sec_strategy = SecStrategyType::SEC_PRIVACY;
  } else if (sec_mode.compare("privacy_integrity") == 0) {
    run_config.common_config.sec_strategy
        = SecStrategyType::SEC_PRIVACY_INTEGRITY;
  }

  if (configs.find("data_config") == configs.end()) {
    LOG_ERROR("You need to define the data_config field\n");
    abort();
  }
  if (configs["data_config"].find("dims") == configs["data_config"].end()) {
    LOG_ERROR("You need to define the dims field\n");
    abort();
  }
  run_config.common_config.input_shape.width
      = configs["data_config"]["dims"][0];
  run_config.common_config.input_shape.height
      = configs["data_config"]["dims"][1];
  run_config.common_config.input_shape.channels
      = configs["data_config"]["dims"][2];

  if (configs["data_config"].find("num_classes")
      == configs["data_config"].end()) {
    LOG_ERROR("You need to define the num_classes field\n");
    abort();
  }
  run_config.common_config.output_shape.num_classes
      = configs["data_config"]["num_classes"];

  if (configs["data_config"].find("trainSize")
      == configs["data_config"].end()) {
    LOG_ERROR("You need to define the trainSize field\n");
    abort();
  }
  if (configs["data_config"].find("testSize") == configs["data_config"].end()) {
    LOG_ERROR("You need to define the testSize field\n");
    abort();
  }
  if (configs["data_config"].find("predictSize")
      == configs["data_config"].end()) {
    LOG_ERROR("You need to define the predictSize field\n");
    abort();
  }
  run_config.common_config.train_size   = configs["data_config"]["trainSize"];
  run_config.common_config.test_size    = configs["data_config"]["testSize"];
  run_config.common_config.predict_size = configs["data_config"]["predictSize"];

  if (configs["data_config"].find("is_image") != configs["data_config"].end()) {
    run_config.is_image = configs["data_config"]["is_image"];
  }
  if (configs["data_config"].find("is_idash") != configs["data_config"].end()) {
    run_config.is_idash = configs["data_config"]["is_idash"];
  }

  if (configs["data_config"].find("train_path")
      != configs["data_config"].end()) {
    std::string train_path = configs["data_config"]["train_path"];
    strcpy(run_config.train_file_path, train_path.c_str());
  }

  if (configs["data_config"].find("test_path")
      != configs["data_config"].end()) {
    std::string test_path = configs["data_config"]["test_path"];
    strcpy(run_config.test_file_path, test_path.c_str());
  }

  if (configs["data_config"].find("predict_path")
      != configs["data_config"].end()) {
    std::string predict_path = configs["data_config"]["predict_path"];
    strcpy(run_config.predict_file_path, predict_path.c_str());
  }

  if (configs["data_config"].find("labels_path")
      != configs["data_config"].end()) {
    std::string labels_path = configs["data_config"]["labels_path"];
    strcpy(run_config.labels_file_path, labels_path.c_str());
  }

  if (configs.find("backup_path") != configs.end()) {
    std::string backup_path = configs["backup_path"];
    strcpy(run_config.backups_dir_path, backup_path.c_str());
  }

  if (configs.find("weights_file") != configs.end()) {
    std::string weights_path = configs["weights_file"];
    strcpy(run_config.finalized_weights_file_path, weights_path.c_str());
  }

  return run_config;
}

void
load_data_set_temp() {
  if (run_config.common_config.task == DNNTaskType::TASK_TRAIN_SGX
      && run_config.common_config.sec_strategy == SecStrategyType::SEC_PLAIN) {
    auto ds_ptr = std::make_unique<sgx::untrusted::VectorRecordSet>(
        std::string("trainig_set"),
        sgx::common::RecordTypes::IMAGE_REC,
        run_config.common_config.train_size);
    LOG_DEBUG("RecordSet with ID %u is generated\n", ds_ptr->getRecordSetID())

    // just generating some dummy image data :(
    for (int i = 0; i < run_config.common_config.train_size; ++i) {
      auto im_ptr = std::make_unique<sgx::common::ImageRecord>(
          run_config.common_config.input_shape.width,
          run_config.common_config.input_shape.height,
          run_config.common_config.input_shape.channels);
      const auto           num_bytes = im_ptr->getRecordSizeInBytes();
      std::vector<uint8_t> rnd_ns(num_bytes);
      int                  rc = RAND_bytes(rnd_ns.data(), num_bytes);
      // unsigned long err = ERR_get_error();
      if (rc != 1) {
        LOG_DEBUG("Getting Random vector failed!\n");
        std::exit(1);
      }
      im_ptr->unSerializeIntoThis(std::move(rnd_ns));
      ds_ptr->appendNew(std::move(im_ptr));
    }

    LOG_DEBUG("RecordSet with ID %u has %u records\n",
              ds_ptr->getRecordSetID(),
              ds_ptr->getTotalNumberofElements());
    sgx::untrusted::IRecordSet::addToRegistery(std::move(ds_ptr));
  }
  LOG_DEBUG("Not very helpful so far\n");
  std::exit(1);
}