#include "app.h"

#include <assert.h>
#include <cryptopp/oids.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
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
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/pubkey.h"
#include "hexString.h"

#define MAX_PATH FILENAME_MAX

//#include "Channel/BasicChannel.hpp"
//#include "Channel/IChannel.hpp"
#include "CryptoEngine.hpp"
//#include <x86intrin.h>
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
sgx_enclave_id_t         global_eid = 0;
sgx_uswitchless_config_t us_config  = SGX_USWITCHLESS_CONFIG_INITIALIZER;
#ifdef MEASURE_SWITCHLESS_TIMING
uint64_t g_stats[4] = {};
#endif
/* Initialize the enclave */

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

bool                      global_training = true;

int gpu_index = 1;

// json configs;
RunConfig run_config;
// std::unordered_map<std::string, timeTracker> grand_timer;
std::map<std::string, timeTracker> grand_timer;
std::map<std::string, double>      duration_map;

std::unordered_map<uint32_t, std::vector<unsigned char>> layerwise_contents;
std::unordered_map<int64_t, std::vector<unsigned char>>  all_blocks;

FlatBufferedContainerT<TrainLocationsConfigs>   trainlocconfigs = {};
FlatBufferedContainerT<PredictLocationsConfigs> predlocconfigs = {};
FlatBufferedContainerT<DataConfig> dsconfigs = {};
FlatBufferedContainerT<ArchConfig> archconfigs = {};

std::unique_ptr<PRNG> pub_root_rng;
std::deque<std::vector<uint8_t>> enc_integ_set;
std::deque<std::vector<uint8_t>> dec_img_set;

std::shared_ptr<network> network_ = nullptr;
std::shared_ptr<PRNG> batch_inp_rng = nullptr;
std::shared_ptr<PRNG> batch_layers_rng = nullptr;


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
initialize_enclave() {
  // sgx_launch_token_t token   = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  // int                updated = 0;

  const void *enclave_ex_p[32] = {};

  us_config.num_uworkers = 2;
  us_config.num_tworkers = 2;
#ifdef MEASURE_SWITCHLESS_TIMING
  us_config.callback_func[3] = &exit_callback;
#endif
  enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX]
      = (const void *)(&us_config);

  // ret = sgx_create_enclave(
  //     ENCLAVE_FILENAME, 1, &token, &updated, &global_eid, NULL);
  ret = sgx_create_enclave_ex(ENCLAVE_FILENAME,
                              1,
                              NULL,
                              NULL,
                              &global_eid,
                              NULL,
                              SGX_CREATE_ENCLAVE_EX_SWITCHLESS,
                              enclave_ex_p);
  CHECK_SGX_SUCCESS(ret, "sgx_create_enclave_ex caused problem!");

  return 0;
}

sgx_status_t
dest_enclave(const sgx_enclave_id_t enclave_id) {
  return sgx_destroy_enclave(enclave_id);
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

void ocall_add_rand_integset(uint8_t* enc_integ, size_t enc_integ_len) {
  // We need to have a policy for storage of rand integset!
  // on disk or in memory!
  std::vector<uint8_t> integ_in(enc_integ_len,0);
  std::memcpy(integ_in.data(), enc_integ, enc_integ_len);
  enc_integ_set.emplace_back(std::move(integ_in));

}


void ocall_add_dec_images(uint8_t* dec_image, size_t dec_len) {
  // We need to have a policy for storage of rand integset!
  // on disk or in memory!
  std::vector<uint8_t> image_in(dec_len,0);
  std::memcpy(image_in.data(), dec_image, dec_len);
  dec_img_set.emplace_back(std::move(image_in));
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
  const auto &vec = layerwise_contents[buff_id];
  std::memcpy(temp_buff, &(vec[start]), temp_buff_len);
}

void
ocall_set_buffer_layerwise(uint32_t       buff_id,
                           uint32_t       start,
                           uint32_t       end,
                           unsigned char *temp_buff,
                           size_t         temp_buff_len) {
  assert((end - start) == temp_buff_len);
  auto &vec = layerwise_contents[buff_id];
  std::memcpy(&(vec[start]), temp_buff, temp_buff_len);
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
ocall_handle_fill_cpu(int total_threads) {
  // #ifdef USE_GEMM_THREADING_SGX
  // std::future<sgx_status_t> returns[total_threads];

  //   for (int i = 0; i < total_threads; ++i) {
  //     returns[i] = std::async(
  //         std::launch::async, &ecall_handle_fill_cpu, global_eid, i);
  //   }
  //   for (int i = 0; i < total_threads; ++i) {
  //     auto res = returns[i].get();
  //     CHECK_SGX_SUCCESS(
  //         res, "call to ecall handle fill cpu caused problem!!\n");
  //   }
  // #endif
}

void
ocall_handle_scale_cpu(int total_threads) {
  // #ifdef USE_GEMM_THREADING_SGX
  // std::future<sgx_status_t> returns[total_threads];

  //   for (int i = 0; i < total_threads; ++i) {
  //     returns[i] = std::async(
  //         std::launch::async, &ecall_handle_scale_cpu, global_eid, i);
  //   }
  //   for (int i = 0; i < total_threads; ++i) {
  //     auto res = returns[i].get();
  //     CHECK_SGX_SUCCESS(
  //         res, "call to ecall handle scale cpu caused problem!!\n");
  //   }
  // #endif
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

// void ocall_send_pub_root_seed(uint8_t* pub_seed,size_t seed_len) {
//   std::array<uint64_t,16> rng_seed = {};
//   assert(seed_len == rng_seed.size()*sizeof(uint64_t));
//   std::memcpy((uint8_t*)rng_seed.data(), pub_seed, seed_len);
//   pub_root_rng = std::make_unique<PRNG>();
//   pub_root_rng->setSeed(rng_seed);
//   auto hex_seed = bytesToHexString(pub_seed, seed_len);
//   LOG_DEBUG("provided root seed from enclave:\n<\"%s\">\n",hex_seed.c_str())
// }

void ocall_gpu_get_iteration_seed(int iteration,
       uint8_t* batch_seed, 
       size_t batch_seed_len,
       uint8_t* layers_seed,
       size_t layers_seed_len) {

std::array<uint64_t,16> temp_seed;
// LOG_DEBUG("for batch %d, the generated seeds for PRNGs are recieved from enclave:\n"
//     "1. <" COLORED_STR(RED,"%s") ">\n"
//     "2. <" COLORED_STR(BRIGHT_GREEN,"%s") ">\n",
//     iteration,bytesToHexString(batch_seed, 
//       batch_seed_len).c_str(),
//     bytesToHexString(layers_seed, 
//       layers_seed_len).c_str())
if (network_) {
  std::memcpy(temp_seed.data(),batch_seed,batch_seed_len);
  network_->iter_batch_rng = 
  std::shared_ptr<PRNG>(new PRNG(temp_seed));
  std::memcpy(temp_seed.data(),layers_seed,layers_seed_len);
  network_->layer_rng_deriver = std::shared_ptr<PRNG>(new PRNG(temp_seed));
}
else {
  LOG_DEBUG("FIXME!\nInconsistent API -- either change the net directly or variables\n")
  // this is the first call to set init weights for training
  LOG_DEBUG("Received the iteration 0 seeds!\n")
  std::memcpy(temp_seed.data(),batch_seed,batch_seed_len);
  batch_inp_rng = 
  std::shared_ptr<PRNG>(new PRNG(temp_seed));
  std::memcpy(temp_seed.data(),layers_seed,layers_seed_len);
  batch_layers_rng = std::shared_ptr<PRNG>(new PRNG(temp_seed));
  prepare_gpu();
}


}

void
parse_location_configs(const std::string &location_conf_file,
                       const std::string &tasktype) {
  if (tasktype.compare("train") == 0) {
    trainlocconfigs.vecBuff = read_file_binary(location_conf_file.c_str());
    // auto trainlocconfigs
    trainlocconfigs.objPtr = flatbuffers::GetMutableRoot<TrainLocationsConfigs>(
        &trainlocconfigs.vecBuff[0]);

  } else if (tasktype.compare("predict") == 0) {
    predlocconfigs.vecBuff = read_file_binary(location_conf_file.c_str());
    // auto trainlocconfigs
    predlocconfigs.objPtr
        = flatbuffers::GetMutableRoot<PredictLocationsConfigs>(
            &predlocconfigs.vecBuff[0]);
  }
}

void
load_sec_keys_into_enclave() {
  // std::vector<uint8_t> client_pk_sig = read_file_binary(train)
  if (trainlocconfigs.objPtr != nullptr) {
    const decltype(trainlocconfigs.objPtr) &tbl_ptr = trainlocconfigs.objPtr;
    auto                                    client_sig_pk
        = read_file_binary(tbl_ptr->client_pk_sig_file()->c_str());
    auto client_aes_gcm_key
        = read_file_binary(tbl_ptr->client_aes_gcm_key_file()->c_str());
    auto sgx_aes_gcm_key
        = read_file_binary(tbl_ptr->sgx_aes_gcm_key_file()->c_str());
    auto sgx_sig_sk = read_file_binary(tbl_ptr->sgx_sk_sig_file()->c_str());
    auto sgx_sig_pk = read_file_binary(tbl_ptr->sgx_pk_sig_file()->c_str());
    auto res        = ecall_NOT_SECURE_send_req_keys(global_eid,
                                              client_sig_pk.data(),
                                              client_sig_pk.size(),
                                              client_aes_gcm_key.data(),
                                              client_aes_gcm_key.size(),
                                              sgx_sig_pk.data(),
                                              sgx_sig_pk.size(),
                                              sgx_sig_sk.data(),
                                              sgx_sig_sk.size(),
                                              sgx_aes_gcm_key.data(),
                                              sgx_aes_gcm_key.size());
    CHECK_SGX_SUCCESS(res, "setting up enclave keys caused problems\n")
  } else {
    // I will reemove this later
    LOG_ERROR("NOT IMPLEMENTED YET!\n")
    abort();
    const decltype(predlocconfigs.objPtr) &tbl_ptr = predlocconfigs.objPtr;
    auto                                   client_sig_pk
        = read_file_binary(tbl_ptr->client_pk_sig_file()->c_str());
    auto client_aes_gcm_key
        = read_file_binary(tbl_ptr->client_aes_gcm_key_file()->c_str());
    auto sgx_aes_gcm_key
        = read_file_binary(tbl_ptr->sgx_aes_gcm_key_file()->c_str());
    auto sgx_sig_sk = read_file_binary(tbl_ptr->sgx_sk_sig_file()->c_str());
    auto sgx_sg_pk  = read_file_binary(tbl_ptr->sgx_pk_sig_file()->c_str());
  }
}

void load_task_config_into_enclave() {
   if (trainlocconfigs.objPtr != nullptr) {
     const decltype(trainlocconfigs.objPtr) &tbl_ptr = trainlocconfigs.objPtr;
     auto signed_task_config_buf = read_file_binary(tbl_ptr->signed_task_config_path()->c_str());
     //LOG_DEBUG("loaded task config file %s with size %u: bytes\n",tbl_ptr->signed_task_config_path()->c_str(),task_config.size())
     auto res = ecall_send_signed_task_config_verify(global_eid,signed_task_config_buf.data(),signed_task_config_buf.size());
     CHECK_SGX_SUCCESS(res, "task sig verification caused an issue\n")
   }
   else if (predlocconfigs.objPtr != nullptr) {

   }
}

void
load_dataset_config_into_enclave() {
  if (trainlocconfigs.objPtr != nullptr) {
    dsconfigs.vecBuff
        = read_file_binary(trainlocconfigs.objPtr->data_config_path()->c_str());
    dsconfigs.objPtr
        = flatbuffers::GetMutableRoot<DataConfig>(&dsconfigs.vecBuff[0]);
    auto res = ecall_send_data_config_dsverify(
        global_eid, dsconfigs.vecBuff.data(), dsconfigs.vecBuff.size());
    CHECK_SGX_SUCCESS(res, "sending task config to enclave caused an issue!\n")
  } else if (predlocconfigs.objPtr != nullptr) {
    LOG_DEBUG("Not implemented\n")
  }
}

void
load_network_config_into_enclave() {
  if (trainlocconfigs.objPtr != nullptr) {
    LOG_DEBUG("loading network config file at location:\n[\"%s\"]\n",
    trainlocconfigs.objPtr->mutable_network_arch_path()->c_str())
    archconfigs.vecBuff = read_file_binary(
        trainlocconfigs.objPtr->mutable_network_arch_path()->c_str());
    archconfigs.objPtr
        = flatbuffers::GetMutableRoot<ArchConfig>(archconfigs.vecBuff.data());

    auto res = ecall_send_arch_cofig_verify_init(
        global_eid, archconfigs.vecBuff.data(), archconfigs.vecBuff.size());
    CHECK_SGX_SUCCESS(res, "ecall_send_arch_cofig_verify_init cause problem!\n")

  } else if (predlocconfigs.objPtr != nullptr) {
    LOG_DEBUG("Not implemented\n")
  }
}

// send keys to enclave
// send signed task to enclave
// send signed dataset_config to enclave
// enclave must verify the dataset, and depending on the task will setup the
// buffers and randomness
void
prepare_enclave(const std::string &location_conf_file,
                const std::string &tasktype) {
  int success = 0;
  parse_location_configs(location_conf_file, tasktype);
  load_sec_keys_into_enclave();
  load_task_config_into_enclave();
  load_dataset_config_into_enclave();
  load_network_config_into_enclave();  
}

void
prepare_gpu() {
#if defined(GPU) && defined(SGX_VERIFIES)
  auto net_ = load_network(
      (char *)archconfigs.objPtr->mutable_contents()->Data(), NULL, 1);
 network_
      = std::shared_ptr<network>(net_, free_delete());
  LOG_DEBUG(
      "GPU loaded the network with following values\n"
      "GPU batch size   : %d\n"
      "GPU subdiv size  : %d\n"
      "processings per batch : %d\n",
      network_->batch,
      network_->subdivisions,
      (network_->batch * network_->subdivisions))
  
  // LOG_DEBUG("net_rng iter state : " COLORED_STR(RED,"%s\n") "layer_rng_deriver iter state: " COLORED_STR(BRIGHT_GREEN,"%s\n"),bytesToHexString((const uint8_t*)network_->iter_batch_rng->getState().data(),sizeof(uint64_t)*16).c_str(),bytesToHexString((const uint8_t*)network_->layer_rng_deriver->getState().data(),sizeof(uint64_t)*16).c_str());

  // LOG_DEBUG("net_rng iter 0 first int : %d\n",network_->iter_batch_rng->getRandomInt());
  // LOG_DEBUG("layer_rng_deriver iter 0 first int : %d\n",network_->layer_rng_deriver->getRandomInt());  
#else
  LOG_ERROR(
      "This program needs to be compiled with following flags:\n"
      "-DGPU and -DSGX_VERIFIES")
#endif
}

void
ocall_get_client_enc_image(uint32_t ind,
                           uint8_t *enc_image,
                           size_t   image_len,
                           uint8_t *iv,
                           size_t   iv_len,
                           uint8_t *tag,
                           size_t   tag_len,
                           uint8_t *aad,
                           size_t   aad_len) {
  const auto img_path = trainlocconfigs.objPtr->dataset_dir()->str() + "/"
                        + std::to_string((int)ind) + ".fb";
  // LOG_DEBUG("file name is:%s\n",img_path.c_str())
  FlatBufferedContainerT<AESGCM128Enc> aes_gcm;
  aes_gcm.vecBuff = read_file_binary(img_path.c_str());
  aes_gcm.objPtr
      = flatbuffers::GetMutableRoot<AESGCM128Enc>(aes_gcm.vecBuff.data());
  //LOG_DEBUG("is field present %d\n",flatbuffers::IsFieldPresent(aes_gcm.objPtr, AESGCM128Enc::VT_AAD));
  //LOG_DEBUG("%d ?= %d\n",aes_gcm.objPtr->mutable_enc_content()->size(),image_len)
  assert(aes_gcm.objPtr->mutable_enc_content()->size() == image_len);
  assert(aes_gcm.objPtr->mutable_iv()->size() == iv_len);
  assert(aes_gcm.objPtr->mutable_mac()->size() == tag_len);
  assert(aes_gcm.objPtr->mutable_aad()->size() == aad_len);
  std::memcpy(enc_image,
              aes_gcm.objPtr->mutable_enc_content()->Data(),
              aes_gcm.objPtr->mutable_enc_content()->size());
  std::memcpy(iv,
              aes_gcm.objPtr->mutable_iv()->Data(),
              aes_gcm.objPtr->mutable_iv()->size());
  std::memcpy(tag,
              aes_gcm.objPtr->mutable_mac()->Data(),
              aes_gcm.objPtr->mutable_mac()->size());
  std::memcpy(aad,
                aes_gcm.objPtr->mutable_aad()->Data(),
                aes_gcm.objPtr->mutable_aad()->size());
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

#ifdef MEASURE_SWITCHLESS_TIMING
void
exit_callback(sgx_uswitchless_worker_type_t         type,
              sgx_uswitchless_worker_event_t        event,
              const sgx_uswitchless_worker_stats_t *stats) {
  // last thread exiting will update the latest results
  g_stats[type * 2]     = stats->processed;
  g_stats[type * 2 + 1] = stats->missed;
}

void
print_switchless_timing() {
  LOG_WARN(
      "for trusted_workers stats were -> (processed: %u,missed: %u)\nfor "
      "untrusted workers stats were -> (processed: %u,missed: %u)\n",
      g_stats[SGX_USWITCHLESS_WORKER_TYPE_TRUSTED * 2],
      g_stats[SGX_USWITCHLESS_WORKER_TYPE_TRUSTED * 2 + 1],
      g_stats[SGX_USWITCHLESS_WORKER_TYPE_UNTRUSTED * 2],
      g_stats[SGX_USWITCHLESS_WORKER_TYPE_UNTRUSTED * 2 + 1]);
}
#endif