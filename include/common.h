#pragma once
// #include <stdint.h>
#include "sgx_error.h"

//#define DO_BLOCK_INPUT

// later remove this to CMAKE
#define LOG_LEVEL LOG_LEVEL_DEBUG_BEYOND

#define AES_GCM_KEY_SIZE 16
#define AES_GCM_TAG_SIZE 16
#define AES_GCM_IV_SIZE 12
#define AES_CMAC_TAG_SIZE AES_GCM_TAG_SIZE

#define ONE_KB (1024)
#define ONE_MB (1024 * ONE_KB)
#define ONE_GB (1024 * ONE_MB)

#define BLOCKING_TOTAL_ITEMS_IN_CACHE 12 * ONE_KB

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_WHITE "\x1b[37m"
#define ANSI_COLOR_RESET "\x1b[0m"

#define LOG_TYPE_TRACE 1001
#define LOG_TYPE_DEBUG 1002
#define LOG_TYPE_INFO 1003
#define LOG_TYPE_WARN 1004
#define LOG_TYPE_ERROR 1005
#define LOG_TYPE_OUT 1006

#define LOG_LEVEL_NO_LOG 2000
#define LOG_LEVEL_ERROR 2001
#define LOG_LEVEL_WARNING_BEYOND 2002
#define LOG_LEVEL_INFO_BEYOND 2003
#define LOG_LEVEL_DEBUG_BEYOND 2004
#define LOG_LEVEL_ALL 2005 // Including Traces

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_NO_LOG
#endif

#define LOG_OUT(...) main_logger(LOG_TYPE_OUT, __FILE__, __LINE__, __VA_ARGS__);
#if LOG_LEVEL == LOG_LEVEL_ALL
#define LOG_TRACE(...)                                                         \
  main_logger(LOG_TYPE_TRACE, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_DEBUG(...)                                                         \
  main_logger(LOG_TYPE_DEBUG, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_INFO(...)                                                          \
  main_logger(LOG_TYPE_INFO, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_WARN(...)                                                          \
  main_logger(LOG_TYPE_WARN, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_ERROR(...)                                                         \
  main_logger(LOG_TYPE_ERROR, __FILE__, __LINE__, __VA_ARGS__);

#elif LOG_LEVEL == LOG_LEVEL_DEBUG_BEYOND
#define LOG_TRACE(...)
#define LOG_DEBUG(...)                                                         \
  main_logger(LOG_TYPE_DEBUG, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_INFO(...)                                                          \
  main_logger(LOG_TYPE_INFO, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_WARN(...)                                                          \
  main_logger(LOG_TYPE_WARN, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_ERROR(...)                                                         \
  main_logger(LOG_TYPE_ERROR, __FILE__, __LINE__, __VA_ARGS__);

#elif LOG_LEVEL == LOG_LEVEL_INFO_BEYOND
#define LOG_TRACE(...)
#define LOG_DEBUG(...)
#define LOG_INFO(...)                                                          \
  main_logger(LOG_TYPE_INFO, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_WARN(...)                                                          \
  main_logger(LOG_TYPE_WARN, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_ERROR(...)                                                         \
  main_logger(LOG_TYPE_ERROR, __FILE__, __LINE__, __VA_ARGS__);

#elif LOG_LEVEL == LOG_LEVEL_ERROR
#define LOG_TRACE(...)
#define LOG_DEBUG(...)
#define LOG_INFO(...)
#define LOG_WARN(...)
#define LOG_ERROR(...)                                                         \
  main_logger(LOG_TYPE_ERROR, __FILE__, __LINE__, __VA_ARGS__);

#elif LOG_LEVEL == LOG_LEVEL_NO_LOG
#define LOG_TRACE(...)
#define LOG_DEBUG(...)
#define LOG_INFO(...)
#define LOG_WARN(...)
#define LOG_ERROR(...)

#endif

#define CHECK_SGX_SUCCESS(RET, MSG)                                            \
  if ((RET) != (SGX_SUCCESS)) {                                                \
    LOG_ERROR(MSG "\nerror code: %#010x expected: %#010x\n", (RET),            \
              (SGX_SUCCESS))                                                   \
    abort();                                                                   \
  }

#ifndef IMG_WIDTH
#define IMG_WIDTH 28
#endif

#ifndef IMG_HEIGHT
#define IMG_HEIGHT 28
#endif

#ifndef IMG_CHAN
#define IMG_CHAN 3
#endif

#ifndef WIDTH_X_HEIGHT_X_CHAN
#define WIDTH_X_HEIGHT_X_CHAN 2352
#endif

#ifndef TOTAL_IMG_TRAIN_RECORDS
#define TOTAL_IMG_TRAIN_RECORDS 50000
#endif

#ifndef TOTAL_IMG_TEST_RECORDS
#define TOTAL_IMG_TEST_RECORDS 10000
#endif

#ifndef NUM_CLASSES
#define NUM_CLASSES 10
#endif

#ifndef ALL_INDICES_AT_DIMENSION
#define ALL_INDICES_AT_DIMENSION -1
#endif

typedef struct trainRecordSerialized {
  float data[WIDTH_X_HEIGHT_X_CHAN];
  float label[NUM_CLASSES];
  unsigned int shuffleID;
} trainRecordSerialized;

typedef struct trainRecordEncrypted {
  trainRecordSerialized encData;
  unsigned char IV[AES_GCM_IV_SIZE];
  unsigned char MAC[AES_GCM_TAG_SIZE];
} trainRecordEncrypted;

enum SecStrategy {
  PLAIN,
  INTEGRITY,
  CONFIDENTIALITY_INTEGRITY,
};
