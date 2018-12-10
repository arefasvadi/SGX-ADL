#pragma once
// #include <stdint.h>

#define AES_GCM_KEY_SIZE 16
#define AES_GCM_TAG_SIZE 16
#define AES_GCM_IV_SIZE 12

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

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
#define  WIDTH_X_HEIGHT_X_CHAN 2352 
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

typedef struct trainRecordSerialized {
  float data [WIDTH_X_HEIGHT_X_CHAN];
  float label [NUM_CLASSES];
  unsigned int shuffleID;
} trainRecordSerialized;

typedef struct trainRecordEncrypted {
  trainRecordSerialized encData;
  unsigned char IV[AES_GCM_IV_SIZE];
  unsigned char MAC[AES_GCM_TAG_SIZE]; 
} trainRecordEncrypted;
