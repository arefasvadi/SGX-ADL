#pragma once
#ifndef _COMMOM_H
#define _COMMOM_H
#include "common-configs.h"

// #include <stdint.h>
// #ifdef USE_SGX
// #include "sgx_error.h"
// #endif

//#define DO_BLOCK_INPUT

//#define MEASURE_SWITCHLESS_PERF
#ifdef MEASURE_SWITCHLESS_PERF
#define MEASURE_SWITCHLESS_TIMING
#endif

#define AES_GCM_KEY_SIZE 16
#define AES_GCM_TAG_SIZE 16
#define AES_GCM_IV_SIZE 12
#define AES_CMAC_TAG_SIZE AES_GCM_TAG_SIZE

#define ONE_KB (1024)
#define ONE_MB (1024 * ONE_KB)
#define ONE_GB (1024 * ONE_MB)

#define BLOCKING_TOTAL_ITEMS_IN_CACHE (1 * ONE_KB)

#define SGX_LAYERWISE_MAX_LAYER_SIZE (28 * ONE_MB)
#define SGX_OCALL_TRANSFER_BLOCK_SIZE (4 * ONE_MB)

// Later define with enums and constexpr if
// possible values CACHE_FIFO, CACHE_LRU
#define CACHE_LRU
#ifndef CACHE_LRU
#define CACHE_FIFO
#endif


//#define ALLOW_TIMING

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_BRIGHT_RED "\x1b[91m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_BRIGHT_GREEN "\x1b[92m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BRIGHT_YELLOW "\x1b[93m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_BRIGHT_BLUE "\x1b[94m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_BRIGHT_MAGENTA "\x1b[95m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_BRIGHT_CYAN "\x1b[96m"
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
#define LOG_LEVEL_ALL 2005  // Including Traces


#define COLORED_STR(COLOR,STR) ANSI_COLOR_##COLOR STR ANSI_COLOR_RESET

#define LOG_OUT(...) main_logger(LOG_TYPE_OUT, __FILE__, __LINE__, __VA_ARGS__);
#if LOG_LEVEL == LOG_LEVEL_ALL
#define LOG_TRACE(...) \
  main_logger(LOG_TYPE_TRACE, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_DEBUG(...) \
  main_logger(LOG_TYPE_DEBUG, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_INFO(...) \
  main_logger(LOG_TYPE_INFO, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_WARN(...) \
  main_logger(LOG_TYPE_WARN, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_ERROR(...) \
  main_logger(LOG_TYPE_ERROR, __FILE__, __LINE__, __VA_ARGS__);

#elif LOG_LEVEL == LOG_LEVEL_DEBUG_BEYOND
#define LOG_TRACE(...)
#define LOG_DEBUG(...) \
  main_logger(LOG_TYPE_DEBUG, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_INFO(...) \
  main_logger(LOG_TYPE_INFO, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_WARN(...) \
  main_logger(LOG_TYPE_WARN, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_ERROR(...) \
  main_logger(LOG_TYPE_ERROR, __FILE__, __LINE__, __VA_ARGS__);

#elif LOG_LEVEL == LOG_LEVEL_INFO_BEYOND
#define LOG_TRACE(...)
#define LOG_DEBUG(...)
#define LOG_INFO(...) \
  main_logger(LOG_TYPE_INFO, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_WARN(...) \
  main_logger(LOG_TYPE_WARN, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_ERROR(...) \
  main_logger(LOG_TYPE_ERROR, __FILE__, __LINE__, __VA_ARGS__);

#elif LOG_LEVEL == LOG_LEVEL_ERROR
#define LOG_TRACE(...)
#define LOG_DEBUG(...)
#define LOG_INFO(...)
#define LOG_WARN(...)
#define LOG_ERROR(...) \
  main_logger(LOG_TYPE_ERROR, __FILE__, __LINE__, __VA_ARGS__);

#elif LOG_LEVEL == LOG_LEVEL_NO_LOG
#define LOG_TRACE(...)
#define LOG_DEBUG(...)
#define LOG_INFO(...)
#define LOG_WARN(...)
#define LOG_ERROR(...)

#endif

#define CHECK_SGX_SUCCESS(RET, MSG)                                          \
  if ((RET) != (SGX_SUCCESS)) {                                              \
    LOG_ERROR(                                                               \
        MSG "\nerror code: %#010x expected: %#010x\n", (RET), (SGX_SUCCESS)) \
    abort();                                                                 \
  }

// https://chromium.googlesource.com/chromium/src/base/+/master/macros.h#23
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// This file contains macros and macro-like constructs (e.g., templates) that
// are commonly used throughout Chromium source. (It may also contain things
// that are closely related to things that are commonly used that belong in this
// file.)

// Put this in the declarations for a class to be uncopyable.
#define DISALLOW_COPY(TypeName) TypeName(const TypeName&) = delete
// Put this in the declarations for a class to be unassignable.
#define DISALLOW_ASSIGN(TypeName) TypeName& operator=(const TypeName&) = delete
// Put this in the declarations for a class to be uncopyable and unassignable.
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
  DISALLOW_COPY(TypeName);                 \
  DISALLOW_ASSIGN(TypeName)
// A macro to disallow all the implicit constructors, namely the
// default constructor, copy constructor and operator= functions.
// This is especially useful for classes containing only static methods.
#define DISALLOW_IMPLICIT_CONSTRUCTORS(TypeName) \
  TypeName() = delete;                           \
  DISALLOW_COPY_AND_ASSIGN(TypeName)
// Used to explicitly mark the return value of a function as unused. If you are
// really sure you don't want to do anything with the return value of a function
// that has been marked WARN_UNUSED_RESULT, wrap it with this. Example:
//
//   std::unique_ptr<MyType> my_var = ...;
//   if (TakeOwnership(my_var.get()) == SUCCESS)
//     ignore_result(my_var.release());
//

#define ALLOW_DEFAULT_COPY(TypeName) TypeName(const TypeName&) = default;

#define ALLOW_DEFAULT_COPYASSIGN(TypeName) \
  TypeName& operator=(const TypeName&) = default;

#define ALLOW_DEFAULT_COPY_AND_ASSIGN(TypeName) \
  ALLOW_DEFAULT_COPY(TypeName)                  \
  ALLOW_DEFAULT_COPYASSIGN(TypeName)

#define ALLOW_DEFAULT_MOVE(TypeName) TypeName(TypeName&&) = default;

#define ALLOW_DEFAULT_MOVEASSIGN(TypeName) \
  TypeName& operator=(TypeName&&) = default;

#define ALLOW_DEFAULT_MOVE_AND_ASSIGN(TypeName) \
  ALLOW_DEFAULT_MOVE(TypeName)                  \
  ALLOW_DEFAULT_MOVEASSIGN(Typename)

#define ALLOW_DEFAULT_MOVE_NOEXCEPT(TypeName) \
  TypeName(TypeName&&) noexcept = default;

#define ALLOW_DEFAULT_MOVEASSIGN_NOEXCEPT(TypeName) \
  TypeName& operator=(TypeName&&) noexcept = default;

#define ALLOW_DEFAULT_MOVE_AND_ASSIGN_NOEXCEPT(TypeName) \
  ALLOW_DEFAULT_MOVE_NOEXCEPT(TypeName)                  \
  ALLOW_DEFAULT_MOVEASSIGN_NOEXCEPT(TypeName)

#ifndef IMG_WIDTH
//#define IMG_WIDTH 28 //CIFAR10
//#define IMG_WIDTH 256 //IMAGENET
#endif

#ifndef IMG_HEIGHT
//#define IMG_HEIGHT 28 //CIFAR10
//#define IMG_HEIGHT 256 //IMAGENET
#endif

#ifndef IMG_CHAN
//#define IMG_CHAN 3
#endif

#ifndef WIDTH_X_HEIGHT_X_CHAN
//#define WIDTH_X_HEIGHT_X_CHAN 196608 //IMAGENET
//#define WIDTH_X_HEIGHT_X_CHAN 2352 //CIFAR10
#endif

#ifndef TOTAL_IMG_TRAIN_RECORDS
//#define TOTAL_IMG_TRAIN_RECORDS 50000 //IMAGENET
//#define TOTAL_IMG_TRAIN_RECORDS 50000 //CIFAR10
#endif

#ifndef TOTAL_IMG_TEST_RECORDS
//#define TOTAL_IMG_TEST_RECORDS 0 //IMAGENET
//#define TOTAL_IMG_TEST_RECORDS 10000 //CIFAR10
#endif

#ifndef NUM_CLASSES
//#define NUM_CLASSES 1000  //IMAGENET
//#define NUM_CLASSES 10 //CIFAR10
#endif

#ifndef ALL_INDICES_AT_DIMENSION
#define ALL_INDICES_AT_DIMENSION -1
#endif

#endif // _COMMOM_H