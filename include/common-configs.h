#pragma once
#ifndef _COMMON_CONFIG_H
#define _COMMON_CONFIG_H

#define LOG_LEVEL LOG_LEVEL_INFO_BEYOND

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_NO_LOG
#endif

/* #undef USE_GEMM_THREADING_SGX */

/* #undef AVAIL_THREADS */

#define USE_DNNL_GEMM

#endif //_COMMON_CONFIG_H
