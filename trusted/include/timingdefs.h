#pragma once

#ifndef _SGX_TIMINGDEFS_H
#define _SGX_TIMINGDEFS_H

#include "trusted-configs.h"
#include "../../enclave_t.h"

#include <cstring>

#ifdef ALLOW_TIMING_REPORT

#define SGX_TIMING_FUNC ocall_set_timing

// remmember we're opening a new bracket
#define SET_START_TIMING(KEY)\
    { \
    SGX_TIMING_FUNC(KEY,(strlen(KEY)+1),1,0);\
    }

#define SET_FINISH_TIMING(KEY) \
    {\
    SGX_TIMING_FUNC(KEY,(strlen(KEY)+1),0,1);\
    }

#define SGX_TIMING_ONEPASS "SGX train one pass"
#define SGX_TIMING_FORWARD "SGX forward pass"
#define SGX_TIMING_BACKWARD "SGX backward pass"
#define SGX_TIMING_FORWARD_CONV "SGX forward pass conv"
#define SGX_TIMING_FORWARD_MAXP "SGX forward pass maxp"
#define SGX_TIMING_FORWARD_CONNCTD "SGX forward pass linear"
#define SGX_TIMING_BACKWARD_CONV "SGX backward pass conv"
#define SGX_TIMING_BACKWARD_CONNCTD "SGX backward pass linear"
#define SGX_TIMING_BACKWARD_MAXP "SGX backward pass maxp"
#define SGX_TIMING_OVERALL_TRAINING "SGX overall training"

#define SGX_TIMING_FORWARD_CONV_OUT_KEQ_1 "SGX forward pass conv out kernel=1"
#define SGX_TIMING_FORWARD_CONV_OUT_KGT_1 "SGX forward pass conv out kernel>1"
#define SGX_TIMING_BACKWARD_CONV_WGRAD_KEQ_1 "SGX backward pass conv wgrad kernel=1"
#define SGX_TIMING_BACKWARD_CONV_WGRAD_KGT_1 "SGX backward pass conv wgrad kernel>1"
#define SGX_TIMING_BACKWARD_CONV_INGRAD_KEQ_1 "SGX backward pass conv ingrad kernel=1"
#define SGX_TIMING_BACKWARD_CONV_INGRAD_KGT_1 "SGX backward pass conv ingrad kernel>1"
#define SGX_TIMING_BACKWARD_CONNCTD_WGRAD "SGX backward pass linear wgrad"
#define SGX_TIMING_BACKWARD_CONNCTD_INGRAD "SGX backward pass linear ingrad"

#define SGX_TIMING_CONV_IM2COL "SGX conv im2col"
#define SGX_TIMING_CONV_COL2IM "SGX conv col2im"
#define SGX_TIMING_GEMM "SGX GEMM"
#define SGX_TIMING_GEMM_VERF "SGX GEMM VERF"
#define SGX_TIMING_GEMM_FLL "SGX GEMM FLL"



#else 

#undef SGX_TIMING_ONEPASS
#undef SGX_TIMING_FORWARD
#undef SGX_TIMING_BACKWARD
#undef SGX_TIMING_FORWARD_CONV
#undef SGX_TIMING_FORWARD_MAXP
#undef SGX_TIMING_FORWARD_CONNCTD
#undef SGX_TIMING_BACKWARD_CONV
#undef SGX_TIMING_BACKWARD_CONNCTD
#undef SGX_TIMING_BACKWARD_MAXP
#undef SGX_TIMING_OVERALL_TRAINING

#undef SGX_TIMING_FORWARD_CONV_OUT_KEQ_1
#undef SGX_TIMING_FORWARD_CONV_OUT_KGT_1
#undef SGX_TIMING_BACKWARD_CONV_WGRAD_KEQ_1
#undef SGX_TIMING_BACKWARD_CONV_WGRAD_KGT_1
#undef SGX_TIMING_BACKWARD_CONV_INGRAD_KEQ_1
#undef SGX_TIMING_BACKWARD_CONV_INGRAD_KGT_1
#undef SGX_TIMING_BACKWARD_CONNCTD_WGRAD
#undef SGX_TIMING_BACKWARD_CONNCTD_INGRAD

#undef SGX_TIMING_CONV_IM2COL
#undef SGX_TIMING_CONV_COL2IM
#undef SGX_TIMING_GEMM
#undef SGX_TIMING_GEMM_VERF
#undef SGX_TIMING_GEMM_FLL

#define SGX_TIMING_FUNC
#define SET_START_TIMING(...)
#define SET_FINISH_TIMING(...)

#endif

#endif //_SGX_TIMINGDEFS_H