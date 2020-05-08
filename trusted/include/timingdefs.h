#pragma once

#ifndef _SGX_TIMINGDEFS_h
#define _SGX_TIMINGDEFS_h

#include <cstring>

#define ALLOW_TIMING_REPORT

#ifdef ALLOW_TIMING_REPORT

#define SGX_TIMING_FUNC ocall_set_timing

// remmember we're opening a new bracket
#define SET_START_TIMING(KEY)\
    SGX_TIMING_FUNC(KEY,(strlen(KEY)+1),1,0);

#define SET_FINISH_TIMING(KEY) \
    SGX_TIMING_FUNC(KEY,(strlen(KEY)+1),0,1);


#define SGX_TIMING_ONEPASS "SGX train one pass"
#define SGX_TIMING_FORWARD "SGX forward pass"
#define SGX_TIMING_BACKWARD "SGX backward pass"
#define SGX_TIMING_FORWARD_CONV "SGX forward pass conv"
#define SGX_TIMING_FORWARD_MAXP "SGX forward pass maxp"
#define SGX_TIMING_FORWARD_CONNCTD "SGX forward pass connected"
#define SGX_TIMING_BACKWARD_CONV "SGX backward pass conv"
#define SGX_TIMING_BACKWARD_CONNCTD "SGX backward pass connected"
#define SGX_TIMING_BACKWARD_MAXP "SGX backward pass maxp"

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

#define SGX_TIMING_FUNC
#define SET_START_TIMING(...)
#define SET_FINISH_TIMING(...)

#endif

#endif //_SGX_TIMINGDEFS_h