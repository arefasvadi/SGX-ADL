#pragma once

#ifndef _GPU_TIMINGDEFS_H
#define _GPU_TIMINGDEFS_H

#include "untrusted-configs.h"

#ifdef ALLOW_TIMING_REPORT

#define GPU_TIMING_FUNC set_timing

// remmember we're opening a new bracket
#define SET_START_TIMING(KEY)\
    GPU_TIMING_FUNC(KEY,(strlen(KEY)+1),1,0);

#define SET_FINISH_TIMING(KEY) \
    GPU_TIMING_FUNC(KEY,(strlen(KEY)+1),0,1);

#define GPU_TIMING_ONEPASS "GPU train one pass"
#define GPU_TIMING_FORWARD "GPU forward pass"
#define GPU_TIMING_BACKWARD "GPU backward pass"
#define GPU_TIMING_FORWARD_CONV "GPU forward pass conv"
#define GPU_TIMING_FORWARD_MAXP "GPU forward pass maxp"
#define GPU_TIMING_FORWARD_CONNCTD "GPU forward pass connected"
#define GPU_TIMING_BACKWARD_CONV "GPU backward pass conv"
#define GPU_TIMING_BACKWARD_CONNCTD "GPU backward pass connected"
#define GPU_TIMING_BACKWARD_MAXP "GPU backward pass maxp"
#define GPU_TIMING_PREPARE_SNAPSHOT "GPU prepare snapshot"
#define APP_TIMING_OVERALL "App overall time"

#else 

#undef GPU_TIMING_ONEPASS
#undef GPU_TIMING_FORWARD
#undef GPU_TIMING_BACKWARD
#undef GPU_TIMING_FORWARD_CONV
#undef GPU_TIMING_FORWARD_MAXP
#undef GPU_TIMING_FORWARD_CONNCTD
#undef GPU_TIMING_BACKWARD_CONV
#undef GPU_TIMING_BACKWARD_CONNCTD
#undef GPU_TIMING_BACKWARD_MAXP
#undef GPU_TIMING_PREPARE_SNAPSHOT
#undef APP_TIMING_OVERALL

#define GPU_TIMING_FUNC
#define SET_START_TIMING(...)
#define SET_FINISH_TIMING(...)

#endif

#endif //_GPU_TIMINGDEFS_H