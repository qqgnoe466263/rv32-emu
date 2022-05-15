#ifndef _DEBUG_H_
#define _DEBUG_H_

#include "common.h"

#define CONFIG_RW_DBG       0
#define CONFIG_PIPE_DBG     1

#if CONFIG_RW_DBG
#define RW_DBG(...) fprintf(stdout, __VA_ARGS__);
#else
#define RW_DBG(...);
#endif

#if CONFIG_PIPE_DBG
#define PIPE_DBG(...) fprintf(stdout, __VA_ARGS__);
#else
#define PIPE_DBG(...);
#endif

#endif
