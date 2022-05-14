#ifndef _DEBUG_H_
#define _DEBUG_H_

#include "common.h"

#define CONFIG_RW_DBG 1

#if CONFIG_RW_DBG
#define RW_DBG(...) fprintf(stdout, __VA_ARGS__);
#else
#define RW_DBG(...);
#endif

#endif
