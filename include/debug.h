#ifndef _DEBUG_H_
#define _DEBUG_H_

#include "common.h"

#define CONFIG_RW_DBG        0
#define CONFIG_FETCH_DBG     1
#define CONFIG_DECODE_DBG    0
#define CONFIG_EXECUTE_DBG   0
#define CONFIG_ELF_DBG       1

#if CONFIG_RW_DBG
#define RW_DBG(...) fprintf(stdout, __VA_ARGS__);
#else
#define RW_DBG(...);
#endif

#if CONFIG_FETCH_DBG
#define FETCH_DBG(...) fprintf(stdout, __VA_ARGS__);
#else
#define FETCH_DBG(...);
#endif

#if CONFIG_DECODE_DBG
#define DECODE_DBG(...) fprintf(stdout, __VA_ARGS__);
#else
#define DECODE_DBG(...);
#endif

#if CONFIG_EXECUTE_DBG
#define EXECUTE_DBG(...) fprintf(stdout, __VA_ARGS__);
#else
#define EXECUTE_DBG(...);
#endif

#if CONFIG_ELF_DBG
#define ELF_DBG(...) fprintf(stdout, __VA_ARGS__);
#else
#define ELF_DBG(...);
#endif


#endif /* _DEBUG_H_ */
