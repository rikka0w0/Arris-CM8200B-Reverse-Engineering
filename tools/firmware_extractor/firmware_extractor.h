#ifndef __FW_LZW_H__
#define __FW_LZW_H__

#include "heap_reap.h"

// for cmsLog
#define cmsLog_error(args...)
#define cmsLog_notice(args...)
#define cmsLog_debug(args...)

// for cmsMem
#define ALLOC_ZEROIZE          0x01

#define cmsMem_alloc(size, allocFlags) heap_and_reap(NULL, size, 1);
#define cmsMem_free(ptr) heap_and_reap(ptr, 0, 0);

// for cmsAst

#include <assert.h>
#define cmsAst_assert(expression) assert(expression);

#endif
