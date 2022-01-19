#ifndef __HEAP_REAP_H
#define __HEAP_REAP_H

#include <stdlib.h>
#include <sys/types.h>

extern unsigned int heap_debug;
void * heap_and_reap(void *ptr, size_t nmemb, size_t size);

#endif
