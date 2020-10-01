/* Experimental tracking of heap allocations for easy reaping no matter what the code path is
 * Copyright 2016 TJ <hacker@iam.tj>
 * Licensed on the terms of the GNU General Public License version 3.
 *
 * Both tasks are in the same function to take advantage of local static variables that are
 * persistent across calls but invisible to code outside the function.
 */

#include "heap_reap.h"
#include <stdio.h>

unsigned int heap_debug = 0;

struct mem_track {
  void *ptr;
  struct mem_track *prev;
  struct mem_track *next;
  size_t requested;
  size_t allocated;
};

/* 
 * @param ptr   NULL: calloc(nmemb, size), NULL-1: reap all, otherwise free(ptr)
 * @param nmemb number of elements of size to allocate
 * @param size  size if each element
 */
void *
heap_and_reap(void *ptr, size_t nmemb, size_t size)
{
  static struct mem_track *memalloc = NULL;
  struct mem_track *tmp;
  void *result = NULL;

  if (ptr == NULL) { 
    // allocate requested memory and 'hide' the struct mem_track at the end of it
    size_t dwords = ((nmemb * size + sizeof(struct mem_track)) / 4) + 1;

    if ((result = calloc(dwords, 4)) != NULL) {
      tmp = (struct mem_track *) (result + (dwords * 4) - sizeof(struct mem_track)  );
      tmp->allocated = dwords * 4;
      tmp->requested = nmemb * size;
      tmp->ptr = result;
      tmp->prev = memalloc;
      tmp->next = memalloc ? memalloc->next : NULL;
      if (memalloc) {
        if (memalloc->next)
          memalloc->next->prev = tmp;
        memalloc->next = tmp;
      }
      else
        memalloc = tmp;
      if (heap_debug)
        fprintf(stderr, "heap %p req %08lx alloc %08lx @ %p track %p next %p\n", memalloc, tmp->requested, tmp->allocated, tmp->ptr, tmp, memalloc->next);
    }
  }
  else { // free allocation
    struct mem_track *p = memalloc;
    while (p) {
      if(heap_debug)
        fprintf(stderr, "%sheap %p free %08lx @ %p track %p next %p\n", (p->ptr != ptr ? "  " : ""), memalloc, p->requested, p->ptr, p, p->next);
      if (ptr == NULL-1 || p->ptr == ptr) { // free all or a specific allocation
        tmp = p->next;
        if (p->prev)
          p->prev->next = p->next;
        if (p->next)
          p->next->prev = p->prev;
        free(p->ptr);
        if (memalloc == p)
          memalloc = tmp;
        p = tmp;
        if (ptr != NULL-1) // only freeing a specific allocation
          break;
      } else
        p = p->next;
    }
  }
  return result;
}

