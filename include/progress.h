#ifndef PROGRESS_H
#define PROGRESS_H

#include "lib.h"

typedef struct { uint64_t total; } Progress;

static inline void progress_init(Progress* p, uint64_t total) { p->total = total; }
static inline void progress_update(Progress* p, uint64_t current) { (void)p; (void)current; }
static inline void progress_finish(Progress* p) { (void)p; }

#endif
