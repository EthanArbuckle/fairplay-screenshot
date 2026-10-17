#ifndef RESEARCH_UTIL_H
#define RESEARCH_UTIL_H
#include <stdbool.h>
typedef unsigned long unw_word_t;
static inline void walk_backtrace(bool (^visitor)(int, unw_word_t, unw_word_t, const char *)) {
    (void)visitor;
}
#endif
