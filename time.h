#ifndef TIME_H
#define TIME_H

#include <stdint.h>

uint64_t rfc3339_with_ms_to_ms(const char *);
uint64_t date_to_ms(const char *, const char **);
uint64_t time_without_ms_to_ms(const char *, const char **);

#endif
