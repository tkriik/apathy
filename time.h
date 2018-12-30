#ifndef TIME_H
#define TIME_H

#include <stdint.h>

uint64_t rfc3339_to_ms(const char *);
uint64_t rfc3339_no_ms_to_ms(const char *);
uint64_t date_to_ms(const char *);
uint64_t time_to_ms(const char *);

#endif
