#ifndef UTIL_H
#define UTIL_H

#include <err.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define ERR(fmt, ...) err(1, "error at %s:%d (%s): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define ERRX(fmt, ...) errx(1, "error at %s:%d (%s): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define WARN(fmt, ...) warn("warning at %s:%d (%s): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define WARNX(fmt, ...) warnx("warning at %s:%d (%s): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#endif
