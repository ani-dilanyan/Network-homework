/* Tiny timestamped logger (stderr, unbuffered). */
#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>

extern int log_quiet;   /* set to 1 to silence logs (unit tests) */

#define LOG_AT(level, ...)                                                   \
    do {                                                                     \
        if (!log_quiet) {                                                    \
            char _ts[32];                                                    \
            time_t _t = time(NULL);                                          \
            strftime(_ts, sizeof _ts, "%Y-%m-%d %H:%M:%S", localtime(&_t));  \
            fprintf(stderr, "%s %-5s ", _ts, level);                         \
            fprintf(stderr, __VA_ARGS__);                                    \
            fputc('\n', stderr);                                             \
        }                                                                    \
    } while (0)

#define LOG_INFO(...)  LOG_AT("INFO", __VA_ARGS__)
#define LOG_WARN(...)  LOG_AT("WARN", __VA_ARGS__)
#define LOG_ERROR(...) LOG_AT("ERROR", __VA_ARGS__)

#endif
