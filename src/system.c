#include "../include/system.h"
#include <ngtcp2/ngtcp2.h>
#include <time.h>
#include <sys/time.h>

ngtcp2_tstamp get_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
} 