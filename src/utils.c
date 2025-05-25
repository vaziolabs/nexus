#include "system.h"
#include <ngtcp2/ngtcp2.h>

// This file is not needed anymore, as the function is defined in system.c
// Keeping as empty for now to avoid build system changes
// The function is left commented out for reference

/* 
// Helper function for timestamp (same as client)
ngtcp2_tstamp get_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}
*/