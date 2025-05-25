#ifndef SYSTEM_H
#define SYSTEM_H

#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stddef.h>
#include <ngtcp2/ngtcp2.h>

// Define CLOCK_MONOTONIC if not available
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

// Get timestamp function used by ngtcp2
ngtcp2_tstamp get_timestamp(void);

#endif // SYSTEM_H