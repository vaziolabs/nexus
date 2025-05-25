#include "debug.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

void dlog(const char* format, ...) {
    printf("[NEXUS] ");
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}