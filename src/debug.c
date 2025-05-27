#include <stdio.h>
#include <stdarg.h>
#include "../include/debug.h"

// Simple debug logging function
void dlog(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf("[DEBUG] ");
    vprintf(format, args);
    printf("\n");
    va_end(args);
}