#include "bootid.h"
#include <stdio.h>

void format_timestamp(const Timestamp* ts, char* buffer, size_t buffer_size) {
    snprintf(buffer, buffer_size, "%04d%02d%02d%02d%02d%02d",
        ts->year, ts->month, ts->day, ts->hour, ts->minute, ts->second);
}