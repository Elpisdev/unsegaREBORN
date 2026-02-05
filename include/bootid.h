#ifndef BOOTID_H
#define BOOTID_H

#include "lib.h"

extern const uint8_t BOOTID_KEY[16];
extern const uint8_t BOOTID_IV[16];

enum ContainerType {
    CONTAINER_TYPE_OS = 0x00,
    CONTAINER_TYPE_APP = 0x01,
    CONTAINER_TYPE_OPTION = 0x02
};

#define IS_APM3_OPTION(game_id) (memcmp(game_id, "SDEM", 4) == 0)

#pragma pack(push, 1)

typedef struct {
    uint16_t year;
    uint8_t  month;
    uint8_t  day;
    uint8_t  hour;
    uint8_t  minute;
    uint8_t  second;
    uint8_t  unk1;
} Timestamp;

typedef struct {
    uint8_t  release;
    uint8_t  minor;
    uint16_t major;
} Version;

typedef union {
    Version version;
    uint8_t option[4];
} GameVersion;

typedef struct {
    uint32_t     crc32;
    uint32_t     length;
    uint8_t      signature[4];
    uint8_t      unk1;
    uint8_t      container_type;
    uint8_t      sequence_number;
    bool         use_custom_iv;
    uint8_t      game_id[4];
    Timestamp    target_timestamp;
    GameVersion  target_version;
    uint64_t     block_count;
    uint64_t     block_size;
    uint64_t     header_block_count;
    uint64_t     unk2;
    uint8_t      os_id[3];
    uint8_t      os_generation;
    Timestamp    source_timestamp;
    Version      source_version;
    Version      os_version;
    uint8_t      padding[8];
    uint8_t      extra_padding[4];
} BootId;

#pragma pack(pop)

static inline void format_timestamp(const Timestamp* ts, char* buffer, size_t buffer_size) {
    snprintf(buffer, buffer_size, "%04d%02d%02d%02d%02d%02d",
        ts->year, ts->month, ts->day, ts->hour, ts->minute, ts->second);
}

#endif