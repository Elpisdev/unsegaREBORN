#ifndef BOOTID_H
#define BOOTID_H

#include <stdint.h>
#include <stdbool.h>

static const uint8_t BOOTID_KEY[16] = {
    0x09, 0xCA, 0x5E, 0xFD, 0x30, 0xC9, 0xAA, 0xEF,
    0x38, 0x04, 0xD0, 0xA7, 0xE3, 0xFA, 0x71, 0x20
};

static const uint8_t BOOTID_IV[16] = {
    0xB1, 0x55, 0xC2, 0x2C, 0x2E, 0x7F, 0x04, 0x91,
    0xFA, 0x7F, 0x0F, 0xDC, 0x21, 0x7A, 0xFF, 0x90
};

enum ContainerType {
    CONTAINER_TYPE_OS = 0x00,
    CONTAINER_TYPE_APP = 0x01,
    CONTAINER_TYPE_OPTION = 0x02
};

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

void format_timestamp(const Timestamp* ts, char* buffer, size_t buffer_size);

#endif // BOOTID_H