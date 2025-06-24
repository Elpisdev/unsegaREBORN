#ifndef EXFAT_H
#define EXFAT_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "common.h"

#define EXFAT_ENTRY_SIZE 32

#define EXFAT_ENTRY_EOD          0x00
#define EXFAT_ENTRY_BITMAP       0x81
#define EXFAT_ENTRY_FILE         0x85
#define EXFAT_ENTRY_STREAM       0xC0
#define EXFAT_ENTRY_FILENAME     0xC1

#pragma pack(push, 1)

typedef struct {
    uint8_t  jump_boot[3];
    uint8_t  fs_name[8];
    uint8_t  must_be_zero[53];
    uint64_t partition_offset;
    uint64_t volume_length;
    uint32_t fat_offset;
    uint32_t fat_length;
    uint32_t cluster_heap_offset;
    uint32_t cluster_count;
    uint32_t first_cluster_of_root_dir;
    uint32_t volume_serial_number;
    uint16_t fs_revision;
    uint16_t volume_flags;
    uint8_t  bytes_per_sector_shift;
    uint8_t  sectors_per_cluster_shift;
    uint8_t  number_of_fats;
    uint8_t  drive_select;
    uint8_t  percent_in_use;
    uint8_t  reserved[7];
    uint8_t  boot_code[390];
    uint16_t boot_signature;
} ExfatBootSector;

typedef struct {
    uint8_t  entry_type;
    uint8_t  secondary_count;
    uint16_t set_checksum;
    uint16_t file_attributes;
    uint16_t reserved1;
    uint32_t create_timestamp;
    uint32_t last_modified_timestamp;
    uint32_t last_access_timestamp;
    uint8_t  create_10ms;
    uint8_t  last_modified_10ms;
    uint8_t  create_utc_offset;
    uint8_t  last_modified_utc_offset;
    uint8_t  last_access_utc_offset;
    uint8_t  reserved2[7];
} ExfatFileEntry;

typedef struct {
    uint8_t  entry_type;
    uint8_t  flags;
    uint8_t  reserved1;
    uint8_t  name_length;
    uint16_t name_hash;
    uint16_t reserved2;
    uint64_t valid_data_length;
    uint32_t reserved3;
    uint32_t first_cluster;
    uint64_t data_length;
} ExfatStreamEntry;

typedef struct {
    uint8_t entry_type;
    uint8_t flags;
    uint16_t file_name[15];  // please work
} ExfatFileNameEntry;

#pragma pack(pop)

typedef struct {
    char name[MAX_PATH_LENGTH];
    uint32_t first_cluster;
    uint64_t data_length;
    bool is_directory;
} ExfatFileInfo;

typedef struct {
    FILE* fp;
    ExfatBootSector boot_sector;
    uint32_t bytes_per_sector;
    uint32_t bytes_per_cluster;
    uint32_t cluster_heap_offset_bytes;
    uint32_t fat_offset_bytes;
    uint32_t fat_length_bytes;
    uint32_t* fat;
} ExfatContext;

bool exfat_init(ExfatContext* ctx, const char* filename);
bool exfat_extract_all(ExfatContext* ctx, const char* output_dir);
void exfat_close(ExfatContext* ctx);

#endif // EXFAT_H
