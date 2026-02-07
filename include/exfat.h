#ifndef EXFAT_H
#define EXFAT_H

#include "lib.h"
#include "common.h"
#include "stream.h"

#define EXFAT_ENTRY_SIZE 32

#define EXFAT_ENTRY_EOD          0x00
#define EXFAT_ENTRY_FILE         0x85
#define EXFAT_ENTRY_STREAM       0xC0

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
    uint16_t file_name[15];
} ExfatFileNameEntry;

#pragma pack(pop)

typedef struct {
    char name[MAX_PATH_LENGTH];
    uint32_t first_cluster;
    uint64_t data_length;
    bool is_directory;
    bool no_fat_chain;
    uint32_t modify_timestamp;
    uint32_t access_timestamp;
    uint8_t modify_10ms;
    int8_t modify_utc_offset;
    int8_t access_utc_offset;
} ExfatFileInfo;

typedef struct {
    char path[MAX_PATH_LENGTH];
    uint64_t mtime;
    uint64_t atime;
} DeferredDirTime;

static inline bool grow_deferred_dirs(DeferredDirTime** dirs, uint32_t* capacity) {
    uint32_t new_cap = *capacity ? *capacity * 2 : 256;
    DeferredDirTime* new_buf = realloc(*dirs, new_cap * sizeof(DeferredDirTime));
    if (!new_buf) return false;
    *dirs = new_buf;
    *capacity = new_cap;
    return true;
}

typedef struct {
    FILE* fp;
    ExfatBootSector boot_sector;
    uint32_t bytes_per_sector;
    uint32_t bytes_per_cluster;
    uint32_t cluster_heap_offset_bytes;
    uint32_t fat_offset_bytes;
    uint32_t fat_length_bytes;
    uint32_t* fat;
    uint8_t* cluster_buf;
    uint8_t* io_buf;
    uint64_t extracted_bytes;
    uint64_t files_extracted;
    uint64_t raw_file_pos;
    bool silent;
    bool verbose;
    DecryptStream* stream;
    char last_dir[MAX_PATH_LENGTH];
    DirHandle cached_dir;
    DeferredDirTime* deferred_dirs;
    uint32_t deferred_count;
    uint32_t deferred_capacity;
} ExfatContext;

bool exfat_init(ExfatContext* ctx, const char* filename);
bool exfat_init_stream(ExfatContext* ctx, DecryptStream* stream);
bool exfat_extract_all(ExfatContext* ctx, const char* output_dir);
void exfat_close(ExfatContext* ctx);

#endif
