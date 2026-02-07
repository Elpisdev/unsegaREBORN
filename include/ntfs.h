#ifndef NTFS_H
#define NTFS_H

#include "lib.h"
#include "common.h"
#include "stream.h"

#define VHD_FOOTER_SIZE 512
#define VHD_SECTOR_SIZE 512
#define VHD_BAT_ENTRY_RESERVED 0xFFFFFFFF
#define VHD_COOKIE "conectix"
#define VHD_DYNAMIC_COOKIE "cxsparse"
#define VHD_TYPE_FIXED 2
#define VHD_TYPE_DYNAMIC 3
#define VHD_TYPE_DIFFERENCING 4
#define VHD_MAX_CHAIN_DEPTH 8
#define FILE_NAME_ATTR 0x30
#define DATA_ATTR 0x80
#define NTFS_SIGNATURE "NTFS    "
#define NTFS_PARTITION_TYPE 0x07
#define MFT_RECORD_IN_USE 0x0001
#define MFT_RECORD_IS_DIRECTORY 0x0002
#define DIR_CACHE_INITIAL_SIZE 2048
#define NTFS_MAX_RECURSION_DEPTH 64

typedef struct {
    uint64_t ref_number;
    char path[MAX_PATH_LENGTH];
    bool occupied;
} DirectoryEntry;

typedef struct {
    DirectoryEntry* entries;
    size_t capacity;
    size_t count;
} DirectoryCache;

#pragma pack(push, 1)

typedef struct {
    char cookie[8];
    uint32_t features;
    uint32_t version;
    uint64_t data_offset;
    uint32_t timestamp;
    uint32_t creator_app;
    uint32_t creator_ver;
    uint32_t creator_os;
    uint64_t original_size;
    uint64_t current_size;
    uint16_t cylinder;
    uint8_t heads;
    uint8_t sectors;
    uint32_t disk_type;
    uint32_t checksum;
    uint8_t unique_id[16];
    uint8_t saved_state;
    uint8_t reserved[427];
} VHDFooter;

typedef struct {
    uint32_t platform_code;
    uint32_t platform_data_space;
    uint32_t platform_data_length;
    uint32_t reserved;
    uint64_t platform_data_offset;
} VHDParentLocator;

typedef struct {
    char cookie[8];
    uint64_t data_offset;
    uint64_t bat_offset;
    uint32_t head_vers;
    uint32_t max_bat_entries;
    uint32_t block_size;
    uint32_t checksum;
    uint8_t parent_id[16];
    uint32_t parent_timestamp;
    uint32_t reserved1;
    uint16_t parent_name[256];
    VHDParentLocator parent_loc[8];
    uint8_t reserved2[256];
} VHDDynamicHeader;

typedef struct {
    uint8_t jump[3];
    uint8_t signature[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t always_zero1[3];
    uint16_t not_used1;
    uint8_t media_descriptor;
    uint16_t always_zero2;
    uint16_t sectors_per_track;
    uint16_t number_of_heads;
    uint32_t hidden_sectors;
    uint32_t not_used2;
    uint32_t not_used3;
    uint64_t total_sectors;
    uint64_t mft_cluster_number;
    uint64_t mft_mirror_cluster_number;
    int8_t clusters_per_mft_record;
    uint8_t not_used4[3];
    int8_t clusters_per_index_record;
    uint8_t not_used5[3];
    uint64_t volume_serial_number;
    uint32_t checksum;
} NTFSBootSector;

typedef struct {
    char magic[4];
    uint16_t usa_offset;
    uint16_t usa_count;
    uint64_t lsn;
    uint16_t sequence_number;
    uint16_t link_count;
    uint16_t attrs_offset;
    uint16_t flags;
    uint32_t bytes_used;
    uint32_t bytes_allocated;
    uint64_t base_ref;
    uint16_t next_attr_id;
    uint16_t record_number;
    uint16_t usa_value;
} MFTRecordHeader;

typedef struct {
    uint32_t type;
    uint32_t length;
    uint8_t non_resident;
    uint8_t name_length;
    uint16_t name_offset;
    uint16_t flags;
    uint16_t attribute_id;
    union {
        struct {
            uint32_t value_length;
            uint16_t value_offset;
            uint16_t flags;
        } resident;
        struct {
            uint64_t lowest_vcn;
            uint64_t highest_vcn;
            uint16_t mapping_pairs_offset;
            uint16_t compression_unit;
            uint32_t padding;
            uint64_t allocated_size;
            uint64_t data_size;
            uint64_t initialized_size;
            uint64_t compressed_size;
        } non_resident;
    } data;
} AttributeHeader;

typedef struct {
    uint64_t parent_directory;
    uint64_t creation_time;
    uint64_t modification_time;
    uint64_t mft_modification_time;
    uint64_t access_time;
    uint64_t allocated_size;
    uint64_t real_size;
    uint32_t flags;
    uint32_t reparse_value;
    uint8_t name_length;
    uint8_t namespace;
    uint16_t name[256];
} FileNameAttribute;

#pragma pack(pop)

typedef struct VHDRunSource {
    void* ntfs_ctx;
    DataRun runs[MAX_DATA_RUNS];
    int run_count;
    uint64_t file_size;
    uint64_t data_start_offset;
    uint32_t bytes_per_cluster;
} VHDRunSource;

typedef struct VHDContext {
    FILE* fp;
    VHDRunSource* run_source;
    VHDFooter footer;
    VHDDynamicHeader dyn_header;
    uint32_t* bat;
    uint32_t sector_bitmap_size;
    uint8_t* sector_bitmap;
    uint8_t* block_buffer;
    uint32_t cached_block_idx;
    bool block_cached;
    struct VHDContext* parent;
    uint32_t depth;
    char base_dir[MAX_PATH_LENGTH];
} VHDContext;

typedef struct {
    char name[MAX_FILENAME_LENGTH];
    uint64_t parent_ref;
    bool is_directory;
    bool valid;
} FileInfo;

typedef struct {
    FILE* fp;
} RawNTFSContext;

#define MAX_PENDING_VHDS 16
#define MAX_PENDING_OPTS 16

typedef struct {
    DataRun runs[MAX_DATA_RUNS];
    int run_count;
    uint64_t file_size;
    int vhd_number;
} PendingVHD;

typedef struct {
    DataRun runs[MAX_DATA_RUNS];
    int run_count;
    uint64_t file_size;
    char filename[MAX_FILENAME_LENGTH];
} PendingOpt;

typedef struct {
    union {
        VHDContext vhd;
        RawNTFSContext raw;
    };
    bool is_vhd;
    NTFSBootSector boot;
    uint16_t bytes_per_sector;
    uint32_t bytes_per_cluster;
    uint64_t mft_offset;
    uint32_t mft_record_size;
    uint64_t mft_data_size;
    uint64_t total_mft_records;
    char base_path[MAX_PATH_LENGTH];
    DirectoryCache dir_cache;
    uint64_t data_start_offset;
    bool silent;
    bool verbose;
    uint64_t extracted_bytes;
    uint64_t files_extracted;
    int highest_extracted_vhd;
    uint64_t raw_file_pos;
    DecryptStream* stream;
    PendingVHD pending_vhds[MAX_PENDING_VHDS];
    int pending_vhd_count;
    PendingOpt pending_opts[MAX_PENDING_OPTS];
    int pending_opt_count;
    uint8_t* lookup_buffer;
    uint8_t* file_buffer;
    char last_dir[MAX_PATH_LENGTH];
    DirHandle cached_dir;
    void* deferred_dirs;
    uint32_t deferred_count;
    uint32_t deferred_capacity;
    uint64_t skip_refs[8];
    int skip_ref_count;
} NTFSContext;

bool ntfs_init(NTFSContext* ctx, const char* vhd_path, const char* extract_path);
bool ntfs_init_stream(NTFSContext* ctx, DecryptStream* stream, const char* extract_path);
bool ntfs_extract_all(NTFSContext* ctx);
bool ntfs_extract_pending_vhds(NTFSContext* ctx, bool silent, bool verbose,
    const char* parent_file, VHDContext* parent_vhd,
    bool* is_orphan, VHDContext** out_base_vhd);
bool vhd_extract_ntfs(VHDContext* vhd, const char* base_path,
                       bool silent, bool verbose,
                       uint64_t* out_files, uint64_t* out_bytes);
bool vhd_init_internal(VHDContext* ctx, const char* filename, uint32_t depth);
bool ntfs_init_vhd(NTFSContext* ctx, const char* vhd_path, const char* extract_path,
                   VHDContext* external_parent);
const PendingOpt* ntfs_get_pending_opt(NTFSContext* ctx, int index);
bool ntfs_read_from_runs(NTFSContext* ctx, const DataRun* runs, int run_count,
    uint64_t file_size, uint64_t read_offset, void* buffer, size_t read_size);
void ntfs_close(NTFSContext* ctx);
void vhd_close(VHDContext* ctx);

#endif