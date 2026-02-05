#include "ntfs.h"
#include "exfat.h"
#include "progress.h"
#define BUFFER_SIZE (1024 * 1024)

uint32_t g_dir_cache[DIR_CACHE_SIZE];
bool g_dir_cache_init;

static bool vhd_read(VHDContext* ctx, void* buffer, uint64_t offset, size_t size);
static bool vhd_init_internal(VHDContext* ctx, const char* filename, uint32_t depth);
static void vhd_close(VHDContext* ctx);
static bool read_bytes_from_runs(NTFSContext* ctx, const DataRun* runs, int run_count,
    uint64_t file_size, uint64_t read_offset, void* buffer, size_t read_size);

static uint32_t swap32(uint32_t value) {
    return ((value & 0xFF000000) >> 24) |
        ((value & 0x00FF0000) >> 8) |
        ((value & 0x0000FF00) << 8) |
        ((value & 0x000000FF) << 24);
}

static uint64_t swap64(uint64_t value) {
    return ((value & 0xFF00000000000000ULL) >> 56) |
        ((value & 0x00FF000000000000ULL) >> 40) |
        ((value & 0x0000FF0000000000ULL) >> 24) |
        ((value & 0x000000FF00000000ULL) >> 8) |
        ((value & 0x00000000FF000000ULL) << 8) |
        ((value & 0x0000000000FF0000ULL) << 24) |
        ((value & 0x000000000000FF00ULL) << 40) |
        ((value & 0x00000000000000FFULL) << 56);
}

static bool ntfs_read(NTFSContext* ctx, void* buffer, uint64_t offset, size_t size) {
    if (ctx->stream) {
        return stream_read(ctx->stream, buffer, offset, size);
    }
    if (ctx->is_vhd) {
        return vhd_read(&ctx->vhd, buffer, offset, size);
    }
    if (ctx->raw_file_pos != offset) {
        if (FSEEKO(ctx->raw.fp, offset, SEEK_SET) != 0) {
            return false;
        }
    }
    if (fread(buffer, 1, size, ctx->raw.fp) != size) {
        return false;
    }
    ctx->raw_file_pos = offset + size;
    return true;
}

static bool apply_mft_fixups(const NTFSContext* ctx, uint8_t* record_buffer, size_t record_size) {
    if (!record_buffer || record_size < sizeof(MFTRecordHeader)) {
        return false;
    }

    MFTRecordHeader* header = (MFTRecordHeader*)record_buffer;
    uint16_t usa_offset = header->usa_offset;
    uint16_t usa_count = header->usa_count;

    if (usa_offset == 0 || usa_count < 2) {
        return true;
    }

    size_t max_entries_available = 0;
    if ((size_t)usa_offset < record_size) {
        max_entries_available = (record_size - (size_t)usa_offset) / sizeof(uint16_t);
    }
    if (max_entries_available < 2) {
        return true;
    }
    if (usa_count > (uint16_t)max_entries_available) {
        usa_count = (uint16_t)max_entries_available;
    }

    uint16_t* usa = (uint16_t*)(record_buffer + usa_offset);
    uint16_t num_sectors = usa_count - 1;
    uint16_t sector_size = (num_sectors > 0) ? (uint16_t)(record_size / num_sectors) : 512;
    if (sector_size == 0) sector_size = 512;

    for (uint16_t i = 1; i <= num_sectors; i++) {
        size_t tail_offset = (size_t)i * sector_size - 2;
        if (tail_offset + 2 > record_size) continue;
        uint16_t* tail = (uint16_t*)(record_buffer + tail_offset);
        *tail = usa[i];
    }

    return true;
}

static bool read_file_info(NTFSContext* ctx, uint64_t ref_number, FileInfo* info) {
    memset(info, 0, sizeof(FileInfo));

    uint64_t mft_offset = ctx->mft_offset + (ref_number * ctx->mft_record_size);

    if (!ctx->lookup_buffer) {
        ctx->lookup_buffer = malloc(ctx->mft_record_size);
        if (!ctx->lookup_buffer) return false;
    }
    uint8_t* record_buffer = ctx->lookup_buffer;

    bool success = false;
    if (ntfs_read(ctx, record_buffer, mft_offset, ctx->mft_record_size)) {
        if (!apply_mft_fixups(ctx, record_buffer, ctx->mft_record_size)) {
            return false;
        }
        const MFTRecordHeader* record = (const MFTRecordHeader*)record_buffer;

        if (memcmp(record->magic, "FILE", 4) != 0 || !(record->flags & MFT_RECORD_IN_USE)) {
            return false;
        }

        uint32_t attrs_offset = record->attrs_offset;
        uint32_t bytes_used = record->bytes_used;
        if (attrs_offset >= ctx->mft_record_size || bytes_used > ctx->mft_record_size) {
            return false;
        }
        bytes_used = min(bytes_used, ctx->mft_record_size);

        info->is_directory = (record->flags & MFT_RECORD_IS_DIRECTORY) != 0;

        const uint8_t* record_end = record_buffer + bytes_used;
        const uint8_t* attr = record_buffer + attrs_offset;

        while (attr + sizeof(AttributeHeader) <= record_end) {
            const AttributeHeader* header = (const AttributeHeader*)attr;

            if (header->type == 0xFFFFFFFF || header->length == 0) {
                break;
            }
            if (header->length < sizeof(AttributeHeader) || attr + header->length > record_end) {
                break;
            }

            if (header->type == FILE_NAME_ATTR && !header->non_resident) {
                uint16_t value_offset = header->data.resident.value_offset;
                uint32_t value_length = header->data.resident.value_length;
                if (value_offset + value_length > header->length) break;

                const FileNameAttribute* fname = (const FileNameAttribute*)(attr + value_offset);
                if ((const uint8_t*)fname + 66 > attr + header->length) break;

                if (fname->namespace != 2) {
                    fs_name_to_utf8(fname->name, fname->name_length, info->name, sizeof(info->name));
                    info->parent_ref = fname->parent_directory & 0xFFFFFFFFFFFF;
                    info->valid = true;
                    success = true;
                    break;
                }
            }

            attr += header->length;
        }
    }

    return success;
}

static inline size_t hash_ref(uint64_t ref, size_t capacity) {
    ref ^= ref >> 33;
    ref *= 0xff51afd7ed558ccdULL;
    ref ^= ref >> 33;
    ref *= 0xc4ceb9fe1a85ec53ULL;
    ref ^= ref >> 33;
    return ref % capacity;
}

static bool init_directory_cache(DirectoryCache* cache) {
    cache->capacity = DIR_CACHE_INITIAL_SIZE;
    cache->count = 0;
    cache->entries = calloc(cache->capacity, sizeof(DirectoryEntry));
    if (!cache->entries) return false;

    uint64_t hash = 5 % cache->capacity;
    cache->entries[hash].ref_number = 5;
    cache->entries[hash].path[0] = '\0';
    cache->entries[hash].occupied = true;
    cache->count = 1;
    return true;
}

static void free_directory_cache(DirectoryCache* cache) {
    free(cache->entries);
    cache->entries = NULL;
    cache->capacity = 0;
    cache->count = 0;
}

static bool resize_directory_cache(DirectoryCache* cache) {
    size_t new_capacity = cache->capacity * 2;
    DirectoryEntry* new_entries = calloc(new_capacity, sizeof(DirectoryEntry));
    if (!new_entries) return false;

    for (size_t i = 0; i < cache->capacity; i++) {
        if (cache->entries[i].occupied) {
            size_t idx = hash_ref(cache->entries[i].ref_number, new_capacity);
            while (new_entries[idx].occupied) {
                idx = (idx + 1) % new_capacity;
            }
            new_entries[idx] = cache->entries[i];
        }
    }

    free(cache->entries);
    cache->entries = new_entries;
    cache->capacity = new_capacity;
    return true;
}

static bool add_directory_to_cache(DirectoryCache* cache, uint64_t ref_number, const char* path) {
    if (cache->count * 10 > cache->capacity * 7) {
        if (!resize_directory_cache(cache)) return false;
    }

    size_t idx = hash_ref(ref_number, cache->capacity);
    while (cache->entries[idx].occupied) {
        if (cache->entries[idx].ref_number == ref_number) {
            strncpy(cache->entries[idx].path, path, MAX_PATH_LENGTH - 1);
            cache->entries[idx].path[MAX_PATH_LENGTH - 1] = '\0';
            return true;
        }
        idx = (idx + 1) % cache->capacity;
    }

    cache->entries[idx].ref_number = ref_number;
    strncpy(cache->entries[idx].path, path, MAX_PATH_LENGTH - 1);
    cache->entries[idx].path[MAX_PATH_LENGTH - 1] = '\0';
    cache->entries[idx].occupied = true;
    cache->count++;
    return true;
}

static const char* get_cached_path(DirectoryCache* cache, uint64_t ref_number) {
    size_t idx = hash_ref(ref_number, cache->capacity);
    while (cache->entries[idx].occupied) {
        if (cache->entries[idx].ref_number == ref_number) {
            return cache->entries[idx].path;
        }
        idx = (idx + 1) % cache->capacity;
    }
    return NULL;
}

static bool build_path_impl(NTFSContext* ctx, uint64_t ref_number, char* buffer, size_t buffer_size, int depth) {
    if (depth > NTFS_MAX_RECURSION_DEPTH) {
        return false;
    }

    if (ref_number == 5) {
        buffer[0] = '\0';
        return true;
    }

    const char* cached_path = get_cached_path(&ctx->dir_cache, ref_number);
    if (cached_path) {
        strncpy(buffer, cached_path, buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
        return true;
    }

    FileInfo info;
    if (!read_file_info(ctx, ref_number, &info) || !info.valid) {
        return false;
    }

    if (info.name[0] == '$') {
        return false;
    }

    char parent_path[MAX_PATH_LENGTH];
    if (!build_path_impl(ctx, info.parent_ref, parent_path, sizeof(parent_path), depth + 1)) {
        return false;
    }

    if (parent_path[0] == '\0') {
        strncpy(buffer, info.name, buffer_size - 1);
    }
    else {
        snprintf(buffer, buffer_size, "%s%s%s", parent_path, PATH_SEPARATOR, info.name);
    }
    buffer[buffer_size - 1] = '\0';

    if (info.is_directory) {
        add_directory_to_cache(&ctx->dir_cache, ref_number, buffer);
    }

    return true;
}

static bool build_path_recursively(NTFSContext* ctx, uint64_t ref_number, char* buffer, size_t buffer_size) {
    return build_path_impl(ctx, ref_number, buffer, buffer_size, 0);
}

static void get_full_path(NTFSContext* ctx, uint64_t parent_ref, const char* name,
    char* out_path, size_t out_size) {
    char parent_path[MAX_PATH_LENGTH];

    if (!build_path_recursively(ctx, parent_ref, parent_path, sizeof(parent_path))) {
        snprintf(out_path, out_size, "%s%s%s",
            ctx->base_path,
            PATH_SEPARATOR,
            name);
        return;
    }

    if (parent_path[0] == '\0') {
        snprintf(out_path, out_size, "%s%s%s",
            ctx->base_path,
            PATH_SEPARATOR,
            name);
    }
    else {
        snprintf(out_path, out_size, "%s%s%s%s%s",
            ctx->base_path,
            PATH_SEPARATOR,
            parent_path,
            PATH_SEPARATOR,
            name);
    }
}

static bool extract_data_from_runs(NTFSContext* ctx, const DataRun* runs, int run_count,
    uint64_t data_size, FILE* out_file) {
    if (!ctx->file_buffer) return false;

    uint64_t total_written = 0;
    bool success = true;

    for (int i = 0; i < run_count && total_written < data_size; i++) {
        uint64_t cluster_offset = ctx->data_start_offset +
            (runs[i].offset * ctx->bytes_per_cluster);
        uint64_t length = runs[i].length * ctx->bytes_per_cluster;

        if (length > data_size - total_written) {
            length = data_size - total_written;
        }

        uint64_t remaining = length;
        while (remaining > 0 && success) {
            size_t to_read = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : (size_t)remaining;

            if (!ntfs_read(ctx, ctx->file_buffer, cluster_offset, to_read)) {
                success = false;
                break;
            }

            if (FWRITE_DIRECT(out_file, ctx->file_buffer, to_read) != to_read) {
                success = false;
                break;
            }

            cluster_offset += to_read;
            remaining -= to_read;
            total_written += to_read;

            ctx->extracted_bytes += to_read;
            if (ctx->progress) {
                progress_update((Progress*)ctx->progress, ctx->extracted_bytes);
            }
        }
    }

    return success;
}

static bool read_bytes_from_runs(NTFSContext* ctx, const DataRun* runs, int run_count,
    uint64_t file_size, uint64_t read_offset, void* buffer, size_t read_size) {
    if (read_offset + read_size > file_size) {
        return false;
    }

    uint64_t current_file_pos = 0;
    uint8_t* out = (uint8_t*)buffer;
    size_t bytes_remaining = read_size;

    for (int i = 0; i < run_count && bytes_remaining > 0; i++) {
        uint64_t run_bytes = runs[i].length * ctx->bytes_per_cluster;
        uint64_t run_start = current_file_pos;
        uint64_t run_end = run_start + run_bytes;

        if (read_offset < run_end && read_offset + read_size > run_start) {
            uint64_t start_in_run = (read_offset > run_start) ? (read_offset - run_start) : 0;
            uint64_t end_in_run = ((read_offset + read_size) < run_end) ?
                (read_offset + read_size - run_start) : run_bytes;
            size_t chunk_size = (size_t)(end_in_run - start_in_run);

            uint64_t disk_offset = ctx->data_start_offset +
                (runs[i].offset * ctx->bytes_per_cluster) + start_in_run;

            if (!ntfs_read(ctx, out, disk_offset, chunk_size)) {
                return false;
            }

            out += chunk_size;
            bytes_remaining -= chunk_size;
        }

        current_file_pos = run_end;
    }

    return bytes_remaining == 0;
}

static int parse_data_runs(const uint8_t* run_list, size_t run_list_len, DataRun* runs, int max_runs) {
    int count = 0;
    uint64_t offset_base = 0;
    const uint8_t* p = run_list;
    const uint8_t* end = run_list + run_list_len;

    while (p < end && *p != 0 && count < max_runs) {
        uint8_t header = *p++;
        int length_size = header & 0xF;
        int offset_size = header >> 4;

        if (length_size == 0) break;
        if (p + length_size + offset_size > end) break;

        uint64_t length = 0;
        for (int i = 0; i < length_size; i++) {
            length |= ((uint64_t)*p++) << (i * 8);
        }

        int64_t offset = 0;
        if (offset_size > 0) {
            for (int i = 0; i < offset_size; i++) {
                offset |= ((uint64_t)*p++) << (i * 8);
            }
            if (offset & ((uint64_t)1 << ((offset_size * 8) - 1))) {
                offset |= ~((uint64_t)(1ULL << (offset_size * 8)) - 1);
            }
        }

        offset_base += offset;
        runs[count].offset = offset_base;
        runs[count].length = length;
        count++;
    }

    return count;
}

static int parse_internal_vhd_number(const char* filename) {
    if (strncmp(filename, "internal_", 9) != 0) return -1;

    size_t len = strlen(filename);
    if (len < 13 || strcmp(filename + len - 4, ".vhd") != 0) return -1;

    char num_str[8] = {0};
    size_t num_len = len - 13;
    if (num_len == 0 || num_len > 7) return -1;

    memcpy(num_str, filename + 9, num_len);
    for (size_t i = 0; i < num_len; i++) {
        if (num_str[i] < '0' || num_str[i] > '9') return -1;
    }
    return atoi(num_str);
}

static bool store_pending_vhd(NTFSContext* ctx, const MFTRecordHeader* record, int vhd_number) {
    if (ctx->pending_vhd_count >= MAX_PENDING_VHDS) return false;

    const uint8_t* attr = (const uint8_t*)record + record->attrs_offset;
    while (attr < (const uint8_t*)record + record->bytes_used) {
        const AttributeHeader* header = (const AttributeHeader*)attr;

        if (header->type == 0xFFFFFFFF || header->length == 0) break;

        if (header->type == DATA_ATTR && header->name_length == 0 && header->non_resident) {
            PendingVHD* pending = &ctx->pending_vhds[ctx->pending_vhd_count];
            const uint8_t* run_list = attr + header->data.non_resident.mapping_pairs_offset;
            size_t run_list_len = header->length - header->data.non_resident.mapping_pairs_offset;
            pending->run_count = parse_data_runs(run_list, run_list_len, pending->runs, MAX_DATA_RUNS);
            pending->file_size = header->data.non_resident.data_size;
            pending->vhd_number = vhd_number;
            ctx->pending_vhd_count++;
            return true;
        }
        attr += header->length;
    }
    return false;
}

static bool store_pending_opt(NTFSContext* ctx, const char* filename, const MFTRecordHeader* record) {
    if (ctx->pending_opt_count >= MAX_PENDING_OPTS) return false;

    const uint8_t* attr = (const uint8_t*)record + record->attrs_offset;
    while (attr < (const uint8_t*)record + record->bytes_used) {
        const AttributeHeader* header = (const AttributeHeader*)attr;

        if (header->type == 0xFFFFFFFF || header->length == 0) break;

        if (header->type == DATA_ATTR && header->name_length == 0 && header->non_resident) {
            PendingOpt* pending = &ctx->pending_opts[ctx->pending_opt_count];
            const uint8_t* run_list = attr + header->data.non_resident.mapping_pairs_offset;
            size_t run_list_len = header->length - header->data.non_resident.mapping_pairs_offset;
            pending->run_count = parse_data_runs(run_list, run_list_len, pending->runs, MAX_DATA_RUNS);
            pending->file_size = header->data.non_resident.data_size;
            pending->data_offset = ctx->data_start_offset;
            strncpy(pending->filename, filename, MAX_FILENAME_LENGTH - 1);
            pending->filename[MAX_FILENAME_LENGTH - 1] = '\0';
            ctx->pending_opt_count++;
            return true;
        }
        attr += header->length;
    }
    return false;
}

static bool extract_file(NTFSContext* ctx, const MFTRecordHeader* record,
    const char* full_path, const char* filename, uint64_t modification_time, uint64_t access_time) {

    const char* ext = strrchr(filename, '.');
    bool is_opt_file = ext && strcmp(ext, ".opt") == 0;

    if (ctx->stream) {
        int vhd_num = parse_internal_vhd_number(filename);
        if (vhd_num >= 0) {
            return store_pending_vhd(ctx, record, vhd_num);
        }
        if (is_opt_file) {
            return store_pending_opt(ctx, filename, record);
        }
    }

    uint64_t file_size = 0;
    const uint8_t* data_attr = NULL;
    const uint8_t* attr = (const uint8_t*)record + record->attrs_offset;
    while (attr < (const uint8_t*)record + record->bytes_used) {
        const AttributeHeader* header = (const AttributeHeader*)attr;
        if (header->type == 0xFFFFFFFF || header->length == 0) break;
        if (header->type == DATA_ATTR && header->name_length == 0) {
            data_attr = attr;
            if (header->non_resident) {
                file_size = header->data.non_resident.data_size;
            } else {
                file_size = header->data.resident.value_length;
            }
            break;
        }
        attr += header->length;
    }
    if (!data_attr) return true;

    char parent_path[MAX_PATH_LENGTH];
    strncpy(parent_path, full_path, sizeof(parent_path) - 1);
    parent_path[sizeof(parent_path) - 1] = '\0';

    char* last_separator = strrchr(parent_path, PATH_SEPARATOR[0]);
    if (last_separator) {
        *last_separator = '\0';
        if (strcmp(parent_path, ctx->last_dir) != 0) {
            create_directories(parent_path);
            strncpy(ctx->last_dir, parent_path, MAX_PATH_LENGTH - 1);
            ctx->last_dir[MAX_PATH_LENGTH - 1] = '\0';
        }
    }

    FILE* out_file;
    if (file_size >= 65536) {
        out_file = FOPEN_PREALLOC(full_path, file_size);
    } else {
        out_file = FOPEN(full_path, "wb");
    }
    if (!out_file) {
        return false;
    }

    bool success = false;
    const AttributeHeader* header = (const AttributeHeader*)data_attr;

    if (header->non_resident) {
        DataRun runs[256];
        const uint8_t* run_list = data_attr + header->data.non_resident.mapping_pairs_offset;
        size_t run_list_len = header->length - header->data.non_resident.mapping_pairs_offset;
        int run_count = parse_data_runs(run_list, run_list_len, runs, 256);

        success = extract_data_from_runs(ctx, runs, run_count, file_size, out_file);
    }
    else {
        const uint8_t* data = data_attr + header->data.resident.value_offset;
        uint32_t len = header->data.resident.value_length;
        success = (FWRITE_DIRECT(out_file, data, len) == len);
        if (success) {
            ctx->extracted_bytes += len;
            if (ctx->progress) {
                progress_update((Progress*)ctx->progress, ctx->extracted_bytes);
            }
        }
    }

    if (success && (modification_time != 0 || access_time != 0)) {
#ifdef _WIN32
        set_file_times_handle(out_file, modification_time, access_time);
#endif
    }

    fclose(out_file);
    if (!success) {
        REMOVE(full_path);
    }
    else {
        ctx->files_extracted++;
#ifndef _WIN32
        if (modification_time != 0 || access_time != 0) {
            set_file_times(full_path, modification_time, access_time);
        }
#endif
    }
    return success;
}

static bool process_mft_record(NTFSContext* ctx, const uint8_t* record_data) {
    const MFTRecordHeader* record = (const MFTRecordHeader*)record_data;

    if (memcmp(record->magic, "FILE", 4) != 0 || !(record->flags & MFT_RECORD_IN_USE)) {
        return true;
    }

    uint32_t attrs_offset = record->attrs_offset;
    uint32_t bytes_used = record->bytes_used;
    if (attrs_offset >= ctx->mft_record_size || bytes_used > ctx->mft_record_size) {
        return true;
    }
    bytes_used = min(bytes_used, ctx->mft_record_size);

    char filename[MAX_FILENAME_LENGTH];
    uint64_t parent_ref = 0;
    uint64_t modification_time = 0;
    uint64_t access_time = 0;
    bool got_filename = false;
    bool is_directory = (record->flags & MFT_RECORD_IS_DIRECTORY) != 0;
    uint64_t record_num = record->record_number & 0xFFFFFFFFFFFF;

    const uint8_t* record_end = record_data + bytes_used;
    const uint8_t* attr = record_data + attrs_offset;

    while (attr + sizeof(AttributeHeader) <= record_end) {
        const AttributeHeader* header = (const AttributeHeader*)attr;

        if (header->type == 0xFFFFFFFF || header->length == 0) {
            break;
        }
        if (header->length < sizeof(AttributeHeader) || attr + header->length > record_end) {
            break;
        }

        if (header->type == FILE_NAME_ATTR && !header->non_resident) {
            uint16_t value_offset = header->data.resident.value_offset;
            uint32_t value_length = header->data.resident.value_length;
            if (value_offset + value_length > header->length) break;

            const FileNameAttribute* fname = (const FileNameAttribute*)(attr + value_offset);
            if ((const uint8_t*)fname + 66 > attr + header->length) break;

            if (fname->namespace != 2) {
                fs_name_to_utf8(fname->name, fname->name_length, filename, sizeof(filename));
                parent_ref = fname->parent_directory & 0xFFFFFFFFFFFF;
                modification_time = fname->modification_time;
                access_time = fname->access_time;
                got_filename = true;
                break;
            }
        }

        attr += header->length;
    }

    if (!got_filename) {
        return true;
    }

    if (filename[0] == '$') {
        return true;
    }

    if (!is_safe_path(filename)) {
        return true;
    }



    char full_path[MAX_PATH_LENGTH];
    get_full_path(ctx, parent_ref, filename, full_path, sizeof(full_path));

    if (is_directory) {
        if (!create_directories(full_path)) {
            return false;
        }

        if (modification_time != 0) {
            DeferredDirTime* dirs = (DeferredDirTime*)ctx->deferred_dirs;
            if (ctx->deferred_count >= ctx->deferred_capacity) {
                uint32_t new_cap = ctx->deferred_capacity ? ctx->deferred_capacity * 2 : 256;
                DeferredDirTime* new_buf = realloc(dirs, new_cap * sizeof(DeferredDirTime));
                if (new_buf) {
                    ctx->deferred_dirs = new_buf;
                    ctx->deferred_capacity = new_cap;
                    dirs = new_buf;
                }
            }
            if (ctx->deferred_count < ctx->deferred_capacity) {
                DeferredDirTime* d = &dirs[ctx->deferred_count++];
                STRCPY_S(d->path, sizeof(d->path), full_path);
                d->mtime = modification_time;
                d->atime = access_time;
            }
        }

        const char* relative_path = full_path + strlen(ctx->base_path);
        while (*relative_path == PATH_SEPARATOR[0]) relative_path++;

        if (!add_directory_to_cache(&ctx->dir_cache, record_num, relative_path)) {
            return false;
        }
        return true;
    }

    return extract_file(ctx, record, full_path, filename, modification_time, access_time);
}

static bool vhd_raw_read(VHDContext* ctx, void* buffer, uint64_t offset, size_t size) {
    if (ctx->run_source) {
        NTFSContext* ntfs = (NTFSContext*)ctx->run_source->ntfs_ctx;
        return read_bytes_from_runs(ntfs, ctx->run_source->runs, ctx->run_source->run_count,
            ctx->run_source->file_size, offset, buffer, size);
    }
    if (FSEEKO(ctx->fp, offset, SEEK_SET) != 0) {
        return false;
    }
    return fread(buffer, 1, size, ctx->fp) == size;
}

static uint64_t vhd_get_size(VHDContext* ctx) {
    if (ctx->run_source) {
        return ctx->run_source->file_size;
    }
    int64_t current = FTELLO(ctx->fp);
    FSEEKO(ctx->fp, 0, SEEK_END);
    int64_t size = FTELLO(ctx->fp);
    FSEEKO(ctx->fp, current, SEEK_SET);
    return (uint64_t)size;
}

static bool vhd_read_dynamic_block(VHDContext* ctx, uint8_t* buf, uint64_t offset, size_t size, bool is_differencing) {
    uint64_t block_size = ctx->dyn_header.block_size;

    while (size > 0) {
        uint32_t block_idx = (uint32_t)(offset / block_size);
        uint32_t block_offset = (uint32_t)(offset % block_size);

        if (block_idx >= ctx->dyn_header.max_bat_entries) {
            return false;
        }

        uint32_t bat_entry = ctx->bat[block_idx];
        size_t chunk = (size < (block_size - block_offset)) ?
            size : (size_t)(block_size - block_offset);

        if (bat_entry == VHD_BAT_ENTRY_RESERVED) {
            if (is_differencing && ctx->parent) {
                if (!vhd_read(ctx->parent, buf, offset, chunk)) {
                    return false;
                }
            } else {
                memset(buf, 0, chunk);
            }
        } else {
            if (!ctx->block_cached || ctx->cached_block_idx != block_idx) {
                uint64_t sector_file_offset = ((uint64_t)bat_entry) * VHD_SECTOR_SIZE;

                if (!vhd_raw_read(ctx, ctx->sector_bitmap, sector_file_offset, ctx->sector_bitmap_size)) {
                    return false;
                }

                if (!vhd_raw_read(ctx, ctx->block_buffer, sector_file_offset + ctx->sector_bitmap_size, block_size)) {
                    return false;
                }

                ctx->cached_block_idx = block_idx;
                ctx->block_cached = true;
            }

            if (is_differencing && ctx->parent) {
                uint32_t start_sector = block_offset / VHD_SECTOR_SIZE;
                uint32_t end_offset = block_offset + (uint32_t)chunk;
                uint32_t end_sector = (end_offset + VHD_SECTOR_SIZE - 1) / VHD_SECTOR_SIZE;

                for (uint32_t s = start_sector; s < end_sector; s++) {
                    uint32_t byte_idx = s / 8;
                    uint32_t bit_idx = 7 - (s % 8);
                    bool sector_present = (ctx->sector_bitmap[byte_idx] >> bit_idx) & 1;

                    uint32_t sector_start_in_block = s * VHD_SECTOR_SIZE;
                    uint32_t sector_end_in_block = sector_start_in_block + VHD_SECTOR_SIZE;

                    uint32_t copy_start = (sector_start_in_block < block_offset) ? block_offset : sector_start_in_block;
                    uint32_t copy_end = (sector_end_in_block > end_offset) ? end_offset : sector_end_in_block;

                    if (copy_start >= copy_end) continue;

                    size_t copy_len = copy_end - copy_start;
                    size_t buf_offset = copy_start - block_offset;

                    if (sector_present) {
                        memcpy(buf + buf_offset, ctx->block_buffer + copy_start, copy_len);
                    } else {
                        uint64_t parent_offset = (uint64_t)block_idx * block_size + copy_start;
                        if (!vhd_read(ctx->parent, buf + buf_offset, parent_offset, copy_len)) {
                            return false;
                        }
                    }
                }
            } else {
                memcpy(buf, ctx->block_buffer + block_offset, chunk);
            }
        }

        buf += chunk;
        offset += chunk;
        size -= chunk;
    }
    return true;
}

static bool vhd_read(VHDContext* ctx, void* buffer, uint64_t offset, size_t size) {
    if (ctx->footer.disk_type == VHD_TYPE_FIXED) {
        return vhd_raw_read(ctx, buffer, offset, size);
    }
    else if (ctx->footer.disk_type == VHD_TYPE_DYNAMIC) {
        return vhd_read_dynamic_block(ctx, (uint8_t*)buffer, offset, size, false);
    }
    else if (ctx->footer.disk_type == VHD_TYPE_DIFFERENCING) {
        return vhd_read_dynamic_block(ctx, (uint8_t*)buffer, offset, size, true);
    }
    return false;
}

static void extract_base_dir(const char* filepath, char* base_dir, size_t base_dir_size) {
    strncpy(base_dir, filepath, base_dir_size - 1);
    base_dir[base_dir_size - 1] = '\0';

    char* last_sep = NULL;
    for (char* p = base_dir; *p; p++) {
        if (*p == '/' || *p == '\\') {
            last_sep = p;
        }
    }
    if (last_sep) {
        *(last_sep + 1) = '\0';
    } else {
        base_dir[0] = '\0';
    }
}

static const char* extract_filename(const char* path) {
    const char* last_slash = strrchr(path, '/');
    const char* last_backslash = strrchr(path, '\\');
    const char* filename = path;
    if (last_slash && last_slash > filename) filename = last_slash + 1;
    if (last_backslash && last_backslash > filename - 1) filename = last_backslash + 1;
    return filename;
}

static bool try_parent_path(const char* base_dir, const char* filename, char* parent_path, size_t path_size) {
    snprintf(parent_path, path_size, "%s%s", base_dir, filename);
    FILE* test = FOPEN(parent_path, "rb");
    if (test) {
        fclose(test);
        return true;
    }
    return false;
}

static bool resolve_parent_path(VHDContext* ctx, char* parent_path, size_t path_size) {
    char parent_filename[MAX_FILENAME_LENGTH] = "internal_0.vhd";

    for (int i = 0; i < 8; i++) {
        VHDParentLocator* loc = &ctx->dyn_header.parent_loc[i];
        uint32_t code = swap32(loc->platform_code);
        uint32_t data_len = swap32(loc->platform_data_length);
        uint64_t data_offset = swap64(loc->platform_data_offset);

        if (code == 0 || data_len == 0 || data_len > 2048) continue;

        uint8_t* path_data = malloc(data_len + 2);
        if (!path_data) continue;

        if (!vhd_raw_read(ctx, path_data, data_offset, data_len)) {
            free(path_data);
            continue;
        }
        path_data[data_len] = 0;
        path_data[data_len + 1] = 0;

        char locator_path[MAX_PATH_LENGTH];
        size_t utf16_len = data_len / 2;
        utf16_to_utf8((const uint16_t*)path_data, (int)utf16_len, locator_path, sizeof(locator_path));
        free(path_data);

        const char* filename = extract_filename(locator_path);
        if (filename[0] != '\0') {
            strncpy(parent_filename, filename, sizeof(parent_filename) - 1);
            break;
        }
    }

    if (try_parent_path(ctx->base_dir, parent_filename, parent_path, path_size)) {
        return true;
    }

    parent_path[0] = '\0';
    return false;
}

static void vhd_close(VHDContext* ctx) {
    if (!ctx) return;

    if (ctx->parent) {
        vhd_close(ctx->parent);
        free(ctx->parent);
        ctx->parent = NULL;
    }

    if (ctx->fp) {
        fclose(ctx->fp);
        ctx->fp = NULL;
    }
    free(ctx->run_source);
    ctx->run_source = NULL;
    free(ctx->bat);
    free(ctx->sector_bitmap);
    free(ctx->block_buffer);
    ctx->bat = NULL;
    ctx->sector_bitmap = NULL;
    ctx->block_buffer = NULL;
}

static bool vhd_init_dynamic_header(VHDContext* ctx) {
    if (!vhd_raw_read(ctx, &ctx->dyn_header, ctx->footer.data_offset, sizeof(VHDDynamicHeader))) {
        return false;
    }

    if (memcmp(ctx->dyn_header.cookie, VHD_DYNAMIC_COOKIE, strlen(VHD_DYNAMIC_COOKIE)) != 0) {
        return false;
    }

    ctx->dyn_header.data_offset = swap64(ctx->dyn_header.data_offset);
    ctx->dyn_header.bat_offset = swap64(ctx->dyn_header.bat_offset);
    ctx->dyn_header.head_vers = swap32(ctx->dyn_header.head_vers);
    ctx->dyn_header.max_bat_entries = swap32(ctx->dyn_header.max_bat_entries);
    ctx->dyn_header.block_size = swap32(ctx->dyn_header.block_size);
    ctx->dyn_header.parent_timestamp = swap32(ctx->dyn_header.parent_timestamp);

    size_t bat_size = (size_t)ctx->dyn_header.max_bat_entries * sizeof(uint32_t);

    if (bat_size == 0 || bat_size > (1ULL << 30)) {
        return false;
    }

    ctx->bat = malloc(bat_size);
    if (!ctx->bat) {
        return false;
    }

    if (!vhd_raw_read(ctx, ctx->bat, ctx->dyn_header.bat_offset, bat_size)) {
        return false;
    }

    for (uint32_t i = 0; i < ctx->dyn_header.max_bat_entries; i++) {
        ctx->bat[i] = swap32(ctx->bat[i]);
    }

    ctx->sector_bitmap_size = (ctx->dyn_header.block_size / VHD_SECTOR_SIZE + 7) / 8;
    ctx->sector_bitmap = malloc(ctx->sector_bitmap_size);
    ctx->block_buffer = malloc(ctx->dyn_header.block_size);

    if (!ctx->sector_bitmap || !ctx->block_buffer) {
        return false;
    }

    return true;
}

static bool vhd_read_footer(VHDContext* ctx) {
    uint64_t file_size = vhd_get_size(ctx);
    if (file_size < VHD_FOOTER_SIZE) {
        return false;
    }

    if (!vhd_raw_read(ctx, &ctx->footer, file_size - VHD_FOOTER_SIZE, sizeof(VHDFooter))) {
        return false;
    }

    if (memcmp(ctx->footer.cookie, VHD_COOKIE, strlen(VHD_COOKIE)) != 0) {
        return false;
    }

    ctx->footer.features = swap32(ctx->footer.features);
    ctx->footer.version = swap32(ctx->footer.version);
    ctx->footer.data_offset = swap64(ctx->footer.data_offset);
    ctx->footer.timestamp = swap32(ctx->footer.timestamp);
    ctx->footer.creator_app = swap32(ctx->footer.creator_app);
    ctx->footer.creator_ver = swap32(ctx->footer.creator_ver);
    ctx->footer.creator_os = swap32(ctx->footer.creator_os);
    ctx->footer.original_size = swap64(ctx->footer.original_size);
    ctx->footer.current_size = swap64(ctx->footer.current_size);
    ctx->footer.cylinder = ((ctx->footer.cylinder >> 8) | (ctx->footer.cylinder << 8));
    ctx->footer.disk_type = swap32(ctx->footer.disk_type);
    ctx->footer.checksum = swap32(ctx->footer.checksum);
    return true;
}

static bool vhd_init_common(VHDContext* ctx, const char* base_dir, uint32_t depth) {
    if (!vhd_read_footer(ctx)) {
        return false;
    }

    if (ctx->footer.disk_type == VHD_TYPE_DYNAMIC) {
        if (!vhd_init_dynamic_header(ctx)) {
            return false;
        }
    }
    else if (ctx->footer.disk_type == VHD_TYPE_DIFFERENCING) {
        if (!vhd_init_dynamic_header(ctx)) {
            return false;
        }

        char parent_path[MAX_PATH_LENGTH];
        if (resolve_parent_path(ctx, parent_path, sizeof(parent_path))) {
            ctx->parent = malloc(sizeof(VHDContext));
            if (ctx->parent) {
                if (!vhd_init_internal(ctx->parent, parent_path, depth + 1)) {
                    free(ctx->parent);
                    ctx->parent = NULL;
                    return false;
                }
            }
        } else {
            return false;
        }
    }
    return true;
}

static bool vhd_init_internal(VHDContext* ctx, const char* filename, uint32_t depth) {
    memset(ctx, 0, sizeof(VHDContext));
    ctx->depth = depth;

    if (depth > VHD_MAX_CHAIN_DEPTH) {
        return false;
    }

    extract_base_dir(filename, ctx->base_dir, sizeof(ctx->base_dir));

    ctx->fp = FOPEN(filename, "rb");
    if (!ctx->fp) {
        return false;
    }

    if (!vhd_init_common(ctx, ctx->base_dir, depth)) {
        vhd_close(ctx);
        return false;
    }

    return true;
}

static bool vhd_init(VHDContext* ctx, const char* filename) {
    return vhd_init_internal(ctx, filename, 0);
}

static bool vhd_init_from_runs(VHDContext* ctx, NTFSContext* ntfs, const DataRun* runs,
    int run_count, uint64_t file_size, const char* base_dir) {
    memset(ctx, 0, sizeof(VHDContext));

    ctx->run_source = malloc(sizeof(VHDRunSource));
    if (!ctx->run_source) {
        return false;
    }

    ctx->run_source->ntfs_ctx = ntfs;
    ctx->run_source->run_count = (run_count < MAX_DATA_RUNS) ? run_count : MAX_DATA_RUNS;
    ctx->run_source->file_size = file_size;
    ctx->run_source->data_start_offset = ntfs->data_start_offset;
    ctx->run_source->bytes_per_cluster = ntfs->bytes_per_cluster;
    memcpy(ctx->run_source->runs, runs, ctx->run_source->run_count * sizeof(DataRun));
    strncpy(ctx->base_dir, base_dir, sizeof(ctx->base_dir) - 1);

    if (!vhd_init_common(ctx, base_dir, 0)) {
        vhd_close(ctx);
        return false;
    }
    return true;
}

static bool ntfs_setup_mft(NTFSContext* ctx, uint64_t ntfs_offset) {
    ctx->data_start_offset = ntfs_offset;

    if (!ntfs_read(ctx, &ctx->boot, ntfs_offset, sizeof(NTFSBootSector))) {
        return false;
    }

    ctx->bytes_per_sector = ctx->boot.bytes_per_sector;
    ctx->bytes_per_cluster = (uint32_t)ctx->boot.bytes_per_sector * ctx->boot.sectors_per_cluster;
    ctx->mft_offset = ntfs_offset + (ctx->boot.mft_cluster_number * ctx->bytes_per_cluster);

    if (ctx->boot.clusters_per_mft_record > 0) {
        ctx->mft_record_size = ctx->boot.clusters_per_mft_record * ctx->bytes_per_cluster;
    } else {
        ctx->mft_record_size = 1U << (-ctx->boot.clusters_per_mft_record);
    }

    ctx->file_buffer = malloc(BUFFER_SIZE);
    if (!ctx->file_buffer) return false;
    ctx->last_dir[0] = '\0';

    uint8_t* mft_record = malloc(ctx->mft_record_size);
    if (!mft_record) return false;

    if (!ntfs_read(ctx, mft_record, ctx->mft_offset, ctx->mft_record_size) ||
        !apply_mft_fixups(ctx, mft_record, ctx->mft_record_size)) {
        free(mft_record);
        return false;
    }

    const MFTRecordHeader* record = (const MFTRecordHeader*)mft_record;
    if (memcmp(record->magic, "FILE", 4) != 0) {
        free(mft_record);
        return false;
    }

    const uint8_t* attr = mft_record + record->attrs_offset;
    while (attr < mft_record + record->bytes_used) {
        const AttributeHeader* header = (const AttributeHeader*)attr;
        if (header->type == 0xFFFFFFFF || header->length == 0) break;
        if (header->type == DATA_ATTR && header->name_length == 0) {
            if (header->non_resident) {
                ctx->mft_data_size = header->data.non_resident.data_size;
                ctx->total_mft_records = ctx->mft_data_size / ctx->mft_record_size;
            }
            break;
        }
        attr += header->length;
    }

    free(mft_record);
    return true;
}

bool ntfs_init(NTFSContext* ctx, const char* path, const char* extract_path) {
    bool silent = ctx->silent;
    bool verbose = ctx->verbose;

    memset(ctx, 0, sizeof(NTFSContext));

    ctx->silent = silent;
    ctx->verbose = verbose;
    strncpy(ctx->base_path, extract_path, sizeof(ctx->base_path) - 1);

    if (!init_directory_cache(&ctx->dir_cache)) {
        return false;
    }

    FILE* fp = FOPEN(path, "rb");
    if (!fp) {
        free_directory_cache(&ctx->dir_cache);
        return false;
    }

    if (FSEEKO(fp, -512, SEEK_END) == 0) {
        char signature[9] = { 0 };
        if (fread(signature, 1, 8, fp) == 8 && memcmp(signature, VHD_COOKIE, 8) == 0) {
            fclose(fp);
            ctx->is_vhd = true;
            if (!vhd_init(&ctx->vhd, path)) {
                free_directory_cache(&ctx->dir_cache);
                return false;
            }
        }
        else {
            rewind(fp);
            ctx->is_vhd = false;
            ctx->raw.fp = fp;
        }
    }

    uint64_t ntfs_offset = 0;
    bool found_ntfs = false;

    if (ctx->is_vhd) {
        uint8_t sector[VHD_SECTOR_SIZE];
        if (ntfs_read(ctx, sector, 0, VHD_SECTOR_SIZE)) {
            if (sector[0x1FE] == 0x55 && sector[0x1FF] == 0xAA) {
                for (int i = 0; i < 4; i++) {
                    const uint8_t* part = sector + 0x1BE + (i * 16);
                    if (part[4] == NTFS_PARTITION_TYPE) {
                        uint32_t start_sector =
                            (uint32_t)part[8] |
                            ((uint32_t)part[9] << 8) |
                            ((uint32_t)part[10] << 16) |
                            ((uint32_t)part[11] << 24);
                        ntfs_offset = (uint64_t)start_sector * VHD_SECTOR_SIZE;

                        if (ntfs_read(ctx, sector, ntfs_offset, VHD_SECTOR_SIZE) &&
                            memcmp(sector + 3, NTFS_SIGNATURE, 8) == 0) {
                            found_ntfs = true;
                            break;
                        }
                    }
                }
            }
        }

        if (!found_ntfs) {
            const uint64_t offsets[] = { 0, 0x100000, 0x200000, 0x400000, 0x800000, 0 };
            for (int i = 0; offsets[i]; i++) {
                if (ntfs_read(ctx, sector, offsets[i], VHD_SECTOR_SIZE) &&
                    memcmp(sector + 3, NTFS_SIGNATURE, 8) == 0) {
                    ntfs_offset = offsets[i];
                    found_ntfs = true;
                    break;
                }
            }
        }
    }
    else {
        uint8_t boot[512];
        if (ntfs_read(ctx, boot, 0, sizeof(boot)) &&
            boot[0] == 0xEB && boot[1] == 0x52 && boot[2] == 0x90 &&
            memcmp(boot + 3, NTFS_SIGNATURE, 8) == 0) {
            found_ntfs = true;
        }
    }

    if (!found_ntfs) {
        ntfs_close(ctx);
        return false;
    }

    if (!ntfs_setup_mft(ctx, ntfs_offset)) {
        ntfs_close(ctx);
        return false;
    }
    return true;
}

bool ntfs_init_stream(NTFSContext* ctx, DecryptStream* stream, const char* extract_path) {
    bool saved_verbose = ctx->verbose;
    bool saved_silent = ctx->silent;
    memset(ctx, 0, sizeof(NTFSContext));
    ctx->verbose = saved_verbose;
    ctx->silent = saved_silent;
    strncpy(ctx->base_path, extract_path, sizeof(ctx->base_path) - 1);
    ctx->stream = stream;

    if (!init_directory_cache(&ctx->dir_cache)) {
        return false;
    }

    uint64_t ntfs_offset = 0;
    bool found_ntfs = false;

    uint8_t boot[512];
    if (ntfs_read(ctx, boot, 0, sizeof(boot)) &&
        boot[0] == 0xEB && boot[1] == 0x52 && boot[2] == 0x90 &&
        memcmp(boot + 3, NTFS_SIGNATURE, 8) == 0) {
        found_ntfs = true;
    }

    if (!found_ntfs) {
        free_directory_cache(&ctx->dir_cache);
        return false;
    }

    if (!ntfs_setup_mft(ctx, ntfs_offset)) {
        free_directory_cache(&ctx->dir_cache);
        return false;
    }
    return true;
}

static uint64_t get_file_data_size(NTFSContext* ctx, const uint8_t* record_data) {
    const MFTRecordHeader* record = (const MFTRecordHeader*)record_data;

    if (memcmp(record->magic, "FILE", 4) != 0 || !(record->flags & MFT_RECORD_IN_USE)) {
        return 0;
    }

    if (record->flags & MFT_RECORD_IS_DIRECTORY) {
        return 0;
    }

    char filename[MAX_FILENAME_LENGTH];
    bool got_filename = false;

    const uint8_t* attr = (const uint8_t*)record + record->attrs_offset;
    while (attr < (const uint8_t*)record + record->bytes_used) {
        const AttributeHeader* header = (const AttributeHeader*)attr;
        if (header->type == 0xFFFFFFFF || header->length == 0) break;

        if (header->type == FILE_NAME_ATTR && !header->non_resident) {
            const FileNameAttribute* fname =
                (const FileNameAttribute*)(attr + header->data.resident.value_offset);
            if (fname->namespace != 2) {
                fs_name_to_utf8(fname->name, fname->name_length, filename, sizeof(filename));
                got_filename = true;
                break;
            }
        }
        attr += header->length;
    }

    if (!got_filename || filename[0] == '$' || !is_safe_path(filename)) {
        return 0;
    }

    attr = (const uint8_t*)record + record->attrs_offset;
    while (attr < (const uint8_t*)record + record->bytes_used) {
        const AttributeHeader* header = (const AttributeHeader*)attr;
        if (header->type == 0xFFFFFFFF || header->length == 0) break;

        if (header->type == DATA_ATTR && header->name_length == 0) {
            if (header->non_resident) {
                return header->data.non_resident.data_size;
            } else {
                return header->data.resident.value_length;
            }
        }
        attr += header->length;
    }

    return 0;
}

static void count_total_bytes(NTFSContext* ctx) {
    ctx->total_bytes = 0;

    uint8_t* record_buffer = malloc(ctx->mft_record_size);
    if (!record_buffer) return;

    uint64_t current_offset = ctx->mft_offset;
    uint64_t total_records = ctx->total_mft_records;

    ctx->raw_file_pos = 0;

    for (uint64_t i = 0; i < total_records; i++) {
        if (!ntfs_read(ctx, record_buffer, current_offset, ctx->mft_record_size)) {
            break;
        }

        if (!apply_mft_fixups(ctx, record_buffer, ctx->mft_record_size)) {
            current_offset += ctx->mft_record_size;
            continue;
        }

        ctx->total_bytes += get_file_data_size(ctx, record_buffer);
        current_offset += ctx->mft_record_size;
    }

    free(record_buffer);
}

int ntfs_detect_vhd_type(NTFSContext* ctx) {
    uint8_t* record_buffer = malloc(ctx->mft_record_size);
    if (!record_buffer) return -1;

    uint64_t current_offset = ctx->mft_offset;
    uint64_t total_records = ctx->total_mft_records;
    int detected_type = -1;

    ctx->raw_file_pos = 0;

    for (uint64_t i = 0; i < total_records && detected_type == -1; i++) {
        if (!ntfs_read(ctx, record_buffer, current_offset, ctx->mft_record_size)) {
            current_offset += ctx->mft_record_size;
            continue;
        }

        if (!apply_mft_fixups(ctx, record_buffer, ctx->mft_record_size)) {
            current_offset += ctx->mft_record_size;
            continue;
        }

        const MFTRecordHeader* record = (const MFTRecordHeader*)record_buffer;
        if (memcmp(record->magic, "FILE", 4) != 0 || !(record->flags & MFT_RECORD_IN_USE)) {
            current_offset += ctx->mft_record_size;
            continue;
        }

        if (record->flags & MFT_RECORD_IS_DIRECTORY) {
            current_offset += ctx->mft_record_size;
            continue;
        }

        char filename[MAX_FILENAME_LENGTH] = {0};
        const uint8_t* attr = (const uint8_t*)record + record->attrs_offset;

        while (attr < (const uint8_t*)record + record->bytes_used) {
            const AttributeHeader* header = (const AttributeHeader*)attr;
            if (header->type == 0xFFFFFFFF || header->length == 0) break;

            if (header->type == FILE_NAME_ATTR && !header->non_resident) {
                const FileNameAttribute* fname =
                    (const FileNameAttribute*)(attr + header->data.resident.value_offset);
                if (fname->namespace != 2) {
                    fs_name_to_utf8(fname->name, fname->name_length, filename, sizeof(filename));
                    break;
                }
            }
            attr += header->length;
        }

        if (strncmp(filename, "internal_", 9) == 0 &&
            strstr(filename, ".vhd") != NULL) {

            attr = (const uint8_t*)record + record->attrs_offset;
            while (attr < (const uint8_t*)record + record->bytes_used) {
                const AttributeHeader* header = (const AttributeHeader*)attr;
                if (header->type == 0xFFFFFFFF || header->length == 0) break;

                if (header->type == DATA_ATTR && header->name_length == 0 && header->non_resident) {
                    uint64_t file_size = header->data.non_resident.data_size;

                    if (file_size >= 512) {
                        DataRun runs[256];
                        const uint8_t* run_list = attr + header->data.non_resident.mapping_pairs_offset;
                        size_t run_list_len = header->length - header->data.non_resident.mapping_pairs_offset;
                        int run_count = parse_data_runs(run_list, run_list_len, runs, 256);

                        uint8_t footer[512];
                        if (read_bytes_from_runs(ctx, runs, run_count, file_size,
                                                  file_size - 512, footer, 512)) {
                            if (memcmp(footer, "conectix", 8) == 0) {
                                detected_type = (footer[60] << 24) | (footer[61] << 16) |
                                               (footer[62] << 8) | footer[63];
                            }
                        }
                    }
                    break;
                }
                attr += header->length;
            }
        }

        current_offset += ctx->mft_record_size;
    }

    free(record_buffer);
    return detected_type;
}

bool ntfs_extract_all(NTFSContext* ctx) {
    if (!create_directories(ctx->base_path)) return false;

    uint8_t* record_buffer = malloc(ctx->mft_record_size);
    if (!record_buffer) return false;

    if (!ctx->is_vhd) {
        count_total_bytes(ctx);
    }
    ctx->extracted_bytes = 0;

    if (ctx->verbose && !ctx->silent && ctx->total_bytes > 0) {
        printf("%llu B\n", (unsigned long long)ctx->total_bytes);
    }

    Progress progress;
    if (!ctx->silent && ctx->total_bytes > 0) {
        progress_init(&progress, ctx->total_bytes);
        ctx->progress = &progress;
    }

    uint64_t current_offset = ctx->mft_offset;
    uint64_t total_records = ctx->total_mft_records;

    ctx->raw_file_pos = 0;

    time_t start_time = time(NULL);
    time_t last_update = start_time;
    uint64_t last_bytes = 0;

    for (uint64_t i = 0; i < total_records; i++) {
        if (!ctx->silent && !ctx->progress && ctx->is_vhd) {
            time_t now = time(NULL);
            if (now != last_update) {
                int64_t elapsed = (int64_t)difftime(now, last_update);
                uint64_t speed_mb = (elapsed > 0) ? (ctx->extracted_bytes - last_bytes) / (uint64_t)elapsed / (1024 * 1024) : 0;
                uint64_t total_mb_w = ctx->extracted_bytes / (1024 * 1024);
                uint64_t total_mb_f = (ctx->extracted_bytes % (1024 * 1024)) * 100 / (1024 * 1024);
                printf("\r%llu.%02llu MB %llu f %llu MB/s    ",
                    (unsigned long long)total_mb_w, (unsigned long long)total_mb_f,
                    (unsigned long long)ctx->files_extracted, (unsigned long long)speed_mb);
                fflush(stdout);
                last_update = now;
                last_bytes = ctx->extracted_bytes;
            }
        }

        if (!ntfs_read(ctx, record_buffer, current_offset, ctx->mft_record_size)) break;

        if (!apply_mft_fixups(ctx, record_buffer, ctx->mft_record_size)) break;

        const MFTRecordHeader* record = (const MFTRecordHeader*)record_buffer;
        if (memcmp(record->magic, "FILE", 4) == 0) {
            process_mft_record(ctx, record_buffer);
        }

        current_offset += ctx->mft_record_size;
    }

    if (!ctx->silent && !ctx->progress && ctx->is_vhd) {
        uint64_t total_mb_w = ctx->extracted_bytes / (1024 * 1024);
        uint64_t total_mb_f = (ctx->extracted_bytes % (1024 * 1024)) * 100 / (1024 * 1024);
        printf("\r%llu.%02llu MB %llu f\n",
            (unsigned long long)total_mb_w, (unsigned long long)total_mb_f,
            (unsigned long long)ctx->files_extracted);
    }

    if (ctx->progress) {
        progress_finish(&progress);
        ctx->progress = NULL;
    }

    if (ctx->pending_vhd_count == 0 && ctx->deferred_dirs) {
        DeferredDirTime* dirs = (DeferredDirTime*)ctx->deferred_dirs;
        for (uint32_t i = ctx->deferred_count; i > 0; i--) {
            set_dir_times(dirs[i - 1].path, dirs[i - 1].mtime, dirs[i - 1].atime);
        }
    }
    free(ctx->deferred_dirs);
    ctx->deferred_dirs = NULL;
    ctx->deferred_count = 0;
    ctx->deferred_capacity = 0;

    free(record_buffer);
    return true;
}

bool ntfs_extract_pending_vhds(NTFSContext* ctx, bool silent, bool verbose, bool* is_orphan) {
    if (is_orphan) *is_orphan = false;
    if (ctx->pending_vhd_count == 0) return true;

    int highest_vhd = -1;
    PendingVHD* highest = NULL;
    for (int i = 0; i < ctx->pending_vhd_count; i++) {
        if (ctx->pending_vhds[i].vhd_number > highest_vhd) {
            highest_vhd = ctx->pending_vhds[i].vhd_number;
            highest = &ctx->pending_vhds[i];
        }
    }

    if (!highest) return true;

    VHDContext vhd_ctx = {0};
    if (!vhd_init_from_runs(&vhd_ctx, ctx, highest->runs, highest->run_count,
        highest->file_size, ctx->base_path)) {
        if (is_orphan) *is_orphan = true;
        return true;
    }

    if (vhd_ctx.footer.disk_type == VHD_TYPE_DIFFERENCING) {
        if (is_orphan) *is_orphan = true;
        vhd_close(&vhd_ctx);
        return true;
    }

    NTFSContext inner_ctx = {0};
    inner_ctx.silent = silent;
    inner_ctx.verbose = verbose;
    inner_ctx.is_vhd = true;
    inner_ctx.vhd = vhd_ctx;
    strncpy(inner_ctx.base_path, ctx->base_path, sizeof(inner_ctx.base_path) - 1);

    if (!init_directory_cache(&inner_ctx.dir_cache)) {
        vhd_close(&inner_ctx.vhd);
        return false;
    }

    uint8_t boot[512];
    bool read_ok = vhd_read(&inner_ctx.vhd, boot, 0, sizeof(boot));

    uint64_t ntfs_offset = 0;
    bool found_ntfs = false;

    if (read_ok && boot[0] == 0xEB && boot[1] == 0x52 && boot[2] == 0x90 &&
        memcmp(boot + 3, NTFS_SIGNATURE, 8) == 0) {
        found_ntfs = true;
    }

    if (!found_ntfs && read_ok && boot[510] == 0x55 && boot[511] == 0xAA) {
        for (int i = 0; i < 4; i++) {
            uint8_t* entry = boot + 446 + (i * 16);
            uint8_t ptype = entry[4];
            uint32_t lba_start = entry[8] | (entry[9] << 8) | (entry[10] << 16) | (entry[11] << 24);

            if (ptype == NTFS_PARTITION_TYPE && lba_start > 0) {
                ntfs_offset = (uint64_t)lba_start * 512;
                if (vhd_read(&inner_ctx.vhd, boot, ntfs_offset, sizeof(boot)) &&
                    boot[0] == 0xEB && boot[1] == 0x52 && boot[2] == 0x90 &&
                    memcmp(boot + 3, NTFS_SIGNATURE, 8) == 0) {
                    found_ntfs = true;
                    break;
                }
            }
        }
    }

    if (!found_ntfs) {
        free_directory_cache(&inner_ctx.dir_cache);
        vhd_close(&inner_ctx.vhd);
        return false;
    }

    if (!ntfs_setup_mft(&inner_ctx, ntfs_offset)) {
        free_directory_cache(&inner_ctx.dir_cache);
        vhd_close(&inner_ctx.vhd);
        return false;
    }

    if (verbose && !silent) {
        printf("  MFT=%llu clust=%u\n",
            (unsigned long long)inner_ctx.total_mft_records, inner_ctx.bytes_per_cluster);
    }

    bool success = ntfs_extract_all(&inner_ctx);

    ctx->files_extracted += inner_ctx.files_extracted;
    ctx->extracted_bytes += inner_ctx.extracted_bytes;

    ntfs_close(&inner_ctx);

    DeferredDirTime* dirs = (DeferredDirTime*)ctx->deferred_dirs;
    for (uint32_t i = ctx->deferred_count; i > 0; i--) {
        DeferredDirTime* d = &dirs[i - 1];
        set_dir_times(d->path, d->mtime, d->atime);
    }
    free(ctx->deferred_dirs);
    ctx->deferred_dirs = NULL;
    ctx->deferred_count = 0;
    ctx->deferred_capacity = 0;

    return success;
}

int ntfs_get_pending_opt_count(NTFSContext* ctx) {
    return ctx ? ctx->pending_opt_count : 0;
}

const PendingOpt* ntfs_get_pending_opt(NTFSContext* ctx, int index) {
    if (!ctx || index < 0 || index >= ctx->pending_opt_count) return NULL;
    return &ctx->pending_opts[index];
}

void ntfs_close(NTFSContext* ctx) {
    if (ctx->stream) {
    }
    else if (ctx->is_vhd) {
        vhd_close(&ctx->vhd);
    }
    else {
        if (ctx->raw.fp) {
            fclose(ctx->raw.fp);
        }
    }
    free(ctx->file_buffer);
    free_directory_cache(&ctx->dir_cache);
    free(ctx->lookup_buffer);
    memset(ctx, 0, sizeof(NTFSContext));
}
