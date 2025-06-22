#include "ntfs.h"
#include <time.h>
#include <locale.h>
#define BUFFER_SIZE 65536

static uint16_t swap16(uint16_t value) {
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

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

static bool create_directories(const char* path) {
    char* tmp = _strdup(path);
    if (!tmp) return false;

    bool success = true;
    char* p = tmp;

    if (strlen(p) > 2) {
        if (p[1] == ':') p += 2;
        if (*p == '\\' || *p == '/') p++;
    }

    while ((p = strchr(p, PATH_SEPARATOR[0])) != NULL) {
        *p = '\0';
        if (strlen(tmp) > 0) {
            if (MKDIR(tmp) != 0 && errno != EEXIST) {
                success = false;
                break;
            }
        }
        *p = PATH_SEPARATOR[0];
        p++;
    }

    if (success && strlen(tmp) > 0) {
        if (MKDIR(tmp) != 0 && errno != EEXIST) {
            success = false;
        }
    }

    free(tmp);
    return success;
}

static void convert_name_to_ascii(const uint16_t* utf16_name, int name_length, char* ascii_name) {
    // just convert it
    _locale_t locale = _create_locale(LC_ALL, "");
    int real_name_length = min(name_length, MAX_FILENAME_LENGTH - 1);
    _wcstombs_l(ascii_name, utf16_name, real_name_length, locale);
    ascii_name[real_name_length] = '\0';
}

static bool ntfs_read(NTFSContext* ctx, void* buffer, uint64_t offset, size_t size) {
    if (ctx->is_vhd) {
        return vhd_read(&ctx->vhd, buffer, offset, size);
    }
    if (fseeko(ctx->raw.fp, offset, SEEK_SET) != 0) {
        return false;
    }
    return fread(buffer, 1, size, ctx->raw.fp) == size;
}

static bool read_file_info(NTFSContext* ctx, uint64_t ref_number, FileInfo* info) {
    memset(info, 0, sizeof(FileInfo));

    uint64_t mft_offset = ctx->mft_offset + (ref_number * ctx->mft_record_size);
    uint8_t* record_buffer = malloc(ctx->mft_record_size);
    if (!record_buffer) {
        return false;
    }

    bool success = false;
    if (ntfs_read(ctx, record_buffer, mft_offset, ctx->mft_record_size)) {
        const MFTRecordHeader* record = (const MFTRecordHeader*)record_buffer;

        if (memcmp(record->magic, "FILE", 4) == 0 && (record->flags & MFT_RECORD_IN_USE)) {
            info->is_directory = (record->flags & MFT_RECORD_IS_DIRECTORY) != 0;

            const uint8_t* attr = (const uint8_t*)record + record->attrs_offset;
            while (attr < (const uint8_t*)record + record->bytes_used) {
                const AttributeHeader* header = (const AttributeHeader*)attr;

                if (header->type == 0xFFFFFFFF || header->length == 0) {
                    break;
                }

                if (header->type == FILE_NAME_ATTR && !header->non_resident) {
                    const FileNameAttribute* fname =
                        (const FileNameAttribute*)(attr + header->data.resident.value_offset);

                    if (fname->namespace != 2) {
                        convert_name_to_ascii(fname->name, fname->name_length, info->name);
                        info->parent_ref = fname->parent_directory & 0xFFFFFFFFFFFF;
                        info->valid = true;
                        success = true;
                        break;
                    }
                }

                attr += header->length;
            }
        }
    }

    free(record_buffer);
    return success;
}

static bool init_directory_cache(DirectoryCache* cache) {
    cache->capacity = 1024;
    cache->count = 0;
    cache->directories = malloc(cache->capacity * sizeof(DirectoryInfo));
    if (!cache->directories) return false;

    cache->directories[0].ref_number = 5;
    cache->directories[0].path[0] = '\0';
    cache->count = 1;
    return true;
}

static void free_directory_cache(DirectoryCache* cache) {
    free(cache->directories);
    cache->directories = NULL;
    cache->capacity = 0;
    cache->count = 0;
}

static bool add_directory_to_cache(DirectoryCache* cache, uint64_t ref_number, const char* path) {
    for (size_t i = 0; i < cache->count; i++) {
        if (cache->directories[i].ref_number == ref_number) {
            strncpy(cache->directories[i].path, path, MAX_PATH_LENGTH - 1);
            cache->directories[i].path[MAX_PATH_LENGTH - 1] = '\0';
            return true;
        }
    }

    if (cache->count >= cache->capacity) {
        size_t new_capacity = cache->capacity * 2;
        DirectoryInfo* new_dirs = realloc(cache->directories,
            new_capacity * sizeof(DirectoryInfo));
        if (!new_dirs) return false;
        cache->directories = new_dirs;
        cache->capacity = new_capacity;
    }

    if (cache->count < cache->capacity) {
        cache->directories[cache->count].ref_number = ref_number;
        strncpy(cache->directories[cache->count].path, path, MAX_PATH_LENGTH - 1);
        cache->directories[cache->count].path[MAX_PATH_LENGTH - 1] = '\0';
        cache->count++;
        return true;
    }

    return false;
}

static const char* get_cached_path(DirectoryCache* cache, uint64_t ref_number) {
    for (size_t i = 0; i < cache->count; i++) {
        if (cache->directories[i].ref_number == ref_number) {
            return cache->directories[i].path;
        }
    }
    return NULL;
}

static bool build_path_recursively(NTFSContext* ctx, uint64_t ref_number, char* buffer, size_t buffer_size) {
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
    if (!build_path_recursively(ctx, info.parent_ref, parent_path, sizeof(parent_path))) {
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

static void get_full_path(const NTFSContext* ctx, uint64_t parent_ref, const char* name,
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
    uint8_t* temp_buffer = malloc(BUFFER_SIZE);
    if (!temp_buffer) return false;

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

            if (!ntfs_read(ctx, temp_buffer, cluster_offset, to_read)) {
                success = false;
                break;
            }

            if (fwrite(temp_buffer, 1, to_read, out_file) != to_read) {
                success = false;
                break;
            }

            cluster_offset += to_read;
            remaining -= to_read;
            total_written += to_read;
        }
    }

    free(temp_buffer);
    return success;
}

static int parse_data_runs(const uint8_t* run_list, DataRun* runs, int max_runs) {
    int count = 0;
    uint64_t offset_base = 0;
    const uint8_t* p = run_list;

    while (*p != 0 && count < max_runs) {
        uint8_t header = *p++;
        int length_size = header & 0xF;
        int offset_size = header >> 4;

        if (length_size == 0) break;

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

static bool extract_file(NTFSContext* ctx, const MFTRecordHeader* record,
    const char* full_path) {
    char parent_path[MAX_PATH_LENGTH];
    strncpy(parent_path, full_path, sizeof(parent_path) - 1);
    parent_path[sizeof(parent_path) - 1] = '\0';

    char* last_separator = strrchr(parent_path, PATH_SEPARATOR[0]);
    if (last_separator) {
        *last_separator = '\0';
        create_directories(parent_path);
    }

    FILE* out_file = fopen(full_path, "wb");
    if (!out_file) {
        printf("Failed to create file: %s\n", full_path);
        return false;
    }

    bool success = false;
    const uint8_t* attr = (const uint8_t*)record + record->attrs_offset;

    while (attr < (const uint8_t*)record + record->bytes_used) {
        const AttributeHeader* header = (const AttributeHeader*)attr;

        if (header->type == 0xFFFFFFFF || header->length == 0) {
            break;
        }

        if (header->type == DATA_ATTR && header->name_length == 0) {
            if (header->non_resident) {
                DataRun runs[256];
                const uint8_t* run_list = attr + header->data.non_resident.mapping_pairs_offset;
                int run_count = parse_data_runs(run_list, runs, 256);

                success = extract_data_from_runs(ctx, runs, run_count,
                    header->data.non_resident.data_size,
                    out_file);
            }
            else {
                const uint8_t* data = attr + header->data.resident.value_offset;
                success = (fwrite(data, 1, header->data.resident.value_length, out_file) ==
                    header->data.resident.value_length);
            }
            break;
        }

        attr += header->length;
    }

    fclose(out_file);
    if (!success) {
        remove(full_path);
    }
    return success;
}

static bool process_mft_record(NTFSContext* ctx, const uint8_t* record_data) {
    const MFTRecordHeader* record = (const MFTRecordHeader*)record_data;

    if (memcmp(record->magic, "FILE", 4) != 0 || !(record->flags & MFT_RECORD_IN_USE)) {
        return true;
    }

    char filename[MAX_FILENAME_LENGTH];
    uint64_t parent_ref = 0;
    bool got_filename = false;
    bool is_directory = (record->flags & MFT_RECORD_IS_DIRECTORY) != 0;
    uint64_t record_num = record->record_number & 0xFFFFFFFFFFFF;

    const uint8_t* attr = (const uint8_t*)record + record->attrs_offset;
    while (attr < (const uint8_t*)record + record->bytes_used) {
        const AttributeHeader* header = (const AttributeHeader*)attr;

        if (header->type == 0xFFFFFFFF || header->length == 0) {
            break;
        }

        if (header->type == FILE_NAME_ATTR && !header->non_resident) {
            const FileNameAttribute* fname =
                (const FileNameAttribute*)(attr + header->data.resident.value_offset);

            if (fname->namespace != 2) {
                convert_name_to_ascii(fname->name, fname->name_length, filename);
                parent_ref = fname->parent_directory & 0xFFFFFFFFFFFF;
                got_filename = true;
                break;
            }
        }

        attr += header->length;
    }

    if (!got_filename || filename[0] == '$') {
        return true;
    }

    char full_path[MAX_PATH_LENGTH];
    get_full_path(ctx, parent_ref, filename, full_path, sizeof(full_path));

    if (is_directory) {
        if (!create_directories(full_path)) {
            printf("Failed to create directory: %s\n", full_path);
            return false;
        }

        const char* relative_path = full_path + strlen(ctx->base_path);
        while (*relative_path == PATH_SEPARATOR[0]) relative_path++;

        if (!add_directory_to_cache(&ctx->dir_cache, record_num, relative_path)) {
            printf("Failed to cache directory: %s\n", filename);
            return false;
        }
        return true;
    }

    return extract_file(ctx, record, full_path);
}

static bool vhd_read(VHDContext* ctx, void* buffer, uint64_t offset, size_t size) {
    if (ctx->footer.disk_type == VHD_TYPE_FIXED) {
        if (fseeko(ctx->fp, offset, SEEK_SET) != 0) {
            return false;
        }
        return fread(buffer, 1, size, ctx->fp) == size;
    }
    else if (ctx->footer.disk_type == VHD_TYPE_DYNAMIC) {
        uint8_t* buf = (uint8_t*)buffer;
        uint64_t block_size = ctx->dyn_header.block_size;

        while (size > 0) {
            uint32_t block_idx = (uint32_t)(offset / block_size);
            uint32_t block_offset = (uint32_t)(offset % block_size);

            if (block_idx >= ctx->dyn_header.max_bat_entries) {
                return false;
            }

            uint32_t bat_entry = ctx->bat[block_idx];
            if (bat_entry == VHD_BAT_ENTRY_RESERVED) {
                size_t chunk = (size < (block_size - block_offset)) ?
                    size : (size_t)(block_size - block_offset);
                memset(buf, 0, chunk);
                buf += chunk;
                offset += chunk;
                size -= chunk;
            }
            else {
                uint64_t sector_offset = ((uint64_t)bat_entry) * VHD_SECTOR_SIZE;

                if (fseeko(ctx->fp, sector_offset, SEEK_SET) != 0) {
                    return false;
                }

                if (fread(ctx->sector_bitmap, 1, ctx->sector_bitmap_size, ctx->fp)
                    != ctx->sector_bitmap_size) {
                    return false;
                }

                if (fread(ctx->block_buffer, 1, block_size, ctx->fp) != block_size) {
                    return false;
                }

                size_t chunk = (size < (block_size - block_offset)) ?
                    size : (size_t)(block_size - block_offset);
                memcpy(buf, ctx->block_buffer + block_offset, chunk);
                buf += chunk;
                offset += chunk;
                size -= chunk;
            }
        }
        return true;
    }
    return false;
}

static bool vhd_init(VHDContext* ctx, const char* filename) {
    memset(ctx, 0, sizeof(VHDContext));

    ctx->fp = fopen(filename, "rb");
    if (!ctx->fp) {
        printf("Failed to open file: %s\n", filename);
        return false;
    }

    if (fseeko(ctx->fp, -((int64_t)VHD_FOOTER_SIZE), SEEK_END) != 0) {
        printf("Failed to seek to VHD footer\n");
        fclose(ctx->fp);
        return false;
    }

    if (fread(&ctx->footer, 1, sizeof(VHDFooter), ctx->fp) != sizeof(VHDFooter)) {
        printf("Failed to read VHD footer\n");
        fclose(ctx->fp);
        return false;
    }

    if (memcmp(ctx->footer.cookie, VHD_COOKIE, strlen(VHD_COOKIE)) != 0) {
        printf("Invalid VHD signature\n");
        fclose(ctx->fp);
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
    ctx->footer.cylinder = swap16(ctx->footer.cylinder);
    ctx->footer.disk_type = swap32(ctx->footer.disk_type);
    ctx->footer.checksum = swap32(ctx->footer.checksum);

    if (ctx->footer.disk_type == VHD_TYPE_DYNAMIC) {
        if (fseeko(ctx->fp, ctx->footer.data_offset, SEEK_SET) != 0) {
            printf("Failed to seek to dynamic header\n");
            fclose(ctx->fp);
            return false;
        }

        if (fread(&ctx->dyn_header, 1, sizeof(VHDDynamicHeader), ctx->fp) != sizeof(VHDDynamicHeader)) {
            printf("Failed to read dynamic header\n");
            fclose(ctx->fp);
            return false;
        }

        if (memcmp(ctx->dyn_header.cookie, VHD_DYNAMIC_COOKIE, strlen(VHD_DYNAMIC_COOKIE)) != 0) {
            printf("Invalid dynamic disk header signature\n");
            fclose(ctx->fp);
            return false;
        }

        ctx->dyn_header.data_offset = swap64(ctx->dyn_header.data_offset);
        ctx->dyn_header.bat_offset = swap64(ctx->dyn_header.bat_offset);
        ctx->dyn_header.head_vers = swap32(ctx->dyn_header.head_vers);
        ctx->dyn_header.max_bat_entries = swap32(ctx->dyn_header.max_bat_entries);
        ctx->dyn_header.block_size = swap32(ctx->dyn_header.block_size);

        size_t bat_size = (size_t)ctx->dyn_header.max_bat_entries * sizeof(uint32_t);

        if (bat_size == 0 || bat_size > (1ULL << 30)) {
            printf("Invalid BAT size\n");
            fclose(ctx->fp);
            return false;
        }

        ctx->bat = malloc(bat_size);
        if (!ctx->bat) {
            printf("Failed to allocate BAT memory\n");
            fclose(ctx->fp);
            return false;
        }

        if (fseeko(ctx->fp, ctx->dyn_header.bat_offset, SEEK_SET) != 0) {
            printf("Failed to seek to BAT\n");
            free(ctx->bat);
            fclose(ctx->fp);
            return false;
        }

        if (fread(ctx->bat, 1, bat_size, ctx->fp) != bat_size) {
            printf("Failed to read BAT\n");
            free(ctx->bat);
            fclose(ctx->fp);
            return false;
        }

        for (uint32_t i = 0; i < ctx->dyn_header.max_bat_entries; i++) {
            ctx->bat[i] = swap32(ctx->bat[i]);
        }

        ctx->sector_bitmap_size = (ctx->dyn_header.block_size / VHD_SECTOR_SIZE + 7) / 8;
        ctx->sector_bitmap = malloc(ctx->sector_bitmap_size);
        ctx->block_buffer = malloc(ctx->dyn_header.block_size);

        if (!ctx->sector_bitmap || !ctx->block_buffer) {
            printf("Failed to allocate dynamic disk buffers\n");
            free(ctx->bat);
            free(ctx->sector_bitmap);
            free(ctx->block_buffer);
            fclose(ctx->fp);
            return false;
        }
    }

    return true;
}

bool ntfs_init(NTFSContext* ctx, const char* path, const char* extract_path) {
    memset(ctx, 0, sizeof(NTFSContext));
    strncpy(ctx->base_path, extract_path, sizeof(ctx->base_path) - 1);

    if (!init_directory_cache(&ctx->dir_cache)) {
        return false;
    }

    FILE* fp = fopen(path, "rb");
    if (!fp) return false;

    if (fseeko(fp, -512, SEEK_END) == 0) {
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
        printf("No NTFS filesystem found\n");
        ntfs_close(ctx);
        return false;
    }

    ctx->data_start_offset = ntfs_offset;

    if (!ntfs_read(ctx, &ctx->boot, ntfs_offset, sizeof(NTFSBootSector))) {
        printf("Failed to read NTFS boot sector\n");
        ntfs_close(ctx);
        return false;
    }

    ctx->bytes_per_cluster = (uint32_t)ctx->boot.bytes_per_sector * ctx->boot.sectors_per_cluster;
    ctx->mft_offset = ntfs_offset + (ctx->boot.mft_cluster_number * ctx->bytes_per_cluster);

    if (ctx->boot.clusters_per_mft_record > 0) {
        ctx->mft_record_size = ctx->boot.clusters_per_mft_record * ctx->bytes_per_cluster;
    }
    else {
        ctx->mft_record_size = 1U << (-ctx->boot.clusters_per_mft_record);
    }

    uint8_t* mft_record = malloc(ctx->mft_record_size);
    if (!mft_record) {
        printf("Failed to allocate memory for MFT record\n");
        ntfs_close(ctx);
        return false;
    }

    if (!ntfs_read(ctx, mft_record, ctx->mft_offset, ctx->mft_record_size)) {
        printf("Failed to read MFT record 0\n");
        free(mft_record);
        ntfs_close(ctx);
        return false;
    }

    const MFTRecordHeader* record = (const MFTRecordHeader*)mft_record;
    if (memcmp(record->magic, "FILE", 4) != 0) {
        printf("Invalid MFT record signature\n");
        free(mft_record);
        ntfs_close(ctx);
        return false;
    }

    const uint8_t* attr = mft_record + record->attrs_offset;
    while (attr < mft_record + record->bytes_used) {
        const AttributeHeader* header = (const AttributeHeader*)attr;
        if (header->type == 0xFFFFFFFF || header->length == 0) break;

        if (header->type == DATA_ATTR && header->name_length == 0) {
            if (header->non_resident) {
                uint64_t mft_data_size = header->data.non_resident.data_size;
                ctx->mft_data_size = mft_data_size;
                ctx->total_mft_records = mft_data_size / ctx->mft_record_size;
            }
            break;
        }
        attr += header->length;
    }

    free(mft_record);
    return true;
}

bool ntfs_extract_all(NTFSContext* ctx) {
    if (!create_directories(ctx->base_path)) {
        printf("Failed to create output directory\n");
        return false;
    }

    uint8_t* record_buffer = malloc(ctx->mft_record_size);
    if (!record_buffer) {
        printf("Failed to allocate MFT record buffer\n");
        return false;
    }

    printf("Extraction in progress...\n");
    uint64_t current_offset = ctx->mft_offset;
    uint64_t total_records = ctx->total_mft_records;
    uint64_t processed_records = 0;
    uint64_t extracted_records = 0;

    time_t last_update_time = time(NULL);
    int last_percentage = -1;

    // Process MFT records
    for (uint64_t i = 0; i < total_records; i++) {
        if (!ntfs_read(ctx, record_buffer, current_offset, ctx->mft_record_size)) {
            printf("Failed to read MFT record at offset 0x%llX\n",
                (unsigned long long)current_offset);
            break;
        }

        const MFTRecordHeader* record = (const MFTRecordHeader*)record_buffer;
        if (memcmp(record->magic, "FILE", 4) == 0) {
            processed_records++;
            if (process_mft_record(ctx, record_buffer)) {
                extracted_records++;
            }
        }

        current_offset += ctx->mft_record_size;

        time_t current_time = time(NULL);
        if (current_time != last_update_time) {
            int percentage = (int)((i + 1) * 100 / total_records);
            if (percentage != last_percentage) {
                printf("\rProgress: %d%%", percentage);
                fflush(stdout);
                last_percentage = percentage;
            }
            last_update_time = current_time;
        }
    }

    printf("\rProgress: 100%%\n");

    printf("Extraction completed.\n");

    free(record_buffer);
    return true;
}

void ntfs_close(NTFSContext* ctx) {
    if (ctx->is_vhd) {
        if (ctx->vhd.fp) {
            fclose(ctx->vhd.fp);
            free(ctx->vhd.bat);
            free(ctx->vhd.sector_bitmap);
            free(ctx->vhd.block_buffer);
        }
    }
    else {
        if (ctx->raw.fp) {
            fclose(ctx->raw.fp);
        }
    }
    free_directory_cache(&ctx->dir_cache);
    memset(ctx, 0, sizeof(NTFSContext));
}