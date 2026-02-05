#include "exfat.h"
#include "progress.h"

static void count_directory_size(ExfatContext* ctx, uint32_t start_cluster);

static uint64_t get_cluster_offset(ExfatContext* ctx, uint32_t cluster) {
    return ctx->cluster_heap_offset_bytes + ((uint64_t)(cluster - 2) * ctx->bytes_per_cluster);
}

static bool exfat_read(ExfatContext* ctx, void* buffer, uint64_t offset, size_t size) {
    if (ctx->stream) {
        return stream_read(ctx->stream, buffer, offset, size);
    }
    if (FSEEKO(ctx->fp, offset, SEEK_SET) != 0) {
        return false;
    }
    return fread(buffer, 1, size, ctx->fp) == size;
}

static bool read_cluster(ExfatContext* ctx, uint32_t cluster, void* buffer) {
    uint32_t offset = get_cluster_offset(ctx, cluster);
    return exfat_read(ctx, buffer, offset, ctx->bytes_per_cluster);
}

static uint32_t get_next_cluster(ExfatContext* ctx, uint32_t cluster) {
    uint32_t max_cluster = ctx->fat_length_bytes / sizeof(uint32_t);
    if (cluster >= max_cluster) {
        return 0;
    }
    uint32_t next = ctx->fat[cluster];
    if (next >= 0xFFFFFFF8) {
        return 0;
    }
    if (next == 0)
    {
        return cluster + 1;
    }
    if (next >= max_cluster) {
        return 0;
    }
    return next;
}

static bool combine_path(char* dest, size_t dest_size, const char* dir, const char* name) {
    if (!dest || dest_size == 0 || !dir || !name) {
        return false;
    }

    if (!is_safe_path(name)) {
        return false;
    }

    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    size_t sep_len = (dir_len > 0 && dir[dir_len - 1] != '/' && dir[dir_len - 1] != '\\') ? 1 : 0;

    if (dir_len + sep_len + name_len + 1 > dest_size) {
        return false;
    }

    STRCPY_S(dest, dest_size, dir);
    if (sep_len) {
        STRCAT_S(dest, dest_size, PATH_SEPARATOR);
    }
    STRCAT_S(dest, dest_size, name);
    return true;
}

static bool extract_file(ExfatContext* ctx, ExfatFileInfo* file, const char* output_path) {
    FILE* out = FOPEN(output_path, "wb");
    if (!out) {
        return false;
    }
    setvbuf(out, NULL, _IOFBF, ctx->bytes_per_cluster);

    uint32_t current_cluster = file->first_cluster;
    uint64_t remaining = file->data_length;

    bool success = true;
    while (remaining > 0 && current_cluster != 0 && success) {
        if (!read_cluster(ctx, current_cluster, ctx->io_buf)) {
            success = false;
            break;
        }

        size_t write_size = (remaining > ctx->bytes_per_cluster) ? ctx->bytes_per_cluster : (size_t)remaining;
        if (fwrite(ctx->io_buf, 1, write_size, out) != write_size) {
            success = false;
            break;
        }

        remaining -= write_size;

        if (file->no_fat_chain) {
            current_cluster++;
        } else {
            current_cluster = get_next_cluster(ctx, current_cluster);
        }

        ctx->extracted_bytes += write_size;
        if (ctx->progress) {
            progress_update((Progress*)ctx->progress, ctx->extracted_bytes);
        }
    }

    fclose(out);

    if (success) {
        ctx->files_extracted++;
        if (file->modify_timestamp != 0) {
            uint64_t mtime = exfat_timestamp_to_ntfs(file->modify_timestamp, file->modify_10ms, file->modify_utc_offset);
            uint64_t atime = exfat_timestamp_to_ntfs(file->access_timestamp, 0, file->access_utc_offset);
            set_file_times(output_path, mtime, atime);
        }
    }

    return success;
}

#define EXFAT_MAX_RECURSION_DEPTH 128

static bool process_directory_recursive(ExfatContext* ctx, uint32_t start_cluster, const char* output_dir, int depth) {
    if (depth > EXFAT_MAX_RECURSION_DEPTH) {
        fprintf(stderr, "depth\n");
        return true;
    }

    uint32_t current_cluster = start_cluster;
    bool finished = false;

    while (!finished && current_cluster != 0) {
        if (!read_cluster(ctx, current_cluster, ctx->cluster_buf)) {
            return false;
        }

        uint32_t entries_per_cluster = ctx->bytes_per_cluster / EXFAT_ENTRY_SIZE;
        uint32_t entry_offset = 0;
        for (uint32_t i = 0; i < entries_per_cluster; ) {
            uint8_t* entry_ptr = ctx->cluster_buf + entry_offset;
            uint8_t entry_type = *entry_ptr;
            if (entry_type == EXFAT_ENTRY_EOD) {
                finished = true;
                break;
            }

            if (entry_type == EXFAT_ENTRY_FILE) {
                ExfatFileEntry* file_entry = (ExfatFileEntry*)entry_ptr;
                ExfatStreamEntry* stream_entry = (ExfatStreamEntry*)(entry_ptr + EXFAT_ENTRY_SIZE);
                if (stream_entry->entry_type != EXFAT_ENTRY_STREAM) {
                    i++;
                    entry_offset += EXFAT_ENTRY_SIZE;
                    continue;
                }
                int total_name_chars = stream_entry->name_length;
                int num_name_entries = (total_name_chars + 14) / 15;

                char full_name[MAX_FILENAME_LENGTH];
                uint16_t full_name_unicode[MAX_FILENAME_LENGTH];
                int pos = 0;
                uint8_t* name_entry_ptr = entry_ptr + EXFAT_ENTRY_SIZE * 2;
                for (int k = 0; k < num_name_entries; k++) {
                    ExfatFileNameEntry* name_entry = (ExfatFileNameEntry*)(name_entry_ptr + k * EXFAT_ENTRY_SIZE);
                    int chars_in_this_entry = (total_name_chars - k * 15 < 15) ? (total_name_chars - k * 15) : 15;
                    for (int j = 0; j < chars_in_this_entry; j++) {
                        if (pos < MAX_FILENAME_LENGTH - 1) {
                            full_name_unicode[pos++] = name_entry->file_name[j];
                        }
                    }
                }
                full_name_unicode[pos] = 0;

                fs_name_to_utf8(full_name_unicode, pos, full_name, sizeof(full_name));

                ExfatFileInfo file_info;
                memset(&file_info, 0, sizeof(file_info));
                strncpy(file_info.name, full_name, MAX_PATH_LENGTH - 1);
                file_info.name[MAX_PATH_LENGTH - 1] = '\0';
                file_info.first_cluster = stream_entry->first_cluster;
                file_info.data_length = stream_entry->data_length;
                file_info.is_directory = ((file_entry->file_attributes & 0x10) != 0);
                file_info.no_fat_chain = ((stream_entry->flags & 0x02) != 0);
                file_info.modify_timestamp = file_entry->last_modified_timestamp;
                file_info.access_timestamp = file_entry->last_access_timestamp;
                file_info.modify_10ms = file_entry->last_modified_10ms;
                file_info.modify_utc_offset = (int8_t)file_entry->last_modified_utc_offset;
                file_info.access_utc_offset = (int8_t)file_entry->last_access_utc_offset;

                char full_path[MAX_PATH_LENGTH];
                if (!combine_path(full_path, sizeof(full_path), output_dir, file_info.name)) {
                    fprintf(stderr, "path:%s\n", file_info.name);
                    continue;
                }

                int total_entries = 2 + num_name_entries;
                i += total_entries;
                entry_offset += EXFAT_ENTRY_SIZE * total_entries;

                if (file_info.is_directory) {
                    if (create_directories(full_path)) {
                        process_directory_recursive(ctx, file_info.first_cluster, full_path, depth + 1);
                        if (file_info.modify_timestamp != 0) {
                            if (ctx->deferred_count >= ctx->deferred_capacity) {
                                uint32_t new_cap = ctx->deferred_capacity ? ctx->deferred_capacity * 2 : 256;
                                DeferredDirTime* new_buf = realloc(ctx->deferred_dirs, new_cap * sizeof(DeferredDirTime));
                                if (new_buf) {
                                    ctx->deferred_dirs = new_buf;
                                    ctx->deferred_capacity = new_cap;
                                }
                            }
                            if (ctx->deferred_count < ctx->deferred_capacity) {
                                DeferredDirTime* d = &ctx->deferred_dirs[ctx->deferred_count++];
                                STRCPY_S(d->path, sizeof(d->path), full_path);
                                d->mtime = exfat_timestamp_to_ntfs(file_info.modify_timestamp, file_info.modify_10ms, file_info.modify_utc_offset);
                                d->atime = exfat_timestamp_to_ntfs(file_info.access_timestamp, 0, file_info.access_utc_offset);
                            }
                        }
                        if (!read_cluster(ctx, current_cluster, ctx->cluster_buf)) {
                            return false;
                        }
                    }
                }
                else {
                    extract_file(ctx, &file_info, full_path);
                }
                continue;
            }
            else {
                i++;
                entry_offset += EXFAT_ENTRY_SIZE;
            }
        }

        if (!finished) {
            current_cluster = get_next_cluster(ctx, current_cluster);
        }
    }

    return true;
}

static bool process_directory(ExfatContext* ctx, uint32_t start_cluster, const char* output_dir) {
    return process_directory_recursive(ctx, start_cluster, output_dir, 0);
}

static bool exfat_setup_fields(ExfatContext* ctx) {
    ctx->bytes_per_sector = (1 << ctx->boot_sector.bytes_per_sector_shift);
    ctx->bytes_per_cluster = ctx->bytes_per_sector * (1 << ctx->boot_sector.sectors_per_cluster_shift);
    ctx->cluster_heap_offset_bytes = ctx->boot_sector.cluster_heap_offset * ctx->bytes_per_sector;
    ctx->fat_offset_bytes = ctx->boot_sector.fat_offset * ctx->bytes_per_sector;
    ctx->fat_length_bytes = ctx->boot_sector.fat_length * ctx->bytes_per_sector;

    ctx->fat = malloc(ctx->fat_length_bytes);
    ctx->cluster_buf = malloc(ctx->bytes_per_cluster);
    ctx->io_buf = malloc(ctx->bytes_per_cluster);
    if (!ctx->fat || !ctx->cluster_buf || !ctx->io_buf) {
        free(ctx->fat);
        free(ctx->cluster_buf);
        free(ctx->io_buf);
        return false;
    }
    return true;
}

bool exfat_init(ExfatContext* ctx, const char* filename) {
    memset(ctx, 0, sizeof(ExfatContext));

    ctx->fp = FOPEN(filename, "rb");
    if (!ctx->fp) return false;

    if (fread(&ctx->boot_sector, sizeof(ExfatBootSector), 1, ctx->fp) != 1) {
        fclose(ctx->fp);
        return false;
    }

    if (!exfat_setup_fields(ctx)) {
        fclose(ctx->fp);
        return false;
    }

    if (fseek(ctx->fp, (long)ctx->fat_offset_bytes, SEEK_SET) != 0 ||
        fread(ctx->fat, 1, ctx->fat_length_bytes, ctx->fp) != ctx->fat_length_bytes) {
        exfat_close(ctx);
        return false;
    }

    return true;
}

bool exfat_init_stream(ExfatContext* ctx, DecryptStream* stream) {
    memset(ctx, 0, sizeof(ExfatContext));
    ctx->stream = stream;

    if (!exfat_read(ctx, &ctx->boot_sector, 0, sizeof(ExfatBootSector))) {
        return false;
    }

    if (!exfat_setup_fields(ctx)) return false;

    if (!exfat_read(ctx, ctx->fat, ctx->fat_offset_bytes, ctx->fat_length_bytes)) {
        exfat_close(ctx);
        return false;
    }

    return true;
}

static void count_directory_size_recursive(ExfatContext* ctx, uint32_t start_cluster, int depth) {
    if (depth > EXFAT_MAX_RECURSION_DEPTH) return;

    uint32_t current_cluster = start_cluster;
    bool finished = false;

    while (!finished && current_cluster != 0) {
        if (!read_cluster(ctx, current_cluster, ctx->cluster_buf)) {
            break;
        }

        uint32_t entries_per_cluster = ctx->bytes_per_cluster / EXFAT_ENTRY_SIZE;
        uint32_t entry_offset = 0;
        for (uint32_t i = 0; i < entries_per_cluster; ) {
            uint8_t* entry_ptr = ctx->cluster_buf + entry_offset;
            uint8_t entry_type = *entry_ptr;
            if (entry_type == EXFAT_ENTRY_EOD) {
                finished = true;
                break;
            }

            if (entry_type == EXFAT_ENTRY_FILE) {
                ExfatFileEntry* file_entry = (ExfatFileEntry*)entry_ptr;
                ExfatStreamEntry* stream_entry = (ExfatStreamEntry*)(entry_ptr + EXFAT_ENTRY_SIZE);
                if (stream_entry->entry_type != EXFAT_ENTRY_STREAM) {
                    i++;
                    entry_offset += EXFAT_ENTRY_SIZE;
                    continue;
                }

                bool is_directory = ((file_entry->file_attributes & 0x10) != 0);
                uint32_t first_cluster = stream_entry->first_cluster;
                uint64_t data_length = stream_entry->data_length;
                int num_name_entries = (stream_entry->name_length + 14) / 15;
                int total_entries = 2 + num_name_entries;
                i += total_entries;
                entry_offset += EXFAT_ENTRY_SIZE * total_entries;

                if (is_directory) {
                    count_directory_size_recursive(ctx, first_cluster, depth + 1);
                    if (!read_cluster(ctx, current_cluster, ctx->cluster_buf)) {
                        return;
                    }
                } else {
                    ctx->total_bytes += data_length;
                }
                continue;
            }
            i++;
            entry_offset += EXFAT_ENTRY_SIZE;
        }

        if (!finished) {
            current_cluster = get_next_cluster(ctx, current_cluster);
        }
    }
}

static void count_directory_size(ExfatContext* ctx, uint32_t start_cluster) {
    count_directory_size_recursive(ctx, start_cluster, 0);
}

bool exfat_extract_all(ExfatContext* ctx, const char* output_dir) {
    if (!create_directories(output_dir)) {
        return false;
    }

    ctx->total_bytes = 0;
    ctx->extracted_bytes = 0;
    count_directory_size(ctx, ctx->boot_sector.first_cluster_of_root_dir);

    if (ctx->verbose && !ctx->silent) {
        printf("%llu B\n", (unsigned long long)ctx->total_bytes);
    }

    Progress progress;
    if (!ctx->silent) {
        progress_init(&progress, ctx->total_bytes > 0 ? ctx->total_bytes : 1);
        ctx->progress = &progress;
    }

    bool result = process_directory(ctx, ctx->boot_sector.first_cluster_of_root_dir, output_dir);

    if (!ctx->silent && ctx->progress) {
        progress_finish(&progress);
    }
    ctx->progress = NULL;

    for (uint32_t i = ctx->deferred_count; i > 0; i--) {
        DeferredDirTime* d = &ctx->deferred_dirs[i - 1];
        set_dir_times(d->path, d->mtime, d->atime);
    }
    free(ctx->deferred_dirs);
    ctx->deferred_dirs = NULL;
    ctx->deferred_count = 0;
    ctx->deferred_capacity = 0;

    return result;
}

void exfat_close(ExfatContext* ctx) {
    if (!ctx->stream && ctx->fp) {
        fclose(ctx->fp);
        ctx->fp = NULL;
    }
    if (ctx->fat) {
        free(ctx->fat);
        ctx->fat = NULL;
    }
    free(ctx->cluster_buf);
    ctx->cluster_buf = NULL;
    free(ctx->io_buf);
    ctx->io_buf = NULL;
}
