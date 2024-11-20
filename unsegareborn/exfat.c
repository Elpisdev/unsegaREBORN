#include "exfat.h"
#include <stdlib.h>
#include <string.h>

#include <direct.h>
#define MKDIR(path) _mkdir(path)
#define PATH_SEPARATOR "\\"

static bool create_directories(const char* path) {
    char temp[MAX_PATH_LENGTH];
    char* p = NULL;
    size_t len;
    bool result = true;

    strncpy(temp, path, MAX_PATH_LENGTH - 1);
    temp[MAX_PATH_LENGTH - 1] = '\0';
    len = strlen(temp);

    if (len > 0 && (temp[len - 1] == '/' || temp[len - 1] == '\\')) {
        temp[len - 1] = '\0';
    }

    for (p = temp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
            if (MKDIR(temp) != 0 && errno != EEXIST) {
                result = false;
                break;
            }
            *p = PATH_SEPARATOR[0];
        }
    }

    if (result && MKDIR(temp) != 0 && errno != EEXIST) {
        result = false;
    }

    return result;
}

static uint32_t get_cluster_offset(ExfatContext* ctx, uint32_t cluster) {
    return ctx->cluster_heap_offset_bytes +
        ((cluster - 2) * ctx->bytes_per_cluster);
}

static bool read_cluster(ExfatContext* ctx, uint32_t cluster, void* buffer) {
    uint32_t offset = get_cluster_offset(ctx, cluster);
    if (fseek(ctx->fp, offset, SEEK_SET) != 0) {
        return false;
    }
    return fread(buffer, 1, ctx->bytes_per_cluster, ctx->fp) == ctx->bytes_per_cluster;
}

static void combine_path(char* dest, size_t dest_size, const char* dir, const char* name) {
    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);

    if (dir_len + name_len + 2 > dest_size) {
        dest[0] = '\0';
        return;
    }

    strcpy(dest, dir);
    if (dir_len > 0 && dir[dir_len - 1] != '/' && dir[dir_len - 1] != '\\') {
        strcat(dest, PATH_SEPARATOR);
    }
    strcat(dest, name);
}

static bool extract_file(ExfatContext* ctx, ExfatFileInfo* file, const char* output_path) {
    FILE* out = fopen(output_path, "wb");
    if (!out) {
        return false;
    }

    uint32_t current_cluster = file->first_cluster;
    uint64_t remaining = file->data_length;
    uint8_t* buffer = malloc(ctx->bytes_per_cluster);

    if (!buffer) {
        fclose(out);
        return false;
    }

    bool success = true;
    while (remaining > 0 && success) {
        if (!read_cluster(ctx, current_cluster, buffer)) {
            success = false;
            break;
        }

        size_t write_size = (remaining > ctx->bytes_per_cluster) ?
            ctx->bytes_per_cluster : (size_t)remaining;

        if (fwrite(buffer, 1, write_size, out) != write_size) {
            success = false;
            break;
        }

        remaining -= write_size;
        current_cluster++;
    }

    free(buffer);
    fclose(out);
    return success;
}

bool exfat_init(ExfatContext* ctx, const char* filename) {
    memset(ctx, 0, sizeof(ExfatContext));

    ctx->fp = fopen(filename, "rb");
    if (!ctx->fp) {
        return false;
    }

    if (fread(&ctx->boot_sector, sizeof(ExfatBootSector), 1, ctx->fp) != 1) {
        fclose(ctx->fp);
        return false;
    }

    ctx->bytes_per_cluster = (1 << ctx->boot_sector.bytes_per_sector_shift) *
        (1 << ctx->boot_sector.sectors_per_cluster_shift);

    ctx->cluster_heap_offset_bytes = ctx->boot_sector.cluster_heap_offset *
        (1 << ctx->boot_sector.bytes_per_sector_shift);

    return true;
}

static bool process_directory(ExfatContext* ctx, uint32_t cluster,
    const char* output_dir) {
    uint8_t* buffer = malloc(ctx->bytes_per_cluster);
    if (!buffer) {
        return false;
    }

    if (!read_cluster(ctx, cluster, buffer)) {
        free(buffer);
        return false;
    }

    uint32_t entries_per_cluster = ctx->bytes_per_cluster / EXFAT_ENTRY_SIZE;
    uint8_t* entry = buffer;

    for (uint32_t i = 0; i < entries_per_cluster; i++) {
        if (*entry == EXFAT_ENTRY_EOD) {
            break;
        }

        if (*entry == EXFAT_ENTRY_FILE) {
            ExfatFileEntry* file_entry = (ExfatFileEntry*)entry;
            ExfatStreamEntry* stream_entry = (ExfatStreamEntry*)(entry + EXFAT_ENTRY_SIZE);
            ExfatFileNameEntry* name_entry = (ExfatFileNameEntry*)(entry + EXFAT_ENTRY_SIZE * 2);

            if (stream_entry->entry_type == EXFAT_ENTRY_STREAM) {
                ExfatFileInfo file_info;
                memset(&file_info, 0, sizeof(file_info));

                char* name_ptr = file_info.name;
                for (int j = 0; j < stream_entry->name_length && j < 15; j++) {
                    *name_ptr++ = (char)(name_entry->file_name[j] & 0xFF);
                }
                *name_ptr = '\0';

                file_info.first_cluster = stream_entry->first_cluster;
                file_info.data_length = stream_entry->data_length;
                file_info.is_directory = (file_entry->file_attributes & 0x10) != 0;

                char full_path[MAX_PATH_LENGTH];
                combine_path(full_path, sizeof(full_path), output_dir, file_info.name);

                if (file_info.is_directory) {
                    if (create_directories(full_path)) {
                        process_directory(ctx, file_info.first_cluster, full_path);
                    }
                }
                else {
                    extract_file(ctx, &file_info, full_path);
                }
            }
        }

        entry += EXFAT_ENTRY_SIZE;
    }

    free(buffer);
    return true;
}

bool exfat_extract_all(ExfatContext* ctx, const char* output_dir) {
    if (!create_directories(output_dir)) {
        return false;
    }
    return process_directory(ctx, ctx->boot_sector.first_cluster_of_root_dir,
        output_dir);
}

void exfat_close(ExfatContext* ctx) {
    if (ctx->fp) {
        fclose(ctx->fp);
        ctx->fp = NULL;
    }
}