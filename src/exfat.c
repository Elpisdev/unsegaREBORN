#include "exfat.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <locale.h>
#include <wchar.h>

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
    return ctx->cluster_heap_offset_bytes + ((cluster - 2) * ctx->bytes_per_cluster);
}

static bool read_cluster(ExfatContext* ctx, uint32_t cluster, void* buffer) {
    uint32_t offset = get_cluster_offset(ctx, cluster);
    if (fseek(ctx->fp, offset, SEEK_SET) != 0) {
        return false;
    }
    return fread(buffer, 1, ctx->bytes_per_cluster, ctx->fp) == ctx->bytes_per_cluster;
}

static uint32_t get_next_cluster(ExfatContext* ctx, uint32_t cluster) {
    uint32_t next = ctx->fat[cluster];
    if (next >= 0xFFFFFFF8) {
        return 0; // end-of-chain
    }
    if (next == 0)
    {
        return cluster + 1; // if cluster in FAT is 0 it means the cluster heap is continous (exfat only)
    }
    return next;
}

static bool is_safe_path(const char* path) {
    if (!path) return false;
    
    if (strstr(path, "..") != NULL) return false;
    if (strstr(path, "./") != NULL) return false;
    if (strstr(path, ".\\") != NULL) return false;
    
    #ifndef _WIN32
    if (path[0] == '/') return false;
    #endif
    
    return true;
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
    while (remaining > 0 && current_cluster != 0 && success) {
        if (!read_cluster(ctx, current_cluster, buffer)) {
            success = false;
            break;
        }

        size_t write_size = (remaining > ctx->bytes_per_cluster) ? ctx->bytes_per_cluster : (size_t)remaining;
        if (fwrite(buffer, 1, write_size, out) != write_size) {
            success = false;
            break;
        }

        remaining -= write_size;
        current_cluster = get_next_cluster(ctx, current_cluster);
    }

    free(buffer);
    fclose(out);
    return success;
}

static bool process_directory(ExfatContext* ctx, uint32_t start_cluster, const char* output_dir) {
    uint8_t* cluster_buffer = malloc(ctx->bytes_per_cluster);
    if (!cluster_buffer) {
        return false;
    }

    uint32_t current_cluster = start_cluster;
    bool finished = false;

    while (!finished && current_cluster != 0) {
        if (!read_cluster(ctx, current_cluster, cluster_buffer)) {
            free(cluster_buffer);
            return false;
        }

        uint32_t entries_per_cluster = ctx->bytes_per_cluster / EXFAT_ENTRY_SIZE;
        uint8_t* entry_ptr = cluster_buffer;
        for (uint32_t i = 0; i < entries_per_cluster; ) {
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
                    entry_ptr += EXFAT_ENTRY_SIZE;
                    continue;
                }
                int total_name_chars = stream_entry->name_length;
                int num_name_entries = (total_name_chars + 14) / 15;

                char full_name[MAX_FILENAME_LENGTH];
                wchar_t full_name_unicode[MAX_FILENAME_LENGTH];
                int pos = 0;
                uint8_t* name_entry_ptr = entry_ptr + EXFAT_ENTRY_SIZE * 2;
                for (int k = 0; k < num_name_entries; k++) {
                    ExfatFileNameEntry* name_entry = (ExfatFileNameEntry*)(name_entry_ptr + k * EXFAT_ENTRY_SIZE);
                    int chars_in_this_entry = (total_name_chars - k * 15 < 15) ? (total_name_chars - k * 15) : 15;
                    for (int j = 0; j < chars_in_this_entry; j++) {
                        if (pos < MAX_FILENAME_LENGTH - 1) {
                            // shouldn't cut off the wide char
                            full_name_unicode[pos++] = (wchar_t)name_entry->file_name[j];
                        }
                    }
                }
                full_name_unicode[pos] = L'\0';

                // convert UTF-16 filename to multibyte
#ifdef _WIN32
                _locale_t locale = _create_locale(LC_ALL, "");
                _wcstombs_l(full_name, full_name_unicode, MAX_FILENAME_LENGTH, locale);
                _free_locale(locale);
#else
                wcstombs(full_name, full_name_unicode, MAX_FILENAME_LENGTH);
#endif

                ExfatFileInfo file_info;
                memset(&file_info, 0, sizeof(file_info));
                strncpy(file_info.name, full_name, MAX_PATH_LENGTH - 1);
                file_info.name[MAX_PATH_LENGTH - 1] = '\0';
                file_info.first_cluster = stream_entry->first_cluster;
                file_info.data_length = stream_entry->data_length;
                file_info.is_directory = ((file_entry->file_attributes & 0x10) != 0);

                char full_path[MAX_PATH_LENGTH];
                if (!combine_path(full_path, sizeof(full_path), output_dir, file_info.name)) {
                    fprintf(stderr, "Warning: Invalid or too long path, skipping: %s/%s\n", output_dir, file_info.name);
                    continue;
                }

                if (file_info.is_directory) {
                    if (create_directories(full_path)) {
                        process_directory(ctx, file_info.first_cluster, full_path);
                    }
                }
                else {
                    extract_file(ctx, &file_info, full_path);
                }

                int total_entries = 2 + num_name_entries;
                i += total_entries;
                entry_ptr += EXFAT_ENTRY_SIZE * total_entries;
                continue;
            }
            else {
                i++;
                entry_ptr += EXFAT_ENTRY_SIZE;
            }
        }

        if (!finished) {
            current_cluster = get_next_cluster(ctx, current_cluster);
        }
    }

    free(cluster_buffer);
    return true;
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

    ctx->bytes_per_sector = (1 << ctx->boot_sector.bytes_per_sector_shift);
    ctx->bytes_per_cluster = ctx->bytes_per_sector * (1 << ctx->boot_sector.sectors_per_cluster_shift);
    ctx->cluster_heap_offset_bytes = ctx->boot_sector.cluster_heap_offset * ctx->bytes_per_sector;

    ctx->fat_offset_bytes = ctx->boot_sector.fat_offset * ctx->bytes_per_sector;
    ctx->fat_length_bytes = ctx->boot_sector.fat_length * ctx->bytes_per_sector;

    ctx->fat = malloc(ctx->fat_length_bytes);
    if (!ctx->fat) {
        fclose(ctx->fp);
        return false;
    }

    if (fseek(ctx->fp, ctx->fat_offset_bytes, SEEK_SET) != 0) {
        free(ctx->fat);
        fclose(ctx->fp);
        return false;
    }

    if (fread(ctx->fat, 1, ctx->fat_length_bytes, ctx->fp) != ctx->fat_length_bytes) {
        free(ctx->fat);
        fclose(ctx->fp);
        return false;
    }

    return true;
}

bool exfat_extract_all(ExfatContext* ctx, const char* output_dir) {
    if (!create_directories(output_dir)) {
        return false;
    }
    return process_directory(ctx, ctx->boot_sector.first_cluster_of_root_dir, output_dir);
}

void exfat_close(ExfatContext* ctx) {
    if (ctx->fp) {
        fclose(ctx->fp);
        ctx->fp = NULL;
    }
    if (ctx->fat) {
        free(ctx->fat);
        ctx->fat = NULL;
    }
}
