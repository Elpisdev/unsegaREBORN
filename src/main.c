#include "lib.h"
#include "bootid.h"
#include "crypto.h"
#include "aes.h"
#include "progress.h"
#include "exfat.h"
#include "ntfs.h"
#include "error.h"
#include "stream.h"
#include "common.h"

#define PAGE_SIZE 4096
#define BUFFER_SIZE (PAGE_SIZE * 256)
#define MAX_PATH_LENGTH 256
#define VERSION "2026020601"

typedef struct {
    bool silent;
    bool verbose;
    bool extract_fs;
    bool write_intermediate;
    char* output_filename;
    const char* output_dir;
    const char* parent_file;
    uint64_t total_files_extracted;
    uint64_t total_bytes_extracted;
    time_t start_time;
} AppContext;

typedef struct {
    BootId bootid;
    uint8_t key[16];
    uint8_t iv[16];
    char os_id[4];
    char game_id[5];
    char timestamp_str[20];
    uint64_t data_offset;
    uint64_t data_size;
    bool is_apm3;
    bool is_inner_apm3;
} DecryptInfo;

#define PRINT(ctx, ...) do { if (!(ctx)->silent) printf(__VA_ARGS__); } while(0)
#define VERBOSE(ctx, ...) do { if ((ctx)->verbose && !(ctx)->silent) printf(__VA_ARGS__); } while(0)

static inline void path_join(char* dest, size_t size, const char* dir, const char* name) {
    if (dir) {
        snprintf(dest, size, "%s%s%s", dir, PATH_SEPARATOR, name);
    } else {
        snprintf(dest, size, "%s", name);
    }
}

static ErrorCode do_file(AppContext* app_ctx, const char* path);

static bool test_keys(FILE* file, uint64_t data_offset, const uint8_t* test_key,
                               const uint8_t* test_iv, const uint8_t* expected_header) {
    uint8_t buffer[16];
    uint8_t page_iv[16];
    uint8_t decrypted[16];

    long saved_pos = ftell(file);
    if (fseek(file, (long)data_offset, SEEK_SET) != 0) {
        fseek(file, saved_pos, SEEK_SET);
        return false;
    }

    if (fread(buffer, 1, 16, file) != 16) {
        fseek(file, saved_pos, SEEK_SET);
        return false;
    }
    fseek(file, saved_pos, SEEK_SET);

    iv_page(0, test_iv, page_iv);

    memcpy(decrypted, buffer, 16);
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, test_key, page_iv);
    AES_CBC_decrypt_buffer(&ctx, decrypted, 16);

    return memcmp(decrypted, expected_header, 8) == 0;
}

static ErrorCode parse_bootid(AppContext* app_ctx, FILE* file, DecryptInfo* info, uint8_t* read_buffer) {
    uint8_t bootid_bytes[96];
    if (fread(bootid_bytes, 1, 96, file) != 96) {
        FAIL(ERR_INVALID_BOOTID);
        return ERR_INVALID_BOOTID;
    }

    uint8_t decrypted[96];
    memcpy(decrypted, bootid_bytes, 96);
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, BOOTID_KEY, BOOTID_IV);
    AES_CBC_decrypt_buffer(&ctx, decrypted, 96);
    memcpy(&info->bootid, decrypted, sizeof(BootId));

    if (info->bootid.container_type != CONTAINER_TYPE_OS &&
        info->bootid.container_type != CONTAINER_TYPE_APP &&
        info->bootid.container_type != CONTAINER_TYPE_OPTION) {
        char msg[64];
        snprintf(msg, sizeof(msg), "type %d", info->bootid.container_type);
        FAIL_MSG(ERR_UNKNOWN_CONTAINER, msg);
        return ERR_UNKNOWN_CONTAINER;
    }

    format_timestamp(&info->bootid.target_timestamp, info->timestamp_str, sizeof(info->timestamp_str));
    memcpy(info->os_id, info->bootid.os_id, 3);
    info->os_id[3] = '\0';
    memcpy(info->game_id, info->bootid.game_id, 4);
    info->game_id[4] = '\0';

    info->is_apm3 = (info->bootid.container_type == CONTAINER_TYPE_OPTION) && IS_APM3_OPTION(info->bootid.game_id);
    info->is_inner_apm3 = false;
    info->data_offset = info->bootid.header_block_count * info->bootid.block_size;
    info->data_size = (info->bootid.block_count - info->bootid.header_block_count) * info->bootid.block_size;

    const char* id = (info->bootid.container_type == CONTAINER_TYPE_OS) ? info->os_id : info->game_id;

    VERBOSE(app_ctx, "  %s %s %s #%d AES:%s\n",
        (info->bootid.container_type == CONTAINER_TYPE_OS) ? "OS" :
        (info->bootid.container_type == CONTAINER_TYPE_APP) ? "APP" :
        info->is_apm3 ? "APM3" : "OPT", id, info->timestamp_str, info->bootid.sequence_number,
        aes_hw_supported() ? "HW" : "SW");

    GameKeys keys;
    bool got_keys = false;
    const char* key_source = NULL;

    if (info->bootid.container_type == CONTAINER_TYPE_OS || info->bootid.container_type == CONTAINER_TYPE_APP) {
        got_keys = key_game(id, &keys);
        if (got_keys) key_source = keys.external ? "ext" : "int";
    } else if (info->is_apm3) {
        memcpy(keys.key, OPTION_KEY, 16);
        memcpy(keys.iv, OPTION_IV, 16);
        keys.has_iv = true;
        got_keys = true;
        key_source = "apm3";
    } else {
        uint8_t derived_key[16], derived_iv[16];
        if (key_derive(info->game_id, derived_key, derived_iv) &&
            test_keys(file, info->data_offset, derived_key, derived_iv, NTFS_HEADER)) {
            memcpy(keys.key, derived_key, 16);
            memcpy(keys.iv, derived_iv, 16);
            keys.has_iv = true;
            got_keys = true;
            info->is_inner_apm3 = true;
            key_source = "derived";
        } else {
            memcpy(keys.key, OPTION_KEY, 16);
            keys.has_iv = false;
            got_keys = true;
            key_source = "optkey";
        }
    }

    if (!got_keys) {
        FAIL_MSG(ERR_KEY_NOT_FOUND, id);
        return ERR_KEY_NOT_FOUND;
    }

    VERBOSE(app_ctx, "  key:%s\n", key_source);
    memcpy(info->key, keys.key, 16);

    bool has_iv = !info->bootid.use_custom_iv && keys.has_iv;
    if (has_iv) {
        memcpy(info->iv, keys.iv, 16);
        VERBOSE(app_ctx, "  iv:key\n");
    } else {
        if (fseek(file, (long)info->data_offset, SEEK_SET) != 0) {
            FAIL(ERR_FILE_SEEK);
            return ERR_FILE_SEEK;
        }
        if (fread(read_buffer, 1, PAGE_SIZE, file) != PAGE_SIZE) {
            FAIL(ERR_FILE_READ);
            return ERR_FILE_READ;
        }
        const uint8_t* header = (info->bootid.container_type == CONTAINER_TYPE_OPTION && !info->is_apm3 && !info->is_inner_apm3) ? EXFAT_HEADER : NTFS_HEADER;
        if (!iv_file(info->key, header, read_buffer, info->iv)) {
            FAIL(ERR_IV_CALCULATION);
            return ERR_IV_CALCULATION;
        }
        VERBOSE(app_ctx, "  iv:calc\n");
    }

    return ERR_OK;
}

static void format_basename(const DecryptInfo* info, char* out, size_t size) {
    if (info->bootid.container_type == CONTAINER_TYPE_OS) {
        snprintf(out, size, "%s_%04d%02d%02d_%s_%d",
            info->os_id, info->bootid.os_version.major, info->bootid.os_version.minor,
            info->bootid.os_version.release, info->timestamp_str, info->bootid.sequence_number);
    } else if (info->bootid.container_type == CONTAINER_TYPE_APP) {
        if (info->bootid.sequence_number > 0) {
            snprintf(out, size, "%s_%d%02d%02d_%s_%d_%d%02d%02d",
                info->game_id, info->bootid.target_version.version.major, info->bootid.target_version.version.minor,
                info->bootid.target_version.version.release, info->timestamp_str, info->bootid.sequence_number,
                info->bootid.source_version.major, info->bootid.source_version.minor, info->bootid.source_version.release);
        } else {
            snprintf(out, size, "%s_%d%02d%02d_%s_%d",
                info->game_id, info->bootid.target_version.version.major, info->bootid.target_version.version.minor,
                info->bootid.target_version.version.release, info->timestamp_str, info->bootid.sequence_number);
        }
    } else if (info->bootid.container_type == CONTAINER_TYPE_OPTION) {
        char option_str[5];
        memcpy(option_str, info->bootid.target_version.option, 4);
        option_str[4] = '\0';
        snprintf(out, size, "%s_%s_%s_%d",
            info->game_id, option_str, info->timestamp_str, info->bootid.sequence_number);
    }
}

typedef enum {
    FS_NTFS,
    FS_EXFAT
} FsType;

static void decrypt_bootid(const uint8_t* enc, BootId* out) {
    uint8_t dec[96];
    memcpy(dec, enc, 96);
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, BOOTID_KEY, BOOTID_IV);
    AES_CBC_decrypt_buffer(&ctx, dec, 96);
    memcpy(out, dec, sizeof(BootId));
}

static void copy_runs_from_opt(RunSource* dst, const PendingOpt* opt, void* ntfs_ctx) {
    dst->ntfs_ctx = ntfs_ctx;
    dst->run_count = (opt->run_count < MAX_DATA_RUNS) ? opt->run_count : MAX_DATA_RUNS;
    dst->file_size = opt->file_size;
    for (int r = 0; r < dst->run_count; r++) {
        dst->runs[r].offset = opt->runs[r].offset;
        dst->runs[r].length = opt->runs[r].length;
    }
}

#define EXTRACT_F_ALLOW_VHD         0x01
#define EXTRACT_F_RMDIR_ON_ORPHAN   0x02
#define EXTRACT_F_CHECK_DIFF_PARENT 0x04

static void strip_extension(char* path) {
    char* ext = strrchr(path, '.');
    if (ext) *ext = '\0';
}

static const char* get_basename(const char* path) {
    const char* b = strrchr(path, '/');
    if (!b) b = strrchr(path, '\\');
    return b ? b + 1 : path;
}

static void do_inner_opts(AppContext* app_ctx, const char* dir_path);
static bool derive_inner_keys(const char* game_id, const uint8_t* first_page,
                              uint8_t* out_key, uint8_t* out_iv, FsType* out_fs);
static bool extract_stream_fs(AppContext* app_ctx, DecryptStream* stream,
                              const char* out_dir, FsType fs_type, uint32_t flags);

static void process_pending_opts(AppContext* app_ctx, NTFSContext* ctx, const char* output_dir) {
    int pending_count = ctx->pending_opt_count;

    for (int i = 0; i < pending_count; i++) {
        const PendingOpt* opt = ntfs_get_pending_opt(ctx, i);
        if (!opt) continue;

        VERBOSE(app_ctx, "opt:%s\n", opt->filename);

        RunSource run_src = {0};
        copy_runs_from_opt(&run_src, opt, ctx);

        uint8_t bootid_enc[96];
        if (!stream_read_raw(ctx, run_src.runs, run_src.run_count,
                            run_src.file_size, 0, bootid_enc, 96)) {
            fprintf(stderr, "optrd\n");
            continue;
        }

        BootId inner_bootid;
        decrypt_bootid(bootid_enc, &inner_bootid);
        if (inner_bootid.container_type != CONTAINER_TYPE_OPTION) continue;

        char inner_game_id[5];
        memcpy(inner_game_id, inner_bootid.game_id, 4);
        inner_game_id[4] = '\0';

        uint64_t inner_data_offset = inner_bootid.header_block_count * inner_bootid.block_size;
        uint64_t inner_data_size = (inner_bootid.block_count - inner_bootid.header_block_count) * inner_bootid.block_size;

        uint8_t first_page[PAGE_SIZE];
        if (!stream_read_raw(ctx, run_src.runs, run_src.run_count,
                            run_src.file_size, inner_data_offset, first_page, PAGE_SIZE)) {
            fprintf(stderr, "pgrd\n");
            continue;
        }

        uint8_t key[16], iv[16];
        FsType inner_fs;
        if (!derive_inner_keys(inner_game_id, first_page, key, iv, &inner_fs)) continue;

        char opt_basename[MAX_FILENAME_LENGTH];
        strncpy(opt_basename, opt->filename, sizeof(opt_basename) - 1);
        opt_basename[sizeof(opt_basename) - 1] = '\0';
        strip_extension(opt_basename);

        char inner_output_dir[MAX_PATH_LENGTH];
        path_join(inner_output_dir, sizeof(inner_output_dir), output_dir, opt_basename);

        RunSource* inner_run_src = malloc(sizeof(RunSource));
        if (!inner_run_src) continue;
        memset(inner_run_src, 0, sizeof(RunSource));
        copy_runs_from_opt(inner_run_src, opt, ctx);

        DecryptStream* inner_stream = malloc(sizeof(DecryptStream));
        if (!inner_stream) {
            free(inner_run_src);
            continue;
        }

        if (!stream_init_from_runs(inner_stream, inner_run_src, key, iv)) {
            free(inner_run_src);
            free(inner_stream);
            continue;
        }

        inner_stream->data_offset = inner_data_offset;
        inner_stream->data_size = inner_data_size;

        extract_stream_fs(app_ctx, inner_stream, inner_output_dir, inner_fs,
                          EXTRACT_F_ALLOW_VHD | EXTRACT_F_RMDIR_ON_ORPHAN);

        free(inner_run_src);
        free(inner_stream);
    }
}

static int find_highest_vhd(const char* dir) {
    char vhd_path[MAX_PATH_LENGTH];
    int highest = -1;
    for (int n = 0; n < 10; n++) {
        snprintf(vhd_path, sizeof(vhd_path), "%s%sinternal_%d.vhd", dir, PATH_SEPARATOR, n);
        FILE* f = FOPEN(vhd_path, "rb");
        if (f) { fclose(f); highest = n; }
    }
    return highest;
}

static bool extract_file_fs(AppContext* app_ctx, const char* filepath,
                            const char* out_dir, FsType fs_type, uint32_t flags) {
    bool ok = false;

    if (fs_type == FS_NTFS) {
        NTFSContext ctx = {0};
        ctx.silent = app_ctx->silent;
        ctx.verbose = app_ctx->verbose;

        if (ntfs_init(&ctx, filepath, out_dir)) {
            if (flags & EXTRACT_F_CHECK_DIFF_PARENT) {
                int vhd_type = ntfs_detect_vhd_type(&ctx);
                if (vhd_type == VHD_TYPE_DIFFERENCING && !app_ctx->parent_file) {
                    PRINT(app_ctx, "\ndiff VHD, use -p\n");
                    ntfs_close(&ctx);
                    return true;
                }
            }

            VERBOSE(app_ctx, "ntfs MFT=%llu c=%u\n",
                (unsigned long long)ctx.total_mft_records, ctx.bytes_per_cluster);

            if (ntfs_extract_all(&ctx)) {
                ok = true;
                app_ctx->total_files_extracted += ctx.files_extracted;
                app_ctx->total_bytes_extracted += ctx.extracted_bytes;

                if (flags & EXTRACT_F_ALLOW_VHD) {
                    int highest = find_highest_vhd(out_dir);
                    if (highest >= 0) {
                        char vhd_path[MAX_PATH_LENGTH];
                        snprintf(vhd_path, sizeof(vhd_path), "%s%sinternal_%d.vhd",
                            out_dir, PATH_SEPARATOR, highest);

                        char vhd_out[MAX_PATH_LENGTH];
                        snprintf(vhd_out, sizeof(vhd_out), "%s%scontents", out_dir, PATH_SEPARATOR);

                        NTFSContext vhd_ctx = {0};
                        vhd_ctx.silent = app_ctx->silent;
                        vhd_ctx.verbose = app_ctx->verbose;

                        if (ntfs_init(&vhd_ctx, vhd_path, vhd_out)) {
                            VERBOSE(app_ctx, "vhd MFT=%llu c=%u\n",
                                (unsigned long long)vhd_ctx.total_mft_records, vhd_ctx.bytes_per_cluster);
                            if (ntfs_extract_all(&vhd_ctx)) {
                                app_ctx->total_files_extracted += vhd_ctx.files_extracted;
                                app_ctx->total_bytes_extracted += vhd_ctx.extracted_bytes;
                            }
                            ntfs_close(&vhd_ctx);
                        }
                    }
                }

                do_inner_opts(app_ctx, out_dir);
            }
            ntfs_close(&ctx);
        }
    } else {
        ExfatContext ctx;
        if (exfat_init(&ctx, filepath)) {
            ctx.silent = app_ctx->silent;
            ctx.verbose = app_ctx->verbose;
            VERBOSE(app_ctx, "exfat c=%u f=%u\n", ctx.bytes_per_cluster, ctx.fat_length_bytes);
            if (exfat_extract_all(&ctx, out_dir)) {
                ok = true;
                app_ctx->total_files_extracted += ctx.files_extracted;
                app_ctx->total_bytes_extracted += ctx.extracted_bytes;
            }
            exfat_close(&ctx);
        }
    }

    return ok;
}

static bool derive_inner_keys(const char* game_id, const uint8_t* first_page,
                              uint8_t* out_key, uint8_t* out_iv, FsType* out_fs) {
    uint8_t derived_key[16], derived_iv[16];

    if (key_derive(game_id, derived_key, derived_iv)) {
        uint8_t page_iv[16], test_decrypt[16];
        iv_page(0, derived_iv, page_iv);
        memcpy(test_decrypt, first_page, 16);
        AES_ctx test_ctx;
        AES_init_ctx_iv(&test_ctx, derived_key, page_iv);
        AES_CBC_decrypt_buffer(&test_ctx, test_decrypt, 16);

        if (memcmp(test_decrypt, NTFS_HEADER, 8) == 0) {
            memcpy(out_key, derived_key, 16);
            memcpy(out_iv, derived_iv, 16);
            *out_fs = FS_NTFS;
            return true;
        }
    }

    memcpy(out_key, OPTION_KEY, 16);
    if (!iv_file(out_key, EXFAT_HEADER, first_page, out_iv)) {
        return false;
    }
    *out_fs = FS_EXFAT;
    return true;
}

static bool extract_stream_fs(AppContext* app_ctx, DecryptStream* stream,
                              const char* out_dir, FsType fs_type, uint32_t flags) {
    bool ok = false;

    if (fs_type == FS_NTFS) {
        NTFSContext ctx = {0};
        ctx.silent = app_ctx->silent;
        ctx.verbose = app_ctx->verbose;

        if (ntfs_init_stream(&ctx, stream, out_dir)) {
            if (flags & EXTRACT_F_CHECK_DIFF_PARENT) {
                int vhd_type = ntfs_detect_vhd_type(&ctx);
                if (vhd_type == VHD_TYPE_DIFFERENCING && !app_ctx->parent_file) {
                    PRINT(app_ctx, "diff VHD, use -p\n");
                    ntfs_close(&ctx);
                    return true;
                }
            }

            VERBOSE(app_ctx, "MFT=%llu c=%u\n",
                (unsigned long long)ctx.total_mft_records, ctx.bytes_per_cluster);

            ctx.silent = true;
            if (ntfs_extract_all(&ctx)) {
                ctx.silent = app_ctx->silent;

                bool is_orphan = false;
                if ((flags & EXTRACT_F_ALLOW_VHD) && ctx.pending_vhd_count > 0) {
                    ntfs_extract_pending_vhds(&ctx, app_ctx->silent, app_ctx->verbose, &is_orphan);
                }

                if ((flags & EXTRACT_F_RMDIR_ON_ORPHAN) && is_orphan) {
                    VERBOSE(app_ctx, "  orphan\n");
                    RMDIR(out_dir);
                } else {
                    ok = true;
                    app_ctx->total_files_extracted += ctx.files_extracted;
                    app_ctx->total_bytes_extracted += ctx.extracted_bytes;
                }
            }
            ntfs_close(&ctx);
        }
    } else {
        ExfatContext ctx;
        if (exfat_init_stream(&ctx, stream)) {
            ctx.silent = app_ctx->silent;
            ctx.verbose = app_ctx->verbose;
            VERBOSE(app_ctx, "exfat c=%u f=%u\n", ctx.bytes_per_cluster, ctx.fat_length_bytes);
            if (exfat_extract_all(&ctx, out_dir)) {
                ok = true;
                app_ctx->total_files_extracted += ctx.files_extracted;
                app_ctx->total_bytes_extracted += ctx.extracted_bytes;
            }
            exfat_close(&ctx);
        }
    }

    return ok;
}

static const char* fmt_size(uint64_t bytes, char* buffer, size_t buffer_size) {
    uint64_t unit, frac;
    const char* suffix;
    if (bytes >= 1024ULL * 1024 * 1024) {
        unit = 1024ULL * 1024 * 1024; suffix = " GB";
    } else if (bytes >= 1024ULL * 1024) {
        unit = 1024ULL * 1024; suffix = " MB";
    } else if (bytes >= 1024) {
        unit = 1024; suffix = " KB";
    } else {
        snprintf(buffer, buffer_size, "%llu bytes", (unsigned long long)bytes);
        return buffer;
    }
    uint64_t whole = bytes / unit;
    frac = (bytes % unit) * 100 / unit;
    snprintf(buffer, buffer_size, "%llu.%02llu%s", (unsigned long long)whole, (unsigned long long)frac, suffix);
    return buffer;
}

static ErrorCode do_stream(AppContext* app_ctx, const char* path);

static bool do_inner_opt(AppContext* app_ctx, const char* opt_path, const char* output_dir) {
    FILE* file = FOPEN(opt_path, "rb");
    if (!file) return false;

    uint8_t bootid_enc[96];
    if (fread(bootid_enc, 1, 96, file) != 96) {
        fclose(file);
        return false;
    }

    BootId bootid;
    decrypt_bootid(bootid_enc, &bootid);

    if (bootid.container_type != CONTAINER_TYPE_OPTION) {
        fclose(file);
        return false;
    }

    char inner_game_id[5];
    memcpy(inner_game_id, bootid.game_id, 4);
    inner_game_id[4] = '\0';

    uint64_t data_offset = bootid.header_block_count * bootid.block_size;
    uint64_t data_size = (bootid.block_count - bootid.header_block_count) * bootid.block_size;

    uint8_t first_page[PAGE_SIZE];
    if (fseek(file, (long)data_offset, SEEK_SET) != 0 ||
        fread(first_page, 1, PAGE_SIZE, file) != PAGE_SIZE) {
        fclose(file);
        return false;
    }

    uint8_t key[16], iv[16];
    FsType fs_type;
    if (!derive_inner_keys(inner_game_id, first_page, key, iv, &fs_type)) {
        fclose(file);
        return false;
    }

    DecryptStream* stream = malloc(sizeof(DecryptStream));
    if (!stream) {
        fclose(file);
        return false;
    }

    if (!stream_init(stream, file, data_offset, data_size, key, iv)) {
        free(stream);
        fclose(file);
        return false;
    }

    bool success = extract_stream_fs(app_ctx, stream, output_dir, fs_type,
                                     EXTRACT_F_ALLOW_VHD | EXTRACT_F_RMDIR_ON_ORPHAN);

    free(stream);
    fclose(file);
    return success;
}

static void do_inner_opts(AppContext* app_ctx, const char* dir_path) {
    char search_path[MAX_PATH_LENGTH];
    snprintf(search_path, sizeof(search_path), "%s%s*.opt", dir_path, PATH_SEPARATOR);

    lib_finddata_t find_data;
    intptr_t hFind = _findfirst(search_path, &find_data);

    if (hFind == -1) return;

    do {
        if (find_data.attrib & _A_SUBDIR) continue;

        char opt_path[MAX_PATH_LENGTH];
        path_join(opt_path, sizeof(opt_path), dir_path, find_data.name);

        char opt_basename[MAX_PATH_LENGTH];
        strncpy(opt_basename, find_data.name, sizeof(opt_basename) - 1);
        opt_basename[sizeof(opt_basename) - 1] = '\0';
        strip_extension(opt_basename);

        char inner_output_dir[MAX_PATH_LENGTH];
        path_join(inner_output_dir, sizeof(inner_output_dir), dir_path, opt_basename);

        VERBOSE(app_ctx, "  opt:%s\n", find_data.name);

        if (do_inner_opt(app_ctx, opt_path, inner_output_dir)) {
            REMOVE(opt_path);
        }
    } while (_findnext(hFind, &find_data) == 0);

    _findclose(hFind);
}

ErrorCode do_file(AppContext* app_ctx, const char* path) {
    if (!app_ctx->write_intermediate && app_ctx->extract_fs) {
        return do_stream(app_ctx, path);
    }

    ErrorCode result = ERR_EXTRACTION_FAILED;
    uint8_t* read_buffer = NULL;
    uint8_t* decrypted_buffer = NULL;
    char* output_filename = NULL;
    FILE* file = NULL;
    FILE* output_file = NULL;
    uint8_t page_iv[16];

    read_buffer = malloc(BUFFER_SIZE);
    decrypted_buffer = malloc(BUFFER_SIZE);
    if (!read_buffer || !decrypted_buffer) {
        FAIL(ERR_MEMORY);
        result = ERR_MEMORY;
        goto cleanup;
    }

    file = FOPEN(path, "rb");
    if (!file) {
        FAIL_MSG(ERR_FILE_OPEN, path);
        result = ERR_FILE_OPEN;
        goto cleanup;
    }

    DecryptInfo info;
    result = parse_bootid(app_ctx, file, &info, read_buffer);
    if (result != ERR_OK) goto cleanup;

    output_filename = malloc(MAX_PATH_LENGTH);
    if (!output_filename) {
        FAIL(ERR_MEMORY);
        result = ERR_MEMORY;
        goto cleanup;
    }

    char basename[MAX_PATH_LENGTH];
    format_basename(&info, basename, MAX_PATH_LENGTH);
    const char* ext = (info.bootid.container_type == CONTAINER_TYPE_OPTION && !info.is_apm3 && !info.is_inner_apm3) ? ".exfat" : ".ntfs";
    strncat(basename, ext, MAX_PATH_LENGTH - strlen(basename) - 1);
    path_join(output_filename, MAX_PATH_LENGTH, app_ctx->output_dir, basename);

    if (app_ctx->output_dir) create_directories(app_ctx->output_dir);

    output_file = FOPEN(output_filename, "wb");
    if (!output_file) {
        FAIL_MSG(ERR_FILE_OPEN, output_filename);
        result = ERR_FILE_OPEN;
        goto cleanup;
    }

    if (info.data_size % 16 != 0) {
        char msg[64];
        snprintf(msg, sizeof(msg), "%llu bytes", (unsigned long long)info.data_size);
        FAIL_MSG(ERR_AES_ALIGNMENT, msg);
        result = ERR_AES_ALIGNMENT;
        goto cleanup;
    }

    if (fseek(file, (long)info.data_offset, SEEK_SET) != 0) {
        FAIL(ERR_FILE_SEEK);
        result = ERR_FILE_SEEK;
        goto cleanup;
    }

    AES_ctx page_ctx;
    AES_init_ctx_iv(&page_ctx, info.key, info.iv);

    Progress progress;
    if (!app_ctx->silent) {
        progress_init(&progress, info.data_size);
    }

    uint64_t total_bytes_read = 0;
    uint64_t bytes_remaining = info.data_size;

    while (bytes_remaining > 0) {
        size_t chunk_size = (bytes_remaining > BUFFER_SIZE) ? BUFFER_SIZE : (size_t)bytes_remaining;

        size_t read_size = fread(read_buffer, 1, chunk_size, file);
        if (read_size != chunk_size) {
            FAIL_MSG(ERR_FILE_READ, feof(file) ? "unexpected end of file" : "read error");
            result = ERR_FILE_READ;
            goto cleanup;
        }

        size_t offset = 0;
        while (offset < read_size) {
            size_t block_size = (read_size - offset > PAGE_SIZE) ? PAGE_SIZE : (read_size - offset);

            uint64_t file_offset = total_bytes_read + offset;
            iv_page(file_offset, info.iv, page_iv);

            memcpy(decrypted_buffer + offset, read_buffer + offset, block_size);
            AES_ctx_set_iv(&page_ctx, page_iv);
            AES_CBC_decrypt_buffer(&page_ctx, decrypted_buffer + offset, block_size);

            offset += block_size;
        }

        if (fwrite(decrypted_buffer, 1, read_size, output_file) != read_size) {
            FAIL(ERR_FILE_WRITE);
            result = ERR_FILE_WRITE;
            goto cleanup;
        }

        total_bytes_read += read_size;
        bytes_remaining -= read_size;

        if (!app_ctx->silent) {
            progress_update(&progress, total_bytes_read);
        }
    }

    if (!app_ctx->silent) {
        progress_finish(&progress);
    }
    PRINT(app_ctx, "ok: %s\n", output_filename);

    if (app_ctx->extract_fs) {
        if (app_ctx->output_filename) free(app_ctx->output_filename);
        app_ctx->output_filename = output_filename;
        output_filename = NULL;
    }

    result = ERR_OK;

cleanup:
    if (file) fclose(file);
    if (output_file) fclose(output_file);
    free(read_buffer);
    free(decrypted_buffer);
    free(output_filename);
    return result;
}

static ErrorCode do_stream(AppContext* app_ctx, const char* path) {
    ErrorCode result = ERR_EXTRACTION_FAILED;
    uint8_t* read_buffer = NULL;
    FILE* file = NULL;
    DecryptStream* stream = NULL;

    read_buffer = malloc(PAGE_SIZE);
    stream = malloc(sizeof(DecryptStream));
    if (!read_buffer || !stream) {
        FAIL(ERR_MEMORY);
        result = ERR_MEMORY;
        goto cleanup;
    }

    file = FOPEN(path, "rb");
    if (!file) {
        FAIL_MSG(ERR_FILE_OPEN, path);
        result = ERR_FILE_OPEN;
        goto cleanup;
    }

    DecryptInfo info;
    result = parse_bootid(app_ctx, file, &info, read_buffer);
    if (result != ERR_OK) goto cleanup;

    if (!stream_init(stream, file, info.data_offset, info.data_size, info.key, info.iv)) {
        FAIL(ERR_EXTRACTION_FAILED);
        result = ERR_EXTRACTION_FAILED;
        goto cleanup;
    }

    char output_dir[MAX_PATH_LENGTH];
    char basename_no_ext[MAX_PATH_LENGTH];
    format_basename(&info, basename_no_ext, sizeof(basename_no_ext));
    path_join(output_dir, sizeof(output_dir), app_ctx->output_dir, basename_no_ext);

    bool extraction_success = false;

    if (info.bootid.container_type == CONTAINER_TYPE_OPTION && !info.is_apm3 && !info.is_inner_apm3) {
        extraction_success = extract_stream_fs(app_ctx, stream, output_dir, FS_EXFAT, 0);
    }
    else if (info.is_apm3 || info.is_inner_apm3) {
        char inner_game_id[5] = {0};
        if (info.is_apm3) {
            memcpy(inner_game_id, info.bootid.target_version.option, 4);
        } else {
            memcpy(inner_game_id, info.game_id, 4);
        }
        inner_game_id[4] = '\0';
        VERBOSE(app_ctx, "apm3:%s\n", inner_game_id);

        NTFSContext ctx = { 0 };
        ctx.silent = app_ctx->silent;
        ctx.verbose = app_ctx->verbose;
        ctx.apm3_decrypt = false;

        if (ntfs_init_stream(&ctx, stream, output_dir)) {
            int vhd_type = ntfs_detect_vhd_type(&ctx);
            if (vhd_type == VHD_TYPE_DIFFERENCING && !app_ctx->parent_file) {
                PRINT(app_ctx, "diff VHD, use -p\n");
                ntfs_close(&ctx);
                result = ERR_OK;
                goto cleanup;
            }

            VERBOSE(app_ctx, "MFT=%llu c=%u\n",
                (unsigned long long)ctx.total_mft_records, ctx.bytes_per_cluster);

            ctx.silent = true;

            if (ntfs_extract_all(&ctx)) {
                extraction_success = true;
                ctx.silent = app_ctx->silent;

                if (ctx.pending_vhd_count > 0) {
                    bool is_orphan = false;
                    ntfs_extract_pending_vhds(&ctx, app_ctx->silent, app_ctx->verbose, &is_orphan);
                }

                app_ctx->total_files_extracted += ctx.files_extracted;
                app_ctx->total_bytes_extracted += ctx.extracted_bytes;

                if (info.is_apm3 && ctx.pending_opt_count > 0) {
                    process_pending_opts(app_ctx, &ctx, output_dir);
                }

                ntfs_close(&ctx);
            }
            else {
                fprintf(stderr, "ntfs\n");
                ntfs_close(&ctx);
            }
        }
        else {
            fprintf(stderr, "ntfsi\n");
        }
    }
    else {
        extraction_success = extract_stream_fs(app_ctx, stream, output_dir, FS_NTFS,
                                               EXTRACT_F_ALLOW_VHD | EXTRACT_F_CHECK_DIFF_PARENT);
    }

    if (extraction_success) {
        result = ERR_OK;
    }

cleanup:
    if (file) fclose(file);
    free(read_buffer);
    free(stream);
    return result;
}

#ifdef PLATFORM_WINDOWS

static bool env_has_prefix(const WCHAR* env, const WCHAR* prefix) {
    while (*prefix) {
        if (*env != *prefix) return false;
        env++; prefix++;
    }
    return true;
}

static bool wchar_iequals(const WCHAR* a, const WCHAR* b) {
    while (*a && *b) {
        WCHAR ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
        a++; b++;
    }
    return *a == *b;
}

static bool get_parent_process_name(WCHAR* out_name, size_t max_chars) {
    out_name[0] = 0;

    PROCESS_BASIC_INFORMATION pbi;
    ULONG ret_len;
    #define NtCurrentProcess() ((HANDLE)(intptr_t)-1)
    NTSTATUS status = NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &ret_len);
    if (!NT_SUCCESS(status)) return false;

    uintptr_t parent_pid = pbi.InheritedFromUniqueProcessId;
    if (parent_pid == 0) return false;

    ULONG buf_size = 1024 * 1024;
    uint8_t* buf = NULL;

    #define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
    for (int attempt = 0; attempt < 3; attempt++) {
        buf = lib_malloc(buf_size);
        if (!buf) return false;

        status = NtQuerySystemInformation(SystemProcessInformation, buf, buf_size, &ret_len);
        if (NT_SUCCESS(status)) break;

        lib_free(buf);
        buf = NULL;

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            buf_size = ret_len + 65536;
        } else {
            return false;
        }
    }

    if (!buf) return false;

    SYSTEM_PROCESS_INFORMATION* proc = (SYSTEM_PROCESS_INFORMATION*)buf;
    bool found = false;

    while (1) {
        if (proc->UniqueProcessId == parent_pid && proc->ImageName.Buffer) {
            WCHAR* name = proc->ImageName.Buffer;
            WCHAR* last_slash = name;
            for (WCHAR* p = name; *p; p++) {
                if (*p == '\\' || *p == '/') last_slash = p + 1;
            }
            size_t i = 0;
            while (last_slash[i] && i < max_chars - 1) {
                out_name[i] = last_slash[i];
                i++;
            }
            out_name[i] = 0;
            found = true;
            break;
        }
        if (proc->NextEntryOffset == 0) break;
        proc = (SYSTEM_PROCESS_INFORMATION*)((uint8_t*)proc + proc->NextEntryOffset);
    }

    lib_free(buf);
    return found;
}

static bool from_explorer(void) {
    WCHAR parent_name[260];
    if (get_parent_process_name(parent_name, 260)) {
        static const WCHAR cmd[] = {'c','m','d','.','e','x','e',0};
        static const WCHAR powershell[] = {'p','o','w','e','r','s','h','e','l','l','.','e','x','e',0};
        static const WCHAR pwsh[] = {'p','w','s','h','.','e','x','e',0};
        static const WCHAR wt[] = {'W','i','n','d','o','w','s','T','e','r','m','i','n','a','l','.','e','x','e',0};
        static const WCHAR code[] = {'C','o','d','e','.','e','x','e',0};
        static const WCHAR conhost[] = {'c','o','n','h','o','s','t','.','e','x','e',0};

        if (wchar_iequals(parent_name, cmd)) return false;
        if (wchar_iequals(parent_name, powershell)) return false;
        if (wchar_iequals(parent_name, pwsh)) return false;
        if (wchar_iequals(parent_name, wt)) return false;
        if (wchar_iequals(parent_name, code)) return false;
        if (wchar_iequals(parent_name, conhost)) return false;

        static const WCHAR explorer[] = {'e','x','p','l','o','r','e','r','.','e','x','e',0};
        if (wchar_iequals(parent_name, explorer)) return true;
    }

    PEB* peb = lib_get_peb();
    RTL_USER_PROCESS_PARAMETERS* params = peb->ProcessParameters;
    WCHAR* env = params->Environment;
    if (!env) return true;

    static const WCHAR prompt[] = {'P','R','O','M','P','T','=',0};
    static const WCHAR wt_session[] = {'W','T','_','S','E','S','S','I','O','N','=',0};
    static const WCHAR term_prog[] = {'T','E','R','M','_','P','R','O','G','R','A','M','=',0};

    WCHAR* scan = env;
    while (*scan) {
        if (env_has_prefix(scan, prompt)) return false;
        if (env_has_prefix(scan, wt_session)) return false;
        if (env_has_prefix(scan, term_prog)) return false;
        while (*scan) scan++;
        scan++;
    }

    return true;
}

#else

static bool from_explorer(void) {
    return false;
}

#endif

static void show_usage(void) {
    puts("unsegaREBORN [flags] <files>\n-o dir -n -w -p parent -s -v -vn");
}

#ifdef PLATFORM_WINDOWS
__declspec(dllimport) NTSTATUS __stdcall NtDelayExecution(uint8_t Alertable, LARGE_INTEGER* DelayInterval);
#endif

static void wait_for_enter(void) {
#ifdef PLATFORM_WINDOWS
    extern HANDLE lib_stdin_handle;
    if (!lib_stdin_handle || lib_stdin_handle == INVALID_HANDLE_VALUE) return;

    char buf[16];
    IO_STATUS_BLOCK iosb = {0};
    NtReadFile(lib_stdin_handle, NULL, NULL, NULL, &iosb, buf, 1, NULL, NULL);
#else
    char c;
    lib_fread(&c, 1, 1, stdin);
#endif
}

static void show_info(void) {
    printf("unsegaREBORN %s\ndrag files or use flags\nkeys: keys.inc\nenter...", VERSION);
    fflush(stdout);
    wait_for_enter();
}

int lib_main(int argc, char** argv) {
    AppContext app_ctx = {0};
    app_ctx.extract_fs = true;
    app_ctx.start_time = time(NULL);

    int start_index = 1;

    if (argc < 2) {
        if (from_explorer()) {
            show_info();
        } else {
            show_usage();
        }
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-vn") == 0) {
            printf("unsegaREBORN %s\n", VERSION);
            return 0;
        }
        if (strcmp(argv[i], "-h") == 0) {
            show_usage();
            return 0;
        }
    }

    const char* input_files[256];
    int input_file_count = 0;

    for (int i = start_index; i < argc && input_file_count < 256; i++) {
        const char* a = argv[i];
        if (a[0] == '-') {
            if (strcmp(a, "-n") == 0) app_ctx.extract_fs = false;
            else if (strcmp(a, "-s") == 0) app_ctx.silent = true;
            else if (strcmp(a, "-v") == 0) app_ctx.verbose = true;
            else if (strcmp(a, "-w") == 0) app_ctx.write_intermediate = true;
            else if (strcmp(a, "-o") == 0 && i + 1 < argc) app_ctx.output_dir = argv[++i];
            else if (strcmp(a, "-p") == 0 && i + 1 < argc) app_ctx.parent_file = argv[++i];
            continue;
        }
        input_files[input_file_count++] = a;
    }

    if (input_file_count == 0) { fprintf(stderr, "no files\n"); return 1; }
    if (!key_any()) fprintf(stderr, "no keys\n");

    bool any_failed = false;
    for (int i = 0; i < input_file_count; ++i) {
        const char* file_path = input_files[i];
        if (do_file(&app_ctx, file_path) == ERR_OK) {
            if (app_ctx.extract_fs && app_ctx.output_filename) {
                const char* basename = get_basename(app_ctx.output_filename);

                char basename_no_ext[MAX_PATH_LENGTH];
                strncpy(basename_no_ext, basename, sizeof(basename_no_ext) - 1);
                basename_no_ext[sizeof(basename_no_ext) - 1] = '\0';
                strip_extension(basename_no_ext);

                char output_dir[MAX_PATH_LENGTH];
                if (app_ctx.output_dir) {
                    path_join(output_dir, sizeof(output_dir), app_ctx.output_dir, basename_no_ext);
                } else {
                    strncpy(output_dir, app_ctx.output_filename, sizeof(output_dir) - 1);
                    output_dir[sizeof(output_dir) - 1] = '\0';
                    strip_extension(output_dir);
                }

                FsType fs_type = strstr(app_ctx.output_filename, ".exfat") ? FS_EXFAT : FS_NTFS;
                extract_file_fs(&app_ctx, app_ctx.output_filename, output_dir, fs_type,
                                EXTRACT_F_ALLOW_VHD | EXTRACT_F_CHECK_DIFF_PARENT);

                free(app_ctx.output_filename);
                app_ctx.output_filename = NULL;
            }
        }
        else {
            fprintf(stderr, "fail:%s\n", file_path);
            any_failed = true;
        }
    }

    if (!app_ctx.silent && app_ctx.total_files_extracted > 0) {
        char size_buf[32];
        fmt_size(app_ctx.total_bytes_extracted, size_buf, sizeof(size_buf));
        printf("\n%llu files %s %ds\n",
            (unsigned long long)app_ctx.total_files_extracted, size_buf,
            (int)difftime(time(NULL), app_ctx.start_time));
    }

    if (app_ctx.output_filename) {
        free(app_ctx.output_filename);
    }

    return any_failed ? 1 : 0;
}
