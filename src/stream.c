#include "stream.h"
#include "crypto.h"
#include "common.h"
#include "ntfs.h"

static bool read_from_runs_internal(void* ntfs_ctx, const DataRun* runs, int run_count,
                                    uint64_t file_size, uint64_t read_offset, void* buffer, size_t read_size);

bool stream_init(DecryptStream* ds, FILE* fp, uint64_t data_offset,
                 uint64_t data_size, const uint8_t key[16], const uint8_t iv[16]) {
    if (!ds || !fp) return false;

    memset(ds, 0, sizeof(DecryptStream));
    ds->fp = fp;
    ds->parent_stream = NULL;
    ds->run_source = NULL;
    ds->data_offset = data_offset;
    ds->data_size = data_size;
    memcpy(ds->key, key, 16);
    memcpy(ds->file_iv, iv, 16);
    ds->cached_page_offset = (uint64_t)-1;
    ds->file_pos = (uint64_t)-1;

    AES_init_ctx_iv(&ds->aes_ctx, key, iv);

    return true;
}

bool stream_init_from_runs(DecryptStream* ds, RunSource* source,
                           const uint8_t key[16], const uint8_t iv[16]) {
    if (!ds || !source) return false;

    memset(ds, 0, sizeof(DecryptStream));
    ds->fp = NULL;
    ds->parent_stream = NULL;
    ds->run_source = source;
    ds->data_offset = 0;
    ds->data_size = source->file_size;
    memcpy(ds->key, key, 16);
    memcpy(ds->file_iv, iv, 16);
    ds->cached_page_offset = (uint64_t)-1;
    ds->file_pos = (uint64_t)-1;

    AES_init_ctx_iv(&ds->aes_ctx, key, iv);

    return true;
}

static bool read_from_runs_internal(void* ntfs_ctx, const DataRun* runs, int run_count,
                                    uint64_t file_size, uint64_t read_offset, void* buffer, size_t read_size) {
    if (read_offset + read_size > file_size) {
        return false;
    }

    NTFSContext* ctx = (NTFSContext*)ntfs_ctx;
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

            if (!stream_read(ctx->stream, out, disk_offset, chunk_size)) {
                return false;
            }

            out += chunk_size;
            bytes_remaining -= chunk_size;
        }

        current_file_pos = run_end;
    }

    return bytes_remaining == 0;
}

bool stream_read_raw(void* ntfs_ctx, const DataRun* runs, int run_count,
                     uint64_t file_size, uint64_t offset, void* buffer, size_t size) {
    return read_from_runs_internal(ntfs_ctx, runs, run_count, file_size, offset, buffer, size);
}

bool stream_read(DecryptStream* ds, void* buffer, uint64_t offset, size_t size) {
    if (!ds || !buffer || size == 0) return false;
    if (offset > ds->data_size) return false;
    if ((uint64_t)size > ds->data_size - offset) return false;

    uint8_t* out = (uint8_t*)buffer;
    size_t bytes_read = 0;

    while (bytes_read < size) {
        uint64_t current_offset = offset + bytes_read;
        uint64_t page_offset = (current_offset / DECRYPT_PAGE_SIZE) * DECRYPT_PAGE_SIZE;
        size_t offset_in_page = (size_t)(current_offset % DECRYPT_PAGE_SIZE);

        if (ds->cached_page_offset != page_offset) {
            size_t page_bytes_available = (size_t)(ds->data_size - page_offset);
            size_t read_size = (page_bytes_available > DECRYPT_PAGE_SIZE)
                             ? DECRYPT_PAGE_SIZE : page_bytes_available;

            if (ds->parent_stream) {
                if (!stream_read(ds->parent_stream, ds->page_buffer, page_offset, read_size)) {
                    return false;
                }
            } else if (ds->run_source) {
                uint64_t run_offset = ds->data_offset + page_offset;
                if (!read_from_runs_internal(ds->run_source->ntfs_ctx, ds->run_source->runs,
                    ds->run_source->run_count, ds->run_source->file_size,
                    run_offset, ds->page_buffer, read_size)) {
                    return false;
                }
            } else {
                uint64_t file_pos_wanted = ds->data_offset + page_offset;
                if (ds->file_pos != file_pos_wanted) {
                    if (FSEEKO(ds->fp, file_pos_wanted, SEEK_SET) != 0) return false;
                }
                if (fread(ds->page_buffer, 1, read_size, ds->fp) != read_size) return false;
                ds->file_pos = file_pos_wanted + read_size;
            }

            if (read_size < DECRYPT_PAGE_SIZE) {
                memset(ds->page_buffer + read_size, 0, DECRYPT_PAGE_SIZE - read_size);
            }

            uint8_t page_iv[16];
            iv_page(page_offset, ds->file_iv, page_iv);

            AES_ctx_set_iv(&ds->aes_ctx, page_iv);
            AES_CBC_decrypt_buffer(&ds->aes_ctx, ds->page_buffer, DECRYPT_PAGE_SIZE);

            ds->cached_page_offset = page_offset;
        }

        size_t bytes_in_page = DECRYPT_PAGE_SIZE - offset_in_page;
        size_t bytes_remaining = size - bytes_read;
        size_t copy_size = (bytes_in_page < bytes_remaining) ? bytes_in_page : bytes_remaining;

        uint64_t max_valid = ds->data_size - current_offset;
        if (copy_size > max_valid) copy_size = (size_t)max_valid;

        memcpy(out + bytes_read, ds->page_buffer + offset_in_page, copy_size);
        bytes_read += copy_size;

        if (copy_size == 0) break;
    }

    return bytes_read == size;
}
