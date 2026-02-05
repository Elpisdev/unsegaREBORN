#ifndef STREAM_H
#define STREAM_H

#include "lib.h"
#include "aes.h"

#define DECRYPT_PAGE_SIZE 4096
#define MAX_DATA_RUNS 256

typedef struct {
    uint64_t offset;
    uint64_t length;
} DataRun;

typedef struct {
    void* ntfs_ctx;
    DataRun runs[MAX_DATA_RUNS];
    int run_count;
    uint64_t file_size;
} RunSource;

typedef struct DecryptStream DecryptStream;

struct DecryptStream {
    FILE* fp;
    DecryptStream* parent_stream;
    RunSource* run_source;
    uint64_t data_offset;
    uint64_t data_size;
    uint8_t key[16];
    uint8_t file_iv[16];
    uint8_t page_buffer[DECRYPT_PAGE_SIZE];
    uint64_t cached_page_offset;
    uint64_t file_pos;
    AES_ctx aes_ctx;
};

bool stream_init(DecryptStream* ds, FILE* fp, uint64_t data_offset,
                 uint64_t data_size, const uint8_t key[16], const uint8_t iv[16]);
bool stream_init_from_runs(DecryptStream* ds, RunSource* source,
                           const uint8_t key[16], const uint8_t iv[16]);
bool stream_read(DecryptStream* ds, void* buffer, uint64_t offset, size_t size);
bool stream_read_raw(void* ntfs_ctx, const DataRun* runs, int run_count,
                     uint64_t file_size, uint64_t offset, void* buffer, size_t size);

#endif
