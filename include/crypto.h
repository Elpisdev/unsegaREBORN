#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stdbool.h>

static const uint8_t NTFS_HEADER[16] = {
    0xeb, 0x52, 0x90, 0x4e, 0x54, 0x46, 0x53, 0x20,
    0x20, 0x20, 0x20, 0x00, 0x10, 0x01, 0x00, 0x00
};

static const uint8_t EXFAT_HEADER[16] = {
    0xeb, 0x76, 0x90, 0x45, 0x58, 0x46, 0x41, 0x54,
    0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t OPTION_KEY[16] = {
    0x5c, 0x84, 0xa9, 0xe7, 0x26, 0xea, 0xa5, 0xdd,
    0x35, 0x1f, 0x2b, 0x07, 0x50, 0xc2, 0x36, 0x97
};

static const uint8_t OPTION_IV[16] = {
    0xc0, 0x63, 0xbf, 0x6f, 0x56, 0x2d, 0x08, 0x4d,
    0x79, 0x63, 0xc9, 0x87, 0xf5, 0x28, 0x17, 0x61
};

typedef struct {
    uint8_t key[16];
    uint8_t iv[16];
    bool has_iv;
} GameKeys;

typedef struct {
    const char* game_id;
    uint8_t key[16];
    uint8_t iv[16];
    bool has_iv;
} GameKeyEntry;

extern const GameKeyEntry game_keys[];
extern const size_t game_keys_count;

void calculate_page_iv(uint64_t file_offset, const uint8_t* file_iv, uint8_t* page_iv);

bool calculate_file_iv(
    const uint8_t key[16],
    const uint8_t expected_header[16],
    const uint8_t* first_page,
    uint8_t out_iv[16]
);

bool get_game_keys(const char* game_id, GameKeys* out_keys);

#endif // CRYPTO_H