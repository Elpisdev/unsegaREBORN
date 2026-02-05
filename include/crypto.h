#ifndef CRYPTO_H
#define CRYPTO_H

#include "lib.h"

extern const uint8_t NTFS_HEADER[16];
extern const uint8_t EXFAT_HEADER[16];
extern const uint8_t OPTION_KEY[16];
extern const uint8_t OPTION_IV[16];
extern const uint8_t APM3_SEED[96];
extern const uint8_t APM3_KEY[16];
extern const uint8_t APM3_IV[16];

typedef struct {
    uint8_t key[16];
    uint8_t iv[16];
    bool has_iv;
    bool external;
} GameKeys;

typedef struct {
    const char* game_id;
    uint8_t key[16];
    uint8_t iv[16];
    bool has_iv;
} GameKeyEntry;

bool key_lookup(const char* id, uint8_t key[16], uint8_t iv[16], bool* from_external);
bool key_any(void);
void iv_page(uint64_t off, const uint8_t* base, uint8_t* out);
bool iv_file(const uint8_t key[16], const uint8_t* hdr, const uint8_t* page, uint8_t out[16]);
bool key_game(const char* id, GameKeys* out);
bool key_derive(const char* id, uint8_t key[16], uint8_t iv[16]);

#endif