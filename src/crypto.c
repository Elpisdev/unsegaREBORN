#include "crypto.h"
#include "common.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

void calculate_page_iv(uint64_t file_offset, const uint8_t* file_iv, uint8_t* page_iv) {
    for (int i = 0; i < 16; i++) {
        page_iv[i] = file_iv[i] ^ ((file_offset >> (8 * (i % 8))) & 0xFF);
    }
}

bool calculate_file_iv(
    const uint8_t key[16],
    const uint8_t expected_header[16],
    const uint8_t* first_page,
    uint8_t out_iv[16]
) {
    uint8_t iv[16];
    uint8_t header[16];
    memcpy(header, first_page, 16);

    calculate_page_iv(0, expected_header, iv);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    int len;
    int plaintext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    uint8_t decrypted[16];

    if (1 != EVP_DecryptUpdate(ctx, decrypted, &len, header, 16)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, decrypted + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    if (plaintext_len != 16)
        return false;

    memcpy(out_iv, decrypted, 16);

    return true;
}

bool get_game_keys(const char* game_id, GameKeys* out_keys) {
    const GameKeyEntry* entry = game_keys;
    while (entry->game_id != NULL) {
        if (strcmp(entry->game_id, game_id) == 0) {
            memcpy(out_keys->key, entry->key, 16);
            if (entry->has_iv) {
                memcpy(out_keys->iv, entry->iv, 16);
                out_keys->has_iv = true;
            }
            else {
                memset(out_keys->iv, 0, 16);
                out_keys->has_iv = false;
            }
            return true;
        }
        entry++;
    }

    char filename[256];
    SNPRINTF(filename, sizeof(filename), "%s.bin", game_id);

    FILE* file = fopen(filename, "rb");
    if (!file) {
        return false;
    }

    uint8_t buffer[32];
    size_t read_size = fread(buffer, 1, sizeof(buffer), file);
    fclose(file);

    if (read_size == 16) {
        memcpy(out_keys->key, buffer, 16);
        memset(out_keys->iv, 0, 16);
        out_keys->has_iv = false;
        return true;
    }
    else if (read_size == 32) {
        memcpy(out_keys->key, buffer, 16);
        memcpy(out_keys->iv, buffer + 16, 16);

        if (memcmp(out_keys->iv, NTFS_HEADER, 16) == 0 || memcmp(out_keys->iv, EXFAT_HEADER, 16) == 0) {
            out_keys->has_iv = false;
        }
        else {
            out_keys->has_iv = true;
        }
        return true;
    }
    else {
        return false;
    }
}