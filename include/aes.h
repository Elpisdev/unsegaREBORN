#ifndef AES_H
#define AES_H

#include "lib.h"

#define AES_BLOCKLEN 16

typedef struct {
    uint8_t round_keys[176] __attribute__((aligned(16)));
    uint8_t dec_keys[160] __attribute__((aligned(16)));
    uint8_t iv[16] __attribute__((aligned(16)));
} AES_ctx;

void AES_init_ctx_iv(AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(AES_ctx* ctx, const uint8_t* iv);
void AES_CBC_decrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t len);
void AES_CBC_encrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t len);
int aes_hw_supported(void);

#endif
