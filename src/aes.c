#include "aes.h"

#if defined(__x86_64__) || defined(_M_X64)
#define AES_HW_AVAILABLE 1
#else
#define AES_HW_AVAILABLE 0
int aes_hw_supported(void) { return 0; }
#endif

#if AES_HW_AVAILABLE
static int aes_hw_checked = 0;
static int aes_hw_available = 0;

__attribute__((noinline))
int aes_hw_supported(void) {
    if (!aes_hw_checked) {
        unsigned int eax, ecx;
        __asm__ volatile ("cpuid" : "=a"(eax), "=c"(ecx) : "a"(1), "c"(0) : "ebx", "edx");
        aes_hw_available = (ecx & (1 << 25)) != 0;
        aes_hw_checked = 1;
    }
    return aes_hw_available;
}

__attribute__((noinline))
static void aes_hw_key_expand(AES_ctx* ctx, const uint8_t* key) {
    __asm__ volatile (
        "movdqu (%[key]), %%xmm0\n\t"
        "movdqa %%xmm0, (%[rk])\n\t"
#define KEYGEN(r, rc) \
        "aeskeygenassist $" #rc ", %%xmm0, %%xmm1\n\t" \
        "pshufd $0xff, %%xmm1, %%xmm1\n\t" \
        "movdqa %%xmm0, %%xmm2\n\t" \
        "pslldq $4, %%xmm2\n\t" "pxor %%xmm2, %%xmm0\n\t" \
        "pslldq $4, %%xmm2\n\t" "pxor %%xmm2, %%xmm0\n\t" \
        "pslldq $4, %%xmm2\n\t" "pxor %%xmm2, %%xmm0\n\t" \
        "pxor %%xmm1, %%xmm0\n\t" \
        "movdqa %%xmm0, " #r "*16(%[rk])\n\t"
        KEYGEN(1,0x01) KEYGEN(2,0x02) KEYGEN(3,0x04) KEYGEN(4,0x08)
        KEYGEN(5,0x10) KEYGEN(6,0x20) KEYGEN(7,0x40) KEYGEN(8,0x80)
        KEYGEN(9,0x1b) KEYGEN(10,0x36)
#undef KEYGEN
        : : [key] "r" (key), [rk] "r" (ctx->round_keys)
        : "xmm0", "xmm1", "xmm2", "memory"
    );
    __asm__ volatile (
#define INVKEY(s, d) \
        "movdqa " #s "*16(%[rk]), %%xmm0\n\t" \
        "aesimc %%xmm0, %%xmm0\n\t" \
        "movdqa %%xmm0, " #d "*16(%[dk])\n\t"
        INVKEY(1,0) INVKEY(2,1) INVKEY(3,2) INVKEY(4,3) INVKEY(5,4)
        INVKEY(6,5) INVKEY(7,6) INVKEY(8,7) INVKEY(9,8)
#undef INVKEY
        : : [rk] "r" (ctx->round_keys), [dk] "r" (ctx->dec_keys)
        : "xmm0", "memory"
    );
}

__attribute__((noinline))
static void aes_hw_cbc_decrypt(AES_ctx* ctx, uint8_t* buf, size_t len) {
    size_t blocks = len >> 4;
    if (!blocks) return;

    __asm__ volatile (
        "movdqa (%[rk]), %%xmm15\n\t"
        "movdqa 160(%[rk]), %%xmm14\n\t"
        "movdqa (%[dk]), %%xmm13\n\t"
        "movdqu (%[iv]), %%xmm12\n\t"
        "cmpq $8, %[n]\n\t"
        "jb 2f\n\t"
        ".p2align 4\n"
        "1:\n\t"
        "movdqu (%[buf]), %%xmm0\n\t"
        "movdqu 16(%[buf]), %%xmm1\n\t"
        "movdqu 32(%[buf]), %%xmm2\n\t"
        "movdqu 48(%[buf]), %%xmm3\n\t"
        "movdqu 64(%[buf]), %%xmm4\n\t"
        "movdqu 80(%[buf]), %%xmm5\n\t"
        "movdqu 96(%[buf]), %%xmm6\n\t"
        "movdqu 112(%[buf]), %%xmm7\n\t"
        "movdqa %%xmm7, %%xmm11\n\t"
        "pxor %%xmm14, %%xmm0\n\t"
        "pxor %%xmm14, %%xmm1\n\t"
        "pxor %%xmm14, %%xmm2\n\t"
        "pxor %%xmm14, %%xmm3\n\t"
        "pxor %%xmm14, %%xmm4\n\t"
        "pxor %%xmm14, %%xmm5\n\t"
        "pxor %%xmm14, %%xmm6\n\t"
        "pxor %%xmm14, %%xmm7\n\t"
#define DR(off) \
        "movdqa " #off "(%[dk]), %%xmm10\n\t" \
        "aesdec %%xmm10, %%xmm0\n\t" \
        "aesdec %%xmm10, %%xmm1\n\t" \
        "aesdec %%xmm10, %%xmm2\n\t" \
        "aesdec %%xmm10, %%xmm3\n\t" \
        "aesdec %%xmm10, %%xmm4\n\t" \
        "aesdec %%xmm10, %%xmm5\n\t" \
        "aesdec %%xmm10, %%xmm6\n\t" \
        "aesdec %%xmm10, %%xmm7\n\t"
        DR(128) DR(112) DR(96) DR(80) DR(64) DR(48) DR(32) DR(16)
#undef DR
        "aesdec %%xmm13, %%xmm0\n\t"
        "aesdec %%xmm13, %%xmm1\n\t"
        "aesdec %%xmm13, %%xmm2\n\t"
        "aesdec %%xmm13, %%xmm3\n\t"
        "aesdec %%xmm13, %%xmm4\n\t"
        "aesdec %%xmm13, %%xmm5\n\t"
        "aesdec %%xmm13, %%xmm6\n\t"
        "aesdec %%xmm13, %%xmm7\n\t"
        "aesdeclast %%xmm15, %%xmm0\n\t"
        "aesdeclast %%xmm15, %%xmm1\n\t"
        "aesdeclast %%xmm15, %%xmm2\n\t"
        "aesdeclast %%xmm15, %%xmm3\n\t"
        "aesdeclast %%xmm15, %%xmm4\n\t"
        "aesdeclast %%xmm15, %%xmm5\n\t"
        "aesdeclast %%xmm15, %%xmm6\n\t"
        "aesdeclast %%xmm15, %%xmm7\n\t"
        "pxor %%xmm12, %%xmm0\n\t"
        "movdqu (%[buf]), %%xmm12\n\t"
        "pxor %%xmm12, %%xmm1\n\t"
        "movdqu 16(%[buf]), %%xmm12\n\t"
        "pxor %%xmm12, %%xmm2\n\t"
        "movdqu 32(%[buf]), %%xmm12\n\t"
        "pxor %%xmm12, %%xmm3\n\t"
        "movdqu 48(%[buf]), %%xmm12\n\t"
        "pxor %%xmm12, %%xmm4\n\t"
        "movdqu 64(%[buf]), %%xmm12\n\t"
        "pxor %%xmm12, %%xmm5\n\t"
        "movdqu 80(%[buf]), %%xmm12\n\t"
        "pxor %%xmm12, %%xmm6\n\t"
        "movdqu 96(%[buf]), %%xmm12\n\t"
        "pxor %%xmm12, %%xmm7\n\t"
        "movdqu %%xmm0, (%[buf])\n\t"
        "movdqu %%xmm1, 16(%[buf])\n\t"
        "movdqu %%xmm2, 32(%[buf])\n\t"
        "movdqu %%xmm3, 48(%[buf])\n\t"
        "movdqu %%xmm4, 64(%[buf])\n\t"
        "movdqu %%xmm5, 80(%[buf])\n\t"
        "movdqu %%xmm6, 96(%[buf])\n\t"
        "movdqu %%xmm7, 112(%[buf])\n\t"
        "movdqa %%xmm11, %%xmm12\n\t"
        "addq $128, %[buf]\n\t"
        "subq $8, %[n]\n\t"
        "cmpq $8, %[n]\n\t"
        "jae 1b\n\t"
        "2:\n\t"
        "testq %[n], %[n]\n\t"
        "jz 4f\n\t"
        "3:\n\t"
        "movdqu (%[buf]), %%xmm0\n\t"
        "movdqa %%xmm0, %%xmm1\n\t"
        "pxor %%xmm14, %%xmm0\n\t"
        "aesdec 128(%[dk]), %%xmm0\n\t"
        "aesdec 112(%[dk]), %%xmm0\n\t"
        "aesdec 96(%[dk]), %%xmm0\n\t"
        "aesdec 80(%[dk]), %%xmm0\n\t"
        "aesdec 64(%[dk]), %%xmm0\n\t"
        "aesdec 48(%[dk]), %%xmm0\n\t"
        "aesdec 32(%[dk]), %%xmm0\n\t"
        "aesdec 16(%[dk]), %%xmm0\n\t"
        "aesdec %%xmm13, %%xmm0\n\t"
        "aesdeclast %%xmm15, %%xmm0\n\t"
        "pxor %%xmm12, %%xmm0\n\t"
        "movdqa %%xmm1, %%xmm12\n\t"
        "movdqu %%xmm0, (%[buf])\n\t"
        "addq $16, %[buf]\n\t"
        "decq %[n]\n\t"
        "jnz 3b\n\t"
        "4:\n\t"
        "movdqu %%xmm12, (%[iv])\n\t"
        : [buf] "+r" (buf), [n] "+r" (blocks)
        : [rk] "r" (ctx->round_keys), [dk] "r" (ctx->dec_keys), [iv] "r" (ctx->iv)
        : "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
          "xmm10","xmm11","xmm12","xmm13","xmm14","xmm15","memory","cc"
    );
}

__attribute__((noinline))
static void aes_hw_cbc_encrypt(AES_ctx* ctx, uint8_t* buf, size_t len) {
    size_t blocks = len >> 4;
    if (!blocks) return;

    __asm__ volatile (
        "movdqa (%[rk]), %%xmm2\n\t"
        "movdqu (%[iv]), %%xmm0\n\t"
        ".p2align 4\n"
        "1:\n\t"
        "movdqu (%[buf]), %%xmm1\n\t"
        "pxor %%xmm0, %%xmm1\n\t"
        "pxor %%xmm2, %%xmm1\n\t"
        "aesenc 16(%[rk]), %%xmm1\n\t"
        "aesenc 32(%[rk]), %%xmm1\n\t"
        "aesenc 48(%[rk]), %%xmm1\n\t"
        "aesenc 64(%[rk]), %%xmm1\n\t"
        "aesenc 80(%[rk]), %%xmm1\n\t"
        "aesenc 96(%[rk]), %%xmm1\n\t"
        "aesenc 112(%[rk]), %%xmm1\n\t"
        "aesenc 128(%[rk]), %%xmm1\n\t"
        "aesenc 144(%[rk]), %%xmm1\n\t"
        "aesenclast 160(%[rk]), %%xmm1\n\t"
        "movdqu %%xmm1, (%[buf])\n\t"
        "movdqa %%xmm1, %%xmm0\n\t"
        "addq $16, %[buf]\n\t"
        "decq %[n]\n\t"
        "jnz 1b\n\t"
        "movdqu %%xmm0, (%[iv])\n\t"
        : [buf] "+r" (buf), [n] "+r" (blocks)
        : [rk] "r" (ctx->round_keys), [iv] "r" (ctx->iv)
        : "xmm0", "xmm1", "xmm2", "memory", "cc"
    );
}
#endif

void AES_init_ctx_iv(AES_ctx* ctx, const uint8_t* key, const uint8_t* iv) {
    aes_hw_key_expand(ctx, key);
    for (int i = 0; i < 16; ++i) ctx->iv[i] = iv[i];
}

void AES_ctx_set_iv(AES_ctx* ctx, const uint8_t* iv) {
    for (int i = 0; i < 16; ++i) ctx->iv[i] = iv[i];
}

void AES_CBC_decrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t len) {
    aes_hw_cbc_decrypt(ctx, buf, len);
}

void AES_CBC_encrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t len) {
    aes_hw_cbc_encrypt(ctx, buf, len);
}
