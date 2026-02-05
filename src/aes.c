#include "aes.h"

const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

const uint8_t aes_rcon[11] = {0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static uint8_t aes_rsbox[256];
static int aes_rsbox_init;

static void aes_init_rsbox(void) {
    if (aes_rsbox_init) return;
    for (int i = 0; i < 256; i++) aes_rsbox[aes_sbox[i]] = (uint8_t)i;
    aes_rsbox_init = 1;
}

#define xtime(x) ((((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b)) & 0xff)
#define mul(a,b) ((((b)&1)*a) ^ (((b>>1)&1)*xtime(a)) ^ (((b>>2)&1)*xtime(xtime(a))) ^ (((b>>3)&1)*xtime(xtime(xtime(a)))))

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
#endif

static void aes_sw_key_expand(uint8_t* rk, const uint8_t* key) {
    uint8_t t[4];
    for (int i = 0; i < 16; ++i) rk[i] = key[i];
    for (int i = 4; i < 44; ++i) {
        int k = (i - 1) << 2;
        t[0] = rk[k]; t[1] = rk[k+1]; t[2] = rk[k+2]; t[3] = rk[k+3];
        if ((i & 3) == 0) {
            uint8_t tmp = t[0];
            t[0] = aes_sbox[t[1]] ^ aes_rcon[i >> 2];
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[tmp];
        }
        int j = i << 2; k = (i - 4) << 2;
        rk[j] = rk[k] ^ t[0]; rk[j+1] = rk[k+1] ^ t[1];
        rk[j+2] = rk[k+2] ^ t[2]; rk[j+3] = rk[k+3] ^ t[3];
    }
}

static void aes_sw_decrypt_block(uint8_t* s, const uint8_t* rk) {
    uint8_t t;
    for (int i = 0; i < 16; ++i) s[i] ^= rk[160+i];
    for (int r = 9; r >= 0; --r) {
        t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
        t = s[2]; s[2] = s[10]; s[10] = t;
        t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
        for (int i = 0; i < 16; ++i) s[i] = aes_rsbox[s[i]];
        for (int i = 0; i < 16; ++i) s[i] ^= rk[(r<<4)+i];
        if (r == 0) break;
        for (int i = 0; i < 4; ++i) {
            int j = i << 2;
            uint8_t a = s[j], b = s[j+1], c = s[j+2], d = s[j+3];
            s[j]   = mul(a,0x0e) ^ mul(b,0x0b) ^ mul(c,0x0d) ^ mul(d,0x09);
            s[j+1] = mul(a,0x09) ^ mul(b,0x0e) ^ mul(c,0x0b) ^ mul(d,0x0d);
            s[j+2] = mul(a,0x0d) ^ mul(b,0x09) ^ mul(c,0x0e) ^ mul(d,0x0b);
            s[j+3] = mul(a,0x0b) ^ mul(b,0x0d) ^ mul(c,0x09) ^ mul(d,0x0e);
        }
    }
}

static void aes_sw_cbc_decrypt(AES_ctx* ctx, uint8_t* buf, size_t len) {
    uint8_t tmp[16], niv[16];
    for (size_t i = 0; i < len; i += 16) {
        for (int j = 0; j < 16; ++j) { niv[j] = buf[i+j]; tmp[j] = buf[i+j]; }
        aes_sw_decrypt_block(tmp, ctx->round_keys);
        for (int j = 0; j < 16; ++j) buf[i+j] = tmp[j] ^ ctx->iv[j];
        for (int j = 0; j < 16; ++j) ctx->iv[j] = niv[j];
    }
}

static void aes_sw_encrypt_block(uint8_t* s, const uint8_t* rk) {
    uint8_t t;
    for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
    for (int r = 1; ; ++r) {
        for (int i = 0; i < 16; ++i) s[i] = aes_sbox[s[i]];
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t;
        t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
        if (r == 10) { for (int i = 0; i < 16; ++i) s[i] ^= rk[(r<<4)+i]; break; }
        for (int i = 0; i < 4; ++i) {
            int j = i << 2;
            uint8_t a = s[j], b = s[j+1], c = s[j+2], d = s[j+3];
            s[j]   = xtime(a) ^ xtime(b) ^ b ^ c ^ d;
            s[j+1] = a ^ xtime(b) ^ xtime(c) ^ c ^ d;
            s[j+2] = a ^ b ^ xtime(c) ^ xtime(d) ^ d;
            s[j+3] = xtime(a) ^ a ^ b ^ c ^ xtime(d);
        }
        for (int i = 0; i < 16; ++i) s[i] ^= rk[(r<<4)+i];
    }
}

static void aes_sw_cbc_encrypt(AES_ctx* ctx, uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        for (int j = 0; j < 16; ++j) buf[i+j] ^= ctx->iv[j];
        aes_sw_encrypt_block(buf + i, ctx->round_keys);
        for (int j = 0; j < 16; ++j) ctx->iv[j] = buf[i+j];
    }
}

void AES_init_ctx_iv(AES_ctx* ctx, const uint8_t* key, const uint8_t* iv) {
    aes_init_rsbox();
#if AES_HW_AVAILABLE
    if (aes_hw_supported()) {
        aes_hw_key_expand(ctx, key);
    } else
#endif
    {
        aes_sw_key_expand(ctx->round_keys, key);
    }
    for (int i = 0; i < 16; ++i) ctx->iv[i] = iv[i];
}

void AES_ctx_set_iv(AES_ctx* ctx, const uint8_t* iv) {
    for (int i = 0; i < 16; ++i) ctx->iv[i] = iv[i];
}

void AES_CBC_decrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t len) {
#if AES_HW_AVAILABLE
    if (aes_hw_supported()) { aes_hw_cbc_decrypt(ctx, buf, len); return; }
#endif
    aes_sw_cbc_decrypt(ctx, buf, len);
}

void AES_CBC_encrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t len) {
    aes_sw_cbc_encrypt(ctx, buf, len);
}
