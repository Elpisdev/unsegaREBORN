#include "crypto.h"
#include "common.h"

typedef struct {
    char game_id[8];
    uint8_t key[16];
    uint8_t iv[16];
} ExternalKey;

static ExternalKey* external_keys;
static size_t external_keys_count;
static size_t external_keys_cap;
static bool external_keys_loaded;

#include "keys.h"

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_hex_bytes(const char* start, const char* end, uint8_t* out, size_t count) {
    size_t idx = 0;
    const char* p = start;
    while (p < end && idx < count) {
        while (p < end && !isxdigit(*p)) p++;
        if (p >= end) break;
        int hi = hex_val(*p++);
        while (p < end && !isxdigit(*p)) p++;
        if (p >= end) break;
        int lo = hex_val(*p++);
        if (hi < 0 || lo < 0) return false;
        out[idx++] = (hi << 4) | lo;
    }
    return idx == count;
}

static void load_keys_from_file(const char* path) {
    FILE* f = FOPEN(path, "r");
    if (!f) return;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* start = strchr(line, '{');
        if (!start) continue;

        char* quote1 = strchr(start, '"');
        if (!quote1) continue;
        char* quote2 = strchr(quote1 + 1, '"');
        if (!quote2) continue;

        size_t id_len = quote2 - quote1 - 1;
        if (id_len == 0 || id_len > 7) continue;

        char* brace1 = strchr(quote2, '{');
        if (!brace1) continue;
        char* brace1_end = strchr(brace1, '}');
        if (!brace1_end) continue;

        char* brace2 = strchr(brace1_end, '{');
        if (!brace2) continue;
        char* brace2_end = strchr(brace2, '}');
        if (!brace2_end) continue;

        if (external_keys_count >= external_keys_cap) {
            size_t new_cap = external_keys_cap ? external_keys_cap * 2 : 8;
            ExternalKey* new_keys = realloc(external_keys, new_cap * sizeof(ExternalKey));
            if (!new_keys) break;
            external_keys = new_keys;
            external_keys_cap = new_cap;
        }

        ExternalKey* k = &external_keys[external_keys_count];
        memset(k, 0, sizeof(*k));
        memcpy(k->game_id, quote1 + 1, id_len);

        if (!parse_hex_bytes(brace1, brace1_end, k->key, 16)) continue;
        if (!parse_hex_bytes(brace2, brace2_end, k->iv, 16)) continue;

        external_keys_count++;
    }
    fclose(f);
}

static void try_load_external_keys(void) {
    if (external_keys_loaded) return;
    external_keys_loaded = true;
    load_keys_from_file("keys.inc");
}

static size_t count_embedded_keys(void) {
    size_t count = 0;
    const GameKeyEntry* entry = embedded_keys;
    while (entry->game_id != NULL) { count++; entry++; }
    return count;
}

bool key_any(void) {
    try_load_external_keys();
    return count_embedded_keys() > 0 || external_keys_count > 0;
}

bool key_lookup(const char* id, uint8_t out_key[16], uint8_t out_iv[16], bool* from_external) {
    try_load_external_keys();
    if (from_external) *from_external = false;

    for (size_t i = 0; i < external_keys_count; i++) {
        if (strcmp(external_keys[i].game_id, id) == 0) {
            memcpy(out_key, external_keys[i].key, 16);
            memcpy(out_iv, external_keys[i].iv, 16);
            if (from_external) *from_external = true;
            return true;
        }
    }

    const GameKeyEntry* entry = embedded_keys;
    while (entry->game_id != NULL) {
        if (strcmp(entry->game_id, id) == 0) {
            memcpy(out_key, entry->key, 16);
            memcpy(out_iv, entry->iv, 16);
            return true;
        }
        entry++;
    }

    return false;
}
