#ifndef COMMON_H
#define COMMON_H

#include "lib.h"

#define FSEEKO fseeko
#define FTELLO ftello

#ifdef PLATFORM_WINDOWS

static inline int utf8_to_wide(const char* utf8, WCHAR* wide, int wide_len) {
    if (!utf8 || !wide || wide_len <= 0) return 0;
    int out = 0;
    const unsigned char* s = (const unsigned char*)utf8;
    while (*s && out < wide_len - 1) {
        uint32_t cp;
        if (s[0] < 0x80) { cp = s[0]; s += 1; }
        else if ((s[0] & 0xE0) == 0xC0 && (s[1] & 0xC0) == 0x80) { cp = ((s[0] & 0x1F) << 6) | (s[1] & 0x3F); s += 2; }
        else if ((s[0] & 0xF0) == 0xE0 && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80) { cp = ((s[0] & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F); s += 3; }
        else if ((s[0] & 0xF8) == 0xF0 && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80) { cp = ((s[0] & 0x07) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F); s += 4; }
        else { cp = '?'; s += 1; }
        if (cp <= 0xFFFF) wide[out++] = (WCHAR)cp;
        else if (cp <= 0x10FFFF && out < wide_len - 2) { cp -= 0x10000; wide[out++] = (WCHAR)(0xD800 | (cp >> 10)); wide[out++] = (WCHAR)(0xDC00 | (cp & 0x3FF)); }
    }
    wide[out] = 0;
    return out;
}

static inline FILE* fopen_utf8(const char* path, const char* mode) {
    return fopen(path, mode);
}

static inline FILE* fopen_prealloc_utf8(const char* path, uint64_t size) {
    WCHAR wpath[1024];
    if (!utf8_to_wide(path, wpath, 1024)) return NULL;
    return lib_wfopen_prealloc(wpath, size);
}

static inline int mkdir_utf8(const char* path) {
    WCHAR wpath[1024];
    if (!utf8_to_wide(path, wpath, 1024)) return -1;
    return _wmkdir(wpath);
}

static inline int remove_utf8(const char* path) {
    WCHAR wpath[1024];
    if (!utf8_to_wide(path, wpath, 1024)) return -1;
    return _wremove(wpath);
}

#define FOPEN fopen_utf8
#define FOPEN_PREALLOC fopen_prealloc_utf8
#define FWRITE_DIRECT lib_fwrite_direct
#define MKDIR(path) mkdir_utf8(path)
#define REMOVE remove_utf8
#define RMDIR(path) _rmdir(path)

static inline bool set_file_times(const char* path, uint64_t modified_time, uint64_t access_time) {
    WCHAR wpath[1024];
    if (!utf8_to_wide(path, wpath, 1024)) return false;

    struct { int64_t actime; int64_t modtime; } times;
    times.modtime = (int64_t)((modified_time / 10000000ULL) - 11644473600ULL);
    times.actime = (int64_t)((access_time / 10000000ULL) - 11644473600ULL);
    return _wutime(wpath, &times) == 0;
}

static inline bool set_dir_times(const char* path, uint64_t modified_time, uint64_t access_time) {
    WCHAR wpath[1024];
    if (!utf8_to_wide(path, wpath, 1024)) return false;

    struct { int64_t actime; int64_t modtime; } times;
    times.modtime = (int64_t)((modified_time / 10000000ULL) - 11644473600ULL);
    times.actime = (int64_t)((access_time / 10000000ULL) - 11644473600ULL);
    return lib_wutime_dir(wpath, &times) == 0;
}

static inline bool set_file_times_handle(FILE* f, uint64_t modified_time, uint64_t access_time) {
    return lib_set_file_times_ntfs(f, (int64_t)modified_time, (int64_t)access_time);
}

#else

#define FOPEN fopen
#define FOPEN_PREALLOC(path, size) fopen(path, "wb")
#define FWRITE_DIRECT(f, buf, size) fwrite(buf, 1, size, f)
#define MKDIR(path) mkdir(path)
#define REMOVE remove
#define RMDIR(path) rmdir(path)

static inline bool set_file_times(const char* path, uint64_t modified_time, uint64_t access_time) {
    struct linux_timespec times[2];
    int64_t unix_mtime = (int64_t)((modified_time / 10000000ULL) - 11644473600ULL);
    int64_t unix_atime = (int64_t)((access_time / 10000000ULL) - 11644473600ULL);
    times[0].tv_sec = unix_atime;
    times[0].tv_nsec = (access_time % 10000000ULL) * 100;
    times[1].tv_sec = unix_mtime;
    times[1].tv_nsec = (modified_time % 10000000ULL) * 100;
    return syscall4(SYS_utimensat, AT_FDCWD, (long)path, (long)times, 0) == 0;
}

static inline bool set_dir_times(const char* path, uint64_t modified_time, uint64_t access_time) {
    return set_file_times(path, modified_time, access_time);
}

static inline bool set_file_times_handle(FILE* f, uint64_t modified_time, uint64_t access_time) {
    (void)f; (void)modified_time; (void)access_time;
    return true;
}

#endif

static inline uint64_t exfat_timestamp_to_ntfs(uint32_t exfat_ts, uint8_t centiseconds, int8_t utc_offset) {
    uint32_t second = (exfat_ts & 0x1F) * 2;
    uint32_t minute = (exfat_ts >> 5) & 0x3F;
    uint32_t hour = (exfat_ts >> 11) & 0x1F;
    uint32_t day = (exfat_ts >> 16) & 0x1F;
    uint32_t month = (exfat_ts >> 21) & 0x0F;
    uint32_t year = ((exfat_ts >> 25) & 0x7F) + 1980;

    uint64_t days = 0;
    for (uint32_t y = 1601; y < year; y++)
        days += (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 366 : 365;
    static const uint16_t month_days[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
    if (month >= 1 && month <= 12) {
        days += month_days[month - 1];
        if (month > 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))) days += 1;
    }
    days += day - 1;

    uint64_t intervals = days * 24ULL * 60 * 60 * 10000000ULL;
    intervals += hour * 60ULL * 60 * 10000000ULL;
    intervals += minute * 60ULL * 10000000ULL;
    intervals += second * 10000000ULL;
    intervals += centiseconds * 100000ULL;

    int64_t offset_seconds = (int64_t)utc_offset * 15 * 60;
    intervals -= offset_seconds * 10000000LL;

    return intervals;
}

#define MAX_PATH_LENGTH 256
#define MAX_FILENAME_LENGTH 256

#ifndef min
  #define min(a,b) ((a) < (b) ? (a) : (b))
#endif

static inline size_t utf16_to_utf8_common(const uint16_t* utf16, int utf16_len, char* utf8, size_t utf8_size) {
    size_t out_pos = 0;
    for (int i = 0; i < utf16_len && out_pos < utf8_size - 1; i++) {
        uint16_t c = utf16[i];
        if (c < 0x80) utf8[out_pos++] = (char)c;
        else if (c < 0x800) {
            if (out_pos + 2 > utf8_size - 1) break;
            utf8[out_pos++] = (char)(0xC0 | (c >> 6));
            utf8[out_pos++] = (char)(0x80 | (c & 0x3F));
        } else {
            if (out_pos + 3 > utf8_size - 1) break;
            utf8[out_pos++] = (char)(0xE0 | (c >> 12));
            utf8[out_pos++] = (char)(0x80 | ((c >> 6) & 0x3F));
            utf8[out_pos++] = (char)(0x80 | (c & 0x3F));
        }
    }
    utf8[out_pos] = '\0';
    return out_pos;
}

#define utf16_to_utf8 utf16_to_utf8_common

static inline void sanitize_filename(char* name) {
    for (char* p = name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == '<' || c == '>' || c == ':' || c == '"' || c == '|' || c == '?' || c == '*' || c == '\\' || c == '/')
            *p = '_';
    }
}

static inline void fs_name_to_utf8(const uint16_t* utf16, int len, char* utf8, size_t utf8_size) {
    if (!utf8 || utf8_size == 0) return;
    utf16_to_utf8(utf16, min(len, MAX_FILENAME_LENGTH - 1), utf8, utf8_size);
    sanitize_filename(utf8);
}

#define STRCPY_S(dst, size, src) do { strncpy(dst, src, (size)-1); (dst)[(size)-1] = '\0'; } while(0)
#define STRCAT_S(dst, size, src) strncat(dst, src, (size) - strlen(dst) - 1)

static inline bool is_safe_path(const char* name) {
    if (!name || name[0] == '\0') return false;
    if (name[0] == '\\' || name[0] == '/') return false;
    if (name[0] == '.' && name[1] == '.') return false;
    if (strstr(name, "/..") || strstr(name, "\\..")) return false;
    if (strchr(name, ':') != NULL) return false;
    return true;
}

static inline uint32_t dir_hash(const char* s, size_t len) {
    uint32_t h = 5381;
    for (size_t i = 0; i < len; i++) h = ((h << 5) + h) ^ s[i];
    return h;
}

#define DIR_CACHE_BITS 10
#define DIR_CACHE_SIZE (1 << DIR_CACHE_BITS)

extern uint32_t g_dir_cache[DIR_CACHE_SIZE];
extern bool g_dir_cache_init;

static inline bool create_directories(const char* path) {
    if (!path || path[0] == '\0' || strstr(path, "..") != NULL) return false;

    if (!g_dir_cache_init) { memset(g_dir_cache, 0, sizeof(g_dir_cache)); g_dir_cache_init = true; }

    size_t path_len = strlen(path);
    uint32_t h = dir_hash(path, path_len);
    uint32_t idx = h & (DIR_CACHE_SIZE - 1);

    if (g_dir_cache[idx] == h) return true;
    if (path_len >= MAX_PATH_LENGTH) return false;

    char tmp[MAX_PATH_LENGTH];
    memcpy(tmp, path, path_len + 1);

    bool success = true;
    char* p = tmp;

#ifdef PLATFORM_WINDOWS
    if (path_len > 2 && p[1] == ':') {
        p += 2;
        if (*p == '\\' || *p == '/') p++;
    }
#else
    if (*p == '/') p++;
#endif

    while ((p = strchr(p, PATH_SEP_CHAR)) != NULL) {
        *p = '\0';
        int result = MKDIR(tmp);
        if (result != 0 && errno != EEXIST) { success = false; break; }
        *p = PATH_SEP_CHAR;
        p++;
    }

    if (success && tmp[0] != '\0') {
        int result = MKDIR(tmp);
        if (result != 0 && errno != EEXIST) success = false;
    }

    if (success) g_dir_cache[idx] = h;
    return success;
}

#endif
