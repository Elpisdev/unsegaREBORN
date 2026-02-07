#ifndef COMMON_H
#define COMMON_H

#include "lib.h"

#define FSEEKO fseeko
#define FTELLO ftello

#ifdef PLATFORM_WINDOWS

static inline int utf8_to_wide(const char* utf8, WCHAR* wide, int wide_len) {
    return (int)utf8_to_utf16(utf8, wide, (size_t)wide_len);
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

typedef HANDLE DirHandle;
#define INVALID_DIR_HANDLE INVALID_HANDLE_VALUE

static inline DirHandle open_output_dir(const char* path) {
    WCHAR wpath[1024];
    if (!utf8_to_wide(path, wpath, 1024)) return INVALID_DIR_HANDLE;
    return lib_open_dir_handle(wpath);
}

static inline FILE* fopen_in_dir(DirHandle dir, const char* filename, uint64_t prealloc_size) {
    WCHAR wname[256];
    if (!utf8_to_wide(filename, wname, 256)) return NULL;
    return lib_fopen_relative(dir, wname, prealloc_size);
}

static inline void close_output_dir(DirHandle dir) {
    if (dir != INVALID_DIR_HANDLE) NtClose(dir);
}

#define FOPEN fopen
#define FOPEN_PREALLOC fopen_prealloc_utf8
#define FWRITE_DIRECT lib_fwrite_direct
#define MKDIR(path) mkdir_utf8(path)
#define REMOVE remove_utf8
#define RMDIR(path) _rmdir(path)

static inline bool set_file_times(const char* path, uint64_t modified_time, uint64_t access_time) {
    WCHAR wpath[1024];
    if (!utf8_to_wide(path, wpath, 1024)) return false;
    return lib_wutime(wpath, (int64_t)modified_time, (int64_t)access_time) == 0;
}

static inline bool set_dir_times(const char* path, uint64_t modified_time, uint64_t access_time) {
    WCHAR wpath[1024];
    if (!utf8_to_wide(path, wpath, 1024)) return false;
    return lib_wutime_dir(wpath, (int64_t)modified_time, (int64_t)access_time) == 0;
}

static inline bool set_file_times_handle(FILE* f, uint64_t modified_time, uint64_t access_time) {
    return lib_set_file_times_ntfs(f, (int64_t)modified_time, (int64_t)access_time);
}

#else

typedef int DirHandle;
#define INVALID_DIR_HANDLE (-1)
static inline DirHandle open_output_dir(const char* path) { (void)path; return -1; }
static inline FILE* fopen_in_dir(DirHandle dir, const char* filename, uint64_t prealloc_size) {
    (void)dir; (void)filename; (void)prealloc_size; return NULL;
}
static inline void close_output_dir(DirHandle dir) { (void)dir; }

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

    uint32_t py = year - 1;
    uint64_t days = (uint64_t)py * 365 + py / 4 - py / 100 + py / 400 - 584388ULL;
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
    size_t out = 0;
    for (int i = 0; i < utf16_len && out < utf8_size - 1; i++) {
        uint32_t cp = utf16[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < utf16_len && utf16[i+1] >= 0xDC00 && utf16[i+1] <= 0xDFFF)
            cp = 0x10000 + ((cp - 0xD800) << 10) + (utf16[++i] - 0xDC00);
        if (cp < 0x80) utf8[out++] = (char)cp;
        else if (cp < 0x800) {
            if (out + 2 > utf8_size - 1) break;
            utf8[out++] = (char)(0xC0 | (cp >> 6));
            utf8[out++] = (char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            if (out + 3 > utf8_size - 1) break;
            utf8[out++] = (char)(0xE0 | (cp >> 12));
            utf8[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            utf8[out++] = (char)(0x80 | (cp & 0x3F));
        } else {
            if (out + 4 > utf8_size - 1) break;
            utf8[out++] = (char)(0xF0 | (cp >> 18));
            utf8[out++] = (char)(0x80 | ((cp >> 12) & 0x3F));
            utf8[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            utf8[out++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    utf8[out] = '\0';
    return out;
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

static inline const char* get_basename(const char* path) {
    const char* b = strrchr(path, '/');
    const char* c = strrchr(path, '\\');
    if (c && (!b || c > b)) b = c;
    return b ? b + 1 : path;
}

#endif
