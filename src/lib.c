#include "lib.h"

int lib_errno_val = 0;

static FILE lib_stdout_impl;
static FILE lib_stderr_impl;
static FILE lib_stdin_impl;

FILE* lib_stdout_file = &lib_stdout_impl;
FILE* lib_stderr_file = &lib_stderr_impl;
FILE* lib_stdin_file = &lib_stdin_impl;

#ifdef PLATFORM_WINDOWS

HANDLE lib_heap = NULL;
HANDLE lib_stdout_handle = NULL;
HANDLE lib_stderr_handle = NULL;
HANDLE lib_stdin_handle = NULL;

#define MAX_FD_TABLE 256
static HANDLE fd_table[MAX_FD_TABLE];
static int fd_next = 3;

#define FILE_POOL_SIZE 16
typedef struct {
    FILE file;
    uint8_t* buffer;
    bool in_use;
} PooledFile;
static PooledFile file_pool[FILE_POOL_SIZE];
static int file_pool_next = 0;

static FILE* pool_alloc_file(void) {
    for (int i = 0; i < FILE_POOL_SIZE; i++) {
        int idx = (file_pool_next + i) % FILE_POOL_SIZE;
        if (!file_pool[idx].in_use) {
            file_pool[idx].in_use = true;
            file_pool_next = (idx + 1) % FILE_POOL_SIZE;
            if (!file_pool[idx].buffer) {
                file_pool[idx].buffer = lib_malloc(LIB_IOBUF_SIZE);
                if (!file_pool[idx].buffer) {
                    file_pool[idx].in_use = false;
                    break;
                }
            }
            FILE* f = &file_pool[idx].file;
            f->buffer = file_pool[idx].buffer;
            f->buf_cap = LIB_IOBUF_SIZE;
            return f;
        }
    }
    FILE* f = lib_malloc(sizeof(FILE) + LIB_IOBUF_SIZE);
    if (f) {
        f->buffer = (uint8_t*)(f + 1);
        f->buf_cap = LIB_IOBUF_SIZE;
    }
    return f;
}

static void pool_free_file(FILE* f) {
    for (int i = 0; i < FILE_POOL_SIZE; i++) {
        if (f == &file_pool[i].file) {
            file_pool[i].in_use = false;
            return;
        }
    }
    lib_free(f);
}

_Static_assert(CRT_OFFSETOF(PEB, ProcessParameters) == 0x20, "PEB.ProcessParameters offset");
_Static_assert(CRT_OFFSETOF(PEB, ProcessHeap) == 0x30, "PEB.ProcessHeap offset");
_Static_assert(CRT_OFFSETOF(RTL_USER_PROCESS_PARAMETERS, StandardInput) == 0x20, "Params.StandardInput offset");
_Static_assert(CRT_OFFSETOF(RTL_USER_PROCESS_PARAMETERS, StandardOutput) == 0x28, "Params.StandardOutput offset");
_Static_assert(CRT_OFFSETOF(RTL_USER_PROCESS_PARAMETERS, StandardError) == 0x30, "Params.StandardError offset");
_Static_assert(CRT_OFFSETOF(RTL_USER_PROCESS_PARAMETERS, CommandLine) == 0x70, "Params.CommandLine offset");

__attribute__((naked, used)) void ___chkstk_ms(void) {
    __asm__ volatile (
        "push %%rcx\n\t" "push %%rax\n\t" "cmp $0x1000, %%rax\n\t" "lea 24(%%rsp), %%rcx\n\t" "jb 2f\n\t"
        "1:\n\t" "sub $0x1000, %%rcx\n\t" "test %%rcx, (%%rcx)\n\t" "sub $0x1000, %%rax\n\t" "cmp $0x1000, %%rax\n\t" "ja 1b\n\t"
        "2:\n\t" "sub %%rax, %%rcx\n\t" "test %%rcx, (%%rcx)\n\t" "pop %%rax\n\t" "pop %%rcx\n\t" "ret\n\t" ::: "memory"
    );
}

#else

static uint8_t* heap_base = NULL;
static uint8_t* heap_end = NULL;
static uint8_t* heap_cur = NULL;
#define HEAP_INITIAL_SIZE (16 * 1024 * 1024)

typedef struct FreeNode { struct FreeNode* next; size_t size; } FreeNode;
static FreeNode* free_list = NULL;

#endif

#ifdef PLATFORM_WINDOWS

void* lib_malloc(size_t size) {
    if (!size) return NULL;
    return RtlAllocateHeap(lib_heap, 0, size);
}

void* lib_calloc(size_t count, size_t size) {
    if (size && count > (size_t)-1 / size) return NULL;
    size_t total = count * size;
    if (!total) return NULL;
#define HEAP_ZERO_MEMORY 0x08
    return RtlAllocateHeap(lib_heap, HEAP_ZERO_MEMORY, total);
}

void* lib_realloc(void* ptr, size_t size) {
    if (!ptr) return lib_malloc(size);
    if (!size) { lib_free(ptr); return NULL; }
    return RtlReAllocateHeap(lib_heap, 0, ptr, size);
}

void lib_free(void* ptr) {
    if (ptr) RtlFreeHeap(lib_heap, 0, ptr);
}

#else

static void heap_init(void) {
    if (heap_base) return;
    long ret = syscall6(SYS_mmap, 0, HEAP_INITIAL_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ret < 0 && ret > -4096) { heap_base = NULL; return; }
    heap_base = (uint8_t*)ret;
    heap_cur = heap_base;
    heap_end = heap_base + HEAP_INITIAL_SIZE;
}

void* lib_malloc(size_t size) {
    if (!size) return NULL;
    if (!heap_base) heap_init();
    if (!heap_base) return NULL;

    size = (size + 15) & ~15UL;
    size_t total = size + 16;

    FreeNode** pp = &free_list;
    while (*pp) {
        if ((*pp)->size >= total) {
            FreeNode* node = *pp;
            size_t node_size = node->size;
            *pp = node->next;
            if (node_size >= total + 48) {
                FreeNode* rem = (FreeNode*)((uint8_t*)node + total);
                rem->size = node_size - total;
                rem->next = free_list;
                free_list = rem;
                *(size_t*)node = total;
            } else {
                *(size_t*)node = node_size;
            }
            return (uint8_t*)node + 16;
        }
        pp = &(*pp)->next;
    }

    if (heap_cur + total > heap_end) {
        size_t mmap_size = (total + 4095) & ~4095UL;
        long ret = syscall6(SYS_mmap, 0, mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ret < 0 && ret > -4096) return NULL;
        uint8_t* ptr = (uint8_t*)ret;
        *(size_t*)ptr = mmap_size | 0x8000000000000000ULL;
        return ptr + 16;
    }

    uint8_t* ptr = heap_cur;
    *(size_t*)ptr = total;
    heap_cur += total;
    return ptr + 16;
}

void* lib_calloc(size_t count, size_t size) {
    if (size && count > (size_t)-1 / size) return NULL;
    size_t total = count * size;
    void* ptr = lib_malloc(total);
    if (ptr) lib_memset(ptr, 0, total);
    return ptr;
}

void* lib_realloc(void* ptr, size_t size) {
    if (!ptr) return lib_malloc(size);
    if (!size) { lib_free(ptr); return NULL; }

    uint8_t* base = (uint8_t*)ptr - 16;
    size_t old_total = *(size_t*)base;
    old_total &= 0x7FFFFFFFFFFFFFFFULL;
    size_t old_size = old_total - 16;

    if (size <= old_size) return ptr;

    void* new_ptr = lib_malloc(size);
    if (new_ptr) {
        lib_memcpy(new_ptr, ptr, old_size < size ? old_size : size);
        lib_free(ptr);
    }
    return new_ptr;
}

void lib_free(void* ptr) {
    if (!ptr) return;
    uint8_t* base = (uint8_t*)ptr - 16;
    size_t size = *(size_t*)base;
    if (size & 0x8000000000000000ULL) {
        size &= 0x7FFFFFFFFFFFFFFFULL;
        syscall2(SYS_munmap, (long)base, size);
    } else if (base >= heap_base && base < heap_end) {
        FreeNode* node = (FreeNode*)base;
        node->size = size;
        node->next = free_list;
        free_list = node;
    }
}

#endif

size_t lib_strlen(const char* s) {
    size_t len;
    __asm__ volatile (
        "xor %%al, %%al\n\t"
        "mov $-1, %[len]\n\t"
        "repne scasb\n\t"
        "not %[len]\n\t"
        "dec %[len]\n\t"
        : [len] "=c" (len), "+D" (s)
        :
        : "al", "memory"
    );
    return len;
}

char* lib_strcpy(char* dst, const char* src) {
    char* d = dst;
    while ((*d++ = *src++));
    return dst;
}

char* lib_strncpy(char* dst, const char* src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i]; i++) dst[i] = src[i];
    for (; i < n; i++) dst[i] = '\0';
    return dst;
}

int lib_strcmp(const char* s1, const char* s2) {
    while (*s1 && *s1 == *s2) { s1++; s2++; }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

int lib_strncmp(const char* s1, const char* s2, size_t n) {
    while (n && *s1 && *s1 == *s2) { s1++; s2++; n--; }
    return n ? (unsigned char)*s1 - (unsigned char)*s2 : 0;
}

char* lib_strchr(const char* s, int c) {
    while (*s) { if (*s == (char)c) return (char*)s; s++; }
    return (c == 0) ? (char*)s : NULL;
}

char* lib_strrchr(const char* s, int c) {
    const char* last = NULL;
    while (*s) { if (*s == (char)c) last = s; s++; }
    return (c == 0) ? (char*)s : (char*)last;
}

char* lib_strstr(const char* haystack, const char* needle) {
    if (!*needle) return (char*)haystack;
    for (; *haystack; haystack++) {
        const char* h = haystack; const char* n = needle;
        while (*h && *n && *h == *n) { h++; n++; }
        if (!*n) return (char*)haystack;
    }
    return NULL;
}

char* lib_strncat(char* dst, const char* src, size_t n) {
    char* d = dst;
    while (*d) d++;
    while (n-- && *src) *d++ = *src++;
    *d = '\0';
    return dst;
}

void* lib_memcpy(void* dst, const void* src, size_t n) {
    void* ret = dst;
    __asm__ volatile (
        "rep movsb"
        : "+D"(dst), "+S"(src), "+c"(n)
        :
        : "memory"
    );
    return ret;
}

#undef memcpy
void* memcpy(void* dst, const void* src, size_t n) __attribute__((alias("lib_memcpy")));
#define memcpy lib_memcpy

void* lib_memset(void* dst, int c, size_t n) {
    void* ret = dst;
    __asm__ volatile (
        "rep stosb"
        : "+D"(dst), "+c"(n)
        : "a"((uint8_t)c)
        : "memory"
    );
    return ret;
}

#undef memset
void* memset(void* dst, int c, size_t n) __attribute__((alias("lib_memset")));
#define memset lib_memset

int lib_memcmp(const void* s1, const void* s2, size_t n) {
    const uint8_t *p1 = s1, *p2 = s2;
    while (n >= 8) {
        uint64_t a, b;
        __builtin_memcpy(&a, p1, 8);
        __builtin_memcpy(&b, p2, 8);
        if (a != b) goto byte_cmp;
        p1 += 8; p2 += 8; n -= 8;
    }
byte_cmp:
    while (n--) { if (*p1 != *p2) return *p1 - *p2; p1++; p2++; }
    return 0;
}

#ifdef PLATFORM_WINDOWS

size_t utf8_to_utf16(const char* utf8, WCHAR* utf16, size_t utf16_max) {
    size_t out = 0;
    const uint8_t* s = (const uint8_t*)utf8;
    while (*s && out < utf16_max - 1) {
        uint32_t cp;
        if (s[0] < 0x80) { cp = s[0]; s += 1; }
        else if ((s[0] & 0xE0) == 0xC0 && s[1]) { cp = ((s[0] & 0x1F) << 6) | (s[1] & 0x3F); s += 2; }
        else if ((s[0] & 0xF0) == 0xE0 && s[1] && s[2]) { cp = ((s[0] & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F); s += 3; }
        else if ((s[0] & 0xF8) == 0xF0 && s[1] && s[2] && s[3]) { cp = ((s[0] & 0x07) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F); s += 4; }
        else { s += 1; continue; }
        if (cp <= 0xFFFF) utf16[out++] = (WCHAR)cp;
        else if (cp <= 0x10FFFF && out < utf16_max - 2) {
            cp -= 0x10000;
            utf16[out++] = (WCHAR)(0xD800 | (cp >> 10));
            utf16[out++] = (WCHAR)(0xDC00 | (cp & 0x3FF));
        }
    }
    utf16[out] = 0;
    return out;
}

static size_t utf16_to_utf8(const WCHAR* utf16, char* utf8, size_t utf8_max) {
    size_t out = 0;
    while (*utf16 && out < utf8_max - 1) {
        uint32_t cp = *utf16++;
        if (cp >= 0xD800 && cp <= 0xDBFF && *utf16 >= 0xDC00 && *utf16 <= 0xDFFF)
            cp = 0x10000 + ((cp - 0xD800) << 10) + (*utf16++ - 0xDC00);
        if (cp < 0x80) utf8[out++] = (char)cp;
        else if (cp < 0x800) {
            if (out + 2 > utf8_max - 1) break;
            utf8[out++] = (char)(0xC0 | (cp >> 6));
            utf8[out++] = (char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            if (out + 3 > utf8_max - 1) break;
            utf8[out++] = (char)(0xE0 | (cp >> 12));
            utf8[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            utf8[out++] = (char)(0x80 | (cp & 0x3F));
        } else {
            if (out + 4 > utf8_max - 1) break;
            utf8[out++] = (char)(0xF0 | (cp >> 18));
            utf8[out++] = (char)(0x80 | ((cp >> 12) & 0x3F));
            utf8[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            utf8[out++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    utf8[out] = '\0';
    return out;
}

static bool path_to_nt(const WCHAR* dos_path, UNICODE_STRING* nt_path) {
    return NT_SUCCESS(RtlDosPathNameToNtPathName_U_WithStatus(dos_path, nt_path, NULL, NULL));
}

static HANDLE nt_open_file(const WCHAR* path, ULONG access, ULONG share, ULONG disp, ULONG opts) {
    UNICODE_STRING nt_path = {0};
    if (!path_to_nt(path, &nt_path)) return INVALID_HANDLE_VALUE;
    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES), NULL, &nt_path, OBJ_CASE_INSENSITIVE, NULL, NULL };
    HANDLE h = INVALID_HANDLE_VALUE; IO_STATUS_BLOCK iosb = {0};
    NTSTATUS status = NtCreateFile(&h, access | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, share, disp, opts | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    RtlFreeUnicodeString(&nt_path);
    if (!NT_SUCCESS(status)) { lib_errno_val = (int)status; return INVALID_HANDLE_VALUE; }
    return h;
}

static int parse_mode(const char* mode, ULONG* access, ULONG* share, ULONG* disp, ULONG* opts, uint32_t* flags) {
    *access = 0; *share = FILE_SHARE_READ; *disp = FILE_OPEN;
    *opts = FILE_NON_DIRECTORY_FILE; *flags = 0;
    if (!mode || !*mode) return -1;
    switch (mode[0]) {
        case 'r': *access = FILE_READ_DATA | FILE_READ_ATTRIBUTES; *disp = FILE_OPEN; *flags = LIB_FILE_READ; break;
        case 'w': *access = FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES; *disp = FILE_OVERWRITE_IF; *flags = LIB_FILE_WRITE; break;
        case 'a': *access = FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES; *disp = FILE_OPEN_IF; *flags = LIB_FILE_WRITE | LIB_FILE_APPEND; break;
        default: return -1;
    }
    for (const char* p = mode + 1; *p; p++) {
        if (*p == '+') { *access |= FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES; *flags |= LIB_FILE_READ | LIB_FILE_WRITE; }
    }
    if ((*flags & LIB_FILE_READ) && !(*flags & LIB_FILE_WRITE)) *opts |= FILE_SEQUENTIAL_ONLY;
    return 0;
}

#endif

#ifdef PLATFORM_WINDOWS

FILE* lib_fopen(const char* path, const char* mode) {
    WCHAR wpath[1024]; utf8_to_utf16(path, wpath, 1024);
    WCHAR wmode[16]; utf8_to_utf16(mode, wmode, 16);
    return lib_wfopen(wpath, wmode);
}

FILE* lib_wfopen(const WCHAR* path, const WCHAR* mode) {
    char narrow_mode[16] = {0};
    for (int i = 0; mode[i] && i < 15; i++) narrow_mode[i] = (char)mode[i];

    ULONG access, share, disp, opts; uint32_t flags;
    if (parse_mode(narrow_mode, &access, &share, &disp, &opts, &flags) < 0) { lib_errno_val = EINVAL; return NULL; }

    HANDLE h = nt_open_file(path, access, share, disp, opts);
    if (h == INVALID_HANDLE_VALUE) return NULL;

    FILE* f = pool_alloc_file();
    if (!f) { NtClose(h); return NULL; }

    f->handle = h; f->buf_pos = 0; f->buf_fill = 0; f->file_pos = 0; f->flags = flags;

    if (flags & LIB_FILE_APPEND) {
        FILE_STANDARD_INFORMATION info; IO_STATUS_BLOCK iosb;
        if (NT_SUCCESS(NtQueryInformationFile(h, &iosb, &info, sizeof(info), FileStandardInformation)))
            f->file_pos = info.EndOfFile.QuadPart;
    }
    if (fd_next < MAX_FD_TABLE) fd_table[fd_next++] = h;
    return f;
}

FILE* lib_wfopen_prealloc(const WCHAR* path, uint64_t size) {
    UNICODE_STRING nt_path = {0};
    if (!path_to_nt(path, &nt_path)) return NULL;

    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES), NULL, &nt_path, OBJ_CASE_INSENSITIVE, NULL, NULL };
    HANDLE h = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK iosb = {0};
    LARGE_INTEGER alloc_size; alloc_size.QuadPart = (LONGLONG)size;

    NTSTATUS status = NtCreateFile(&h, FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb,
        &alloc_size, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_SEQUENTIAL_ONLY, NULL, 0);
    RtlFreeUnicodeString(&nt_path);
    if (!NT_SUCCESS(status)) { lib_errno_val = (int)status; return NULL; }

    FILE* f = pool_alloc_file();
    if (!f) { NtClose(h); return NULL; }

    f->handle = h; f->buf_pos = 0; f->buf_fill = 0; f->file_pos = 0; f->flags = LIB_FILE_WRITE;
    if (fd_next < MAX_FD_TABLE) fd_table[fd_next++] = h;
    return f;
}

HANDLE lib_open_dir_handle(const WCHAR* path) {
    UNICODE_STRING nt_path = {0};
    if (!path_to_nt(path, &nt_path)) return INVALID_HANDLE_VALUE;
    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES), NULL, &nt_path, OBJ_CASE_INSENSITIVE, NULL, NULL };
    HANDLE h; IO_STATUS_BLOCK iosb;
    NTSTATUS status = NtCreateFile(&h, FILE_ADD_FILE | FILE_TRAVERSE | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    RtlFreeUnicodeString(&nt_path);
    if (!NT_SUCCESS(status)) return INVALID_HANDLE_VALUE;
    return h;
}

FILE* lib_fopen_relative(HANDLE dir_handle, const WCHAR* filename, uint64_t prealloc_size) {
    UNICODE_STRING name_str;
    name_str.Buffer = (WCHAR*)filename;
    name_str.Length = 0;
    while (filename[name_str.Length / 2]) name_str.Length += 2;
    name_str.MaximumLength = name_str.Length + 2;

    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES), dir_handle, &name_str, OBJ_CASE_INSENSITIVE, NULL, NULL };
    HANDLE h; IO_STATUS_BLOCK iosb;
    LARGE_INTEGER alloc = {0};
    if (prealloc_size) alloc.QuadPart = (LONGLONG)prealloc_size;

    NTSTATUS status = NtCreateFile(&h, FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb,
        prealloc_size ? &alloc : NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_SEQUENTIAL_ONLY, NULL, 0);
    if (!NT_SUCCESS(status)) return NULL;

    FILE* f = pool_alloc_file();
    if (!f) { NtClose(h); return NULL; }

    f->handle = h; f->buf_pos = 0; f->buf_fill = 0; f->file_pos = 0; f->flags = LIB_FILE_WRITE;
    if (fd_next < MAX_FD_TABLE) fd_table[fd_next++] = h;
    return f;
}

size_t lib_fwrite_direct(FILE* f, const void* buf, size_t size) {
    if (!f || !buf || !size || !(f->flags & LIB_FILE_WRITE)) return 0;
    IO_STATUS_BLOCK iosb = {0};
    LARGE_INTEGER offset; offset.QuadPart = f->file_pos;
    NTSTATUS status = NtWriteFile(f->handle, NULL, NULL, NULL, &iosb, (void*)buf, (ULONG)size, &offset, NULL);
    if (!NT_SUCCESS(status)) { f->flags |= LIB_FILE_ERROR; return 0; }
    f->file_pos += iosb.Information;
    return iosb.Information;
}

static bool flush_write_buffer(FILE* f) {
    if (!(f->flags & LIB_FILE_WRITE) || f->buf_fill == 0) return true;
    IO_STATUS_BLOCK iosb = {0};
    bool is_console = (f == lib_stdout_file || f == lib_stderr_file);
    LARGE_INTEGER offset; offset.QuadPart = f->file_pos;
    NTSTATUS status = NtWriteFile(f->handle, NULL, NULL, NULL, &iosb, f->buffer, f->buf_fill, is_console ? NULL : &offset, NULL);
    if (!NT_SUCCESS(status)) { f->flags |= LIB_FILE_ERROR; return false; }
    f->file_pos += f->buf_fill; f->buf_fill = 0; f->buf_pos = 0;
    return true;
}

static bool refill_read_buffer(FILE* f) {
    if (!(f->flags & LIB_FILE_READ) || (f->flags & LIB_FILE_EOF)) return false;
    IO_STATUS_BLOCK iosb = {0};
    bool is_console = (f == lib_stdin_file);
    LARGE_INTEGER offset; offset.QuadPart = f->file_pos;
    NTSTATUS status = NtReadFile(f->handle, NULL, NULL, NULL, &iosb, f->buffer, f->buf_cap, is_console ? NULL : &offset, NULL);
    if (status == STATUS_END_OF_FILE || iosb.Information == 0) { f->flags |= LIB_FILE_EOF; f->buf_fill = 0; f->buf_pos = 0; return false; }
    if (!NT_SUCCESS(status)) { f->flags |= LIB_FILE_ERROR; return false; }
    f->buf_fill = (uint32_t)iosb.Information; f->buf_pos = 0; f->file_pos += iosb.Information;
    return true;
}

size_t lib_fread(void* buf, size_t size, size_t count, FILE* f) {
    if (!f || !buf || !size || !count || !(f->flags & LIB_FILE_READ)) return 0;
    if (size > 1 && count > (size_t)-1 / size) return 0;
    size_t total = size * count, read_total = 0;
    uint8_t* dst = buf;
    while (total > 0) {
        size_t avail = f->buf_fill - f->buf_pos;
        if (avail > 0) {
            size_t to_copy = (avail < total) ? avail : total;
            lib_memcpy(dst, f->buffer + f->buf_pos, to_copy);
            f->buf_pos += (uint32_t)to_copy; dst += to_copy; total -= to_copy; read_total += to_copy;
        } else {
            if (total >= f->buf_cap) {
                IO_STATUS_BLOCK iosb = {0}; LARGE_INTEGER offset; offset.QuadPart = f->file_pos;
                size_t chunk = total & ~((size_t)f->buf_cap - 1);
                NTSTATUS status = NtReadFile(f->handle, NULL, NULL, NULL, &iosb, dst, (ULONG)chunk, &offset, NULL);
                if (status == STATUS_END_OF_FILE || iosb.Information == 0) { f->flags |= LIB_FILE_EOF; break; }
                if (!NT_SUCCESS(status)) { f->flags |= LIB_FILE_ERROR; break; }
                f->file_pos += iosb.Information; dst += iosb.Information; total -= iosb.Information; read_total += iosb.Information;
                if (iosb.Information < chunk) { f->flags |= LIB_FILE_EOF; break; }
            } else { if (!refill_read_buffer(f)) break; }
        }
    }
    return read_total / size;
}

size_t lib_fwrite(const void* buf, size_t size, size_t count, FILE* f) {
    if (!f || !buf || !size || !count || !(f->flags & LIB_FILE_WRITE)) return 0;
    if (size > 1 && count > (size_t)-1 / size) return 0;
    size_t total = size * count, written = 0;
    const uint8_t* src = buf;
    while (total >= f->buf_cap) {
        if (f->buf_fill > 0 && !flush_write_buffer(f)) return written / size;
        IO_STATUS_BLOCK iosb = {0}; LARGE_INTEGER offset; offset.QuadPart = f->file_pos;
        size_t chunk = total & ~((size_t)f->buf_cap - 1);
        NTSTATUS status = NtWriteFile(f->handle, NULL, NULL, NULL, &iosb, (void*)src, (ULONG)chunk, &offset, NULL);
        if (!NT_SUCCESS(status)) { f->flags |= LIB_FILE_ERROR; return written / size; }
        f->file_pos += iosb.Information; src += iosb.Information; total -= iosb.Information; written += iosb.Information;
        if (iosb.Information < chunk) return written / size;
    }
    while (total > 0) {
        size_t space = f->buf_cap - f->buf_fill;
        if (space > 0) {
            size_t to_copy = (space < total) ? space : total;
            lib_memcpy(f->buffer + f->buf_fill, src, to_copy);
            f->buf_fill += (uint32_t)to_copy; src += to_copy; total -= to_copy; written += to_copy;
        }
        if (f->buf_fill >= f->buf_cap) if (!flush_write_buffer(f)) break;
    }
    return written / size;
}

int lib_fseeki64(FILE* f, int64_t offset, int whence) {
    if (!f) return -1;
    if (f->flags & LIB_FILE_WRITE) if (!flush_write_buffer(f)) return -1;
    int64_t new_pos;
    switch (whence) {
        case SEEK_SET: new_pos = offset; break;
        case SEEK_CUR: new_pos = (f->file_pos - (f->buf_fill - f->buf_pos)) + offset; break;
        case SEEK_END: {
            FILE_STANDARD_INFORMATION info; IO_STATUS_BLOCK iosb;
            if (!NT_SUCCESS(NtQueryInformationFile(f->handle, &iosb, &info, sizeof(info), FileStandardInformation))) return -1;
            new_pos = info.EndOfFile.QuadPart + offset; break;
        }
        default: return -1;
    }
    if (new_pos < 0) return -1;
    FILE_POSITION_INFORMATION pos_info; pos_info.CurrentByteOffset.QuadPart = new_pos;
    IO_STATUS_BLOCK iosb;
    if (!NT_SUCCESS(NtSetInformationFile(f->handle, &iosb, &pos_info, sizeof(pos_info), FilePositionInformation))) return -1;
    f->file_pos = new_pos; f->buf_pos = 0; f->buf_fill = 0; f->flags &= ~LIB_FILE_EOF;
    return 0;
}

int64_t lib_ftelli64(FILE* f) {
    if (!f) return -1;
    return (f->flags & LIB_FILE_WRITE) ? f->file_pos + f->buf_fill : f->file_pos - (f->buf_fill - f->buf_pos);
}

int lib_fflush(FILE* f) { return (!f || flush_write_buffer(f)) ? 0 : EOF; }

int lib_fclose(FILE* f) {
    if (!f) return EOF;
    int ret = (f->flags & LIB_FILE_WRITE) ? (flush_write_buffer(f) ? 0 : EOF) : 0;
    NtClose(f->handle);
    if (f != &lib_stdout_impl && f != &lib_stderr_impl && f != &lib_stdin_impl) pool_free_file(f);
    return ret;
}

#define EPOCH_DIFF 116444736000000000ULL

time_t lib_time(time_t* t) {
    LARGE_INTEGER sys_time; NtQuerySystemTime(&sys_time);
    time_t result = (time_t)((sys_time.QuadPart - EPOCH_DIFF) / 10000000ULL);
    if (t) *t = result;
    return result;
}

#else

FILE* lib_fopen(const char* path, const char* mode) {
    int flags = 0;
    uint32_t fflags = 0;

    if (mode[0] == 'r') {
        flags = (mode[1] == '+') ? O_RDWR : O_RDONLY;
        fflags = LIB_FILE_READ | ((mode[1] == '+') ? LIB_FILE_WRITE : 0);
    } else if (mode[0] == 'w') {
        flags = O_CREAT | O_TRUNC | ((mode[1] == '+') ? O_RDWR : O_WRONLY);
        fflags = LIB_FILE_WRITE | ((mode[1] == '+') ? LIB_FILE_READ : 0);
    } else if (mode[0] == 'a') {
        flags = O_CREAT | O_APPEND | ((mode[1] == '+') ? O_RDWR : O_WRONLY);
        fflags = LIB_FILE_WRITE | LIB_FILE_APPEND | ((mode[1] == '+') ? LIB_FILE_READ : 0);
    } else {
        lib_errno_val = EINVAL;
        return NULL;
    }

    long fd = syscall3(SYS_open, (long)path, flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) { lib_errno_val = (int)(-fd); return NULL; }

    FILE* f = lib_malloc(sizeof(FILE));
    if (!f) { syscall1(SYS_close, fd); return NULL; }
    f->buffer = lib_malloc(LIB_IOBUF_SIZE);
    if (!f->buffer) { lib_free(f); syscall1(SYS_close, fd); return NULL; }

    f->fd = (int)fd; f->buf_cap = LIB_IOBUF_SIZE; f->buf_pos = 0; f->buf_fill = 0; f->file_pos = 0; f->flags = fflags;

    if (fflags & LIB_FILE_APPEND) {
        long pos = syscall3(SYS_lseek, fd, 0, SEEK_END);
        if (pos >= 0) f->file_pos = pos;
    }
    return f;
}

static bool flush_write_buffer(FILE* f) {
    if (!(f->flags & LIB_FILE_WRITE) || f->buf_fill == 0) return true;
    long ret = syscall3(SYS_write, f->fd, (long)f->buffer, f->buf_fill);
    if (ret < 0) { f->flags |= LIB_FILE_ERROR; return false; }
    f->file_pos += f->buf_fill; f->buf_fill = 0; f->buf_pos = 0;
    return true;
}

static bool refill_read_buffer(FILE* f) {
    if (!(f->flags & LIB_FILE_READ) || (f->flags & LIB_FILE_EOF)) return false;
    long ret = syscall3(SYS_read, f->fd, (long)f->buffer, f->buf_cap);
    if (ret <= 0) { if (ret == 0) f->flags |= LIB_FILE_EOF; else f->flags |= LIB_FILE_ERROR; f->buf_fill = 0; f->buf_pos = 0; return false; }
    f->buf_fill = (uint32_t)ret; f->buf_pos = 0; f->file_pos += ret;
    return true;
}

size_t lib_fread(void* buf, size_t size, size_t count, FILE* f) {
    if (!f || !buf || !size || !count || !(f->flags & LIB_FILE_READ)) return 0;
    if (size > 1 && count > (size_t)-1 / size) return 0;
    size_t total = size * count, read_total = 0;
    uint8_t* dst = buf;
    while (total > 0) {
        size_t avail = f->buf_fill - f->buf_pos;
        if (avail > 0) {
            size_t to_copy = (avail < total) ? avail : total;
            lib_memcpy(dst, f->buffer + f->buf_pos, to_copy);
            f->buf_pos += (uint32_t)to_copy; dst += to_copy; total -= to_copy; read_total += to_copy;
        } else {
            if (total >= f->buf_cap) {
                long ret = syscall3(SYS_read, f->fd, (long)dst, total);
                if (ret <= 0) { if (ret == 0) f->flags |= LIB_FILE_EOF; else f->flags |= LIB_FILE_ERROR; break; }
                f->file_pos += ret; dst += ret; total -= ret; read_total += ret;
            } else { if (!refill_read_buffer(f)) break; }
        }
    }
    return read_total / size;
}

size_t lib_fwrite(const void* buf, size_t size, size_t count, FILE* f) {
    if (!f || !buf || !size || !count || !(f->flags & LIB_FILE_WRITE)) return 0;
    if (size > 1 && count > (size_t)-1 / size) return 0;
    size_t total = size * count, written = 0;
    const uint8_t* src = buf;
    while (total >= f->buf_cap) {
        if (f->buf_fill > 0 && !flush_write_buffer(f)) return written / size;
        size_t chunk = total & ~((size_t)f->buf_cap - 1);
        long ret = syscall3(SYS_write, f->fd, (long)src, chunk);
        if (ret < 0) { f->flags |= LIB_FILE_ERROR; return written / size; }
        f->file_pos += ret; src += ret; total -= ret; written += ret;
        if ((size_t)ret < chunk) return written / size;
    }
    while (total > 0) {
        size_t space = f->buf_cap - f->buf_fill;
        if (space > 0) {
            size_t to_copy = (space < total) ? space : total;
            lib_memcpy(f->buffer + f->buf_fill, src, to_copy);
            f->buf_fill += (uint32_t)to_copy; src += to_copy; total -= to_copy; written += to_copy;
        }
        if (f->buf_fill >= f->buf_cap) if (!flush_write_buffer(f)) break;
    }
    return written / size;
}

int lib_fseeki64(FILE* f, int64_t offset, int whence) {
    if (!f) return -1;
    if (f->flags & LIB_FILE_WRITE) if (!flush_write_buffer(f)) return -1;
    long new_pos = syscall3(SYS_lseek, f->fd, offset, whence);
    if (new_pos < 0) return -1;
    f->file_pos = new_pos; f->buf_pos = 0; f->buf_fill = 0; f->flags &= ~LIB_FILE_EOF;
    return 0;
}

int64_t lib_ftelli64(FILE* f) {
    if (!f) return -1;
    return (f->flags & LIB_FILE_WRITE) ? f->file_pos + f->buf_fill : f->file_pos - (f->buf_fill - f->buf_pos);
}

int lib_fflush(FILE* f) { return (!f || flush_write_buffer(f)) ? 0 : EOF; }

int lib_fclose(FILE* f) {
    if (!f) return EOF;
    int ret = (f->flags & LIB_FILE_WRITE) ? (flush_write_buffer(f) ? 0 : EOF) : 0;
    syscall1(SYS_close, f->fd);
    if (f->buffer) lib_free(f->buffer);
    if (f != &lib_stdout_impl && f != &lib_stderr_impl && f != &lib_stdin_impl) lib_free(f);
    return ret;
}

time_t lib_time(time_t* t) {
    struct linux_timespec ts;
    syscall2(228, 0, (long)&ts);
    if (t) *t = ts.tv_sec;
    return ts.tv_sec;
}

#endif

int lib_feof(FILE* f) { return f ? (f->flags & LIB_FILE_EOF) != 0 : 0; }
static int lib_fgetc(FILE* f) { unsigned char c; return (lib_fread(&c, 1, 1, f) == 1) ? c : EOF; }
static int lib_fputc(int c, FILE* f) { unsigned char ch = (unsigned char)c; return (lib_fwrite(&ch, 1, 1, f) == 1) ? ch : EOF; }
static int lib_fputs(const char* s, FILE* f) { size_t len = lib_strlen(s); return (lib_fwrite(s, 1, len, f) == len) ? 0 : EOF; }

char* lib_fgets(char* buf, int n, FILE* f) {
    if (!buf || n <= 0 || !f) return NULL;
    int i = 0;
    while (i < n - 1) {
        int c = lib_fgetc(f);
        if (c == EOF) { if (i == 0) return NULL; break; }
        buf[i++] = (char)c;
        if (c == '\n') break;
    }
    buf[i] = '\0';
    return buf;
}

void lib_rewind(FILE* f) { if (f) { lib_fseeki64(f, 0, SEEK_SET); } }
double lib_difftime(time_t t1, time_t t0) { return (double)(t1 - t0); }

static char* fmt_uint64(char* buf, uint64_t val, int base, int width, char pad, bool upper) {
    char tmp[24]; char* p = tmp + sizeof(tmp) - 1; *p = '\0';
    if (width > 23) width = 23;
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    do { *--p = digits[val % base]; val /= base; } while (val);
    int len = (int)(tmp + sizeof(tmp) - 1 - p);
    while (len < width) { *--p = pad; len++; }
    while (*p) *buf++ = *p++;
    return buf;
}

static char* fmt_int64(char* buf, int64_t val, int width, char pad) {
    if (val < 0) { *buf++ = '-'; val = -val; if (width > 0) width--; }
    return fmt_uint64(buf, (uint64_t)val, 10, width, pad, false);
}



int lib_vsnprintf(char* buf, size_t n, const char* fmt, va_list ap) {
    if (!buf || !n) return 0;
    char* dst = buf; char* end = buf + n - 1;
    while (*fmt && dst < end) {
        if (*fmt != '%') { *dst++ = *fmt++; continue; }
        fmt++;
        char pad = ' '; if (*fmt == '0') { pad = '0'; fmt++; }
        int width = 0; while (*fmt >= '0' && *fmt <= '9') { width = width * 10 + (*fmt - '0'); fmt++; }
        bool is_ll = (*fmt == 'l' && fmt[1] == 'l');
        if (is_ll) fmt += 2;
        else if (*fmt == 'l' || *fmt == 'z') fmt++;
        char tmp[24]; char* p;
        switch (*fmt) {
            case 's': { const char* s = va_arg(ap, const char*); if (!s) s = "(null)"; while (*s && dst < end) *dst++ = *s++; break; }
            case 'c': *dst++ = (char)va_arg(ap, int); break;
            case 'd': case 'i':
                p = is_ll ? fmt_int64(tmp, va_arg(ap, long long), width, pad) : fmt_int64(tmp, va_arg(ap, int), width, pad);
                *p = '\0'; for (p = tmp; *p && dst < end;) *dst++ = *p++; break;
            case 'u':
                p = is_ll ? fmt_uint64(tmp, va_arg(ap, unsigned long long), 10, width, pad, false) : fmt_uint64(tmp, va_arg(ap, unsigned int), 10, width, pad, false);
                *p = '\0'; for (p = tmp; *p && dst < end;) *dst++ = *p++; break;
            case 'x': case 'X':
                p = is_ll ? fmt_uint64(tmp, va_arg(ap, unsigned long long), 16, width, pad, *fmt == 'X') : fmt_uint64(tmp, va_arg(ap, unsigned int), 16, width, pad, *fmt == 'X');
                *p = '\0'; for (p = tmp; *p && dst < end;) *dst++ = *p++; break;
            case 'p': *dst++ = '0'; if (dst < end) *dst++ = 'x'; p = fmt_uint64(tmp, (uintptr_t)va_arg(ap, void*), 16, 0, '0', false); *p = '\0'; for (p = tmp; *p && dst < end;) *dst++ = *p++; break;
            case '%': *dst++ = '%'; break;
            default: break;
        }
        fmt++;
    }
    *dst = '\0';
    return (int)(dst - buf);
}

int lib_snprintf(char* buf, size_t n, const char* fmt, ...) { va_list ap; va_start(ap, fmt); int ret = lib_vsnprintf(buf, n, fmt, ap); va_end(ap); return ret; }
int lib_vfprintf(FILE* f, const char* fmt, va_list ap) { char buf[4096]; int len = lib_vsnprintf(buf, sizeof(buf), fmt, ap); if (len > 0) lib_fwrite(buf, 1, len, f); return len; }
int lib_fprintf(FILE* f, const char* fmt, ...) { va_list ap; va_start(ap, fmt); int ret = lib_vfprintf(f, fmt, ap); va_end(ap); return ret; }
int lib_vprintf(const char* fmt, va_list ap) { return lib_vfprintf(lib_stdout_file, fmt, ap); }
int lib_printf(const char* fmt, ...) { va_list ap; va_start(ap, fmt); int ret = lib_vprintf(fmt, ap); va_end(ap); return ret; }
int lib_puts(const char* s) { int ret = lib_fputs(s, lib_stdout_file); if (ret >= 0) ret = lib_fputc('\n', lib_stdout_file); return ret; }

#ifdef PLATFORM_WINDOWS

#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xC000003AL)
#define STATUS_ACCESS_DENIED         ((NTSTATUS)0xC0000022L)

static int ntstatus_to_errno(NTSTATUS status) {
    switch (status) {
        case STATUS_OBJECT_NAME_COLLISION: return EEXIST;
        case STATUS_OBJECT_NAME_NOT_FOUND:
        case STATUS_OBJECT_PATH_NOT_FOUND: return ENOENT;
        case STATUS_ACCESS_DENIED: return EACCES;
        default: return EINVAL;
    }
}

int lib_wmkdir(const WCHAR* path) {
    UNICODE_STRING nt_path = {0};
    if (!path_to_nt(path, &nt_path)) return -1;
    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES), NULL, &nt_path, OBJ_CASE_INSENSITIVE, NULL, NULL };
    HANDLE h; IO_STATUS_BLOCK iosb;
    NTSTATUS status = NtCreateFile(&h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    RtlFreeUnicodeString(&nt_path);
    if (NT_SUCCESS(status)) { NtClose(h); return 0; }
    lib_errno_val = ntstatus_to_errno(status);
    return -1;
}

int lib_mkdir(const char* path) {
    WCHAR wpath[1024]; utf8_to_utf16(path, wpath, 1024);
    return lib_wmkdir(wpath);
}

int lib_wremove(const WCHAR* path) {
    UNICODE_STRING nt_path = {0};
    if (!path_to_nt(path, &nt_path)) return -1;
    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES), NULL, &nt_path, OBJ_CASE_INSENSITIVE, NULL, NULL };
    HANDLE h; IO_STATUS_BLOCK iosb;
    NTSTATUS status = NtCreateFile(&h, DELETE | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    RtlFreeUnicodeString(&nt_path);
    if (NT_SUCCESS(status)) { NtClose(h); return 0; }
    lib_errno_val = (int)status;
    return -1;
}

int lib_remove(const char* path) {
    WCHAR wpath[1024]; utf8_to_utf16(path, wpath, 1024);
    return lib_wremove(wpath);
}

int lib_rmdir(const char* path) {
    WCHAR wpath[1024]; utf8_to_utf16(path, wpath, 1024);
    UNICODE_STRING nt_path = {0};
    if (!path_to_nt(wpath, &nt_path)) return -1;
    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES), NULL, &nt_path, OBJ_CASE_INSENSITIVE, NULL, NULL };
    HANDLE h; IO_STATUS_BLOCK iosb;
    NTSTATUS status = NtCreateFile(&h, DELETE | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_DELETE, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    RtlFreeUnicodeString(&nt_path);
    if (NT_SUCCESS(status)) { NtClose(h); return 0; }
    lib_errno_val = (int)status;
    return -1;
}

int lib_rename(const char* old_path, const char* new_path) {
    WCHAR wold[1024]; utf8_to_utf16(old_path, wold, 1024);
    WCHAR wnew[1024]; utf8_to_utf16(new_path, wnew, 1024);

    HANDLE h = nt_open_file(wold, DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_DIRECTORY_FILE);
    if (h == INVALID_HANDLE_VALUE) return -1;

    UNICODE_STRING nt_new = {0};
    if (!path_to_nt(wnew, &nt_new)) { NtClose(h); return -1; }

    struct {
        uint8_t ReplaceIfExists;
        HANDLE RootDirectory;
        ULONG FileNameLength;
        WCHAR FileName[1024];
    } rename_info;
    rename_info.ReplaceIfExists = 0;
    rename_info.RootDirectory = NULL;
    rename_info.FileNameLength = nt_new.Length;
    memcpy(rename_info.FileName, nt_new.Buffer, nt_new.Length);

    IO_STATUS_BLOCK iosb;
    NTSTATUS status = NtSetInformationFile(h, &iosb, &rename_info,
        (ULONG)(sizeof(rename_info) - sizeof(rename_info.FileName) + nt_new.Length),
        FileRenameInformation);

    RtlFreeUnicodeString(&nt_new);
    NtClose(h);
    if (NT_SUCCESS(status)) return 0;
    lib_errno_val = (int)status;
    return -1;
}

typedef struct { HANDLE dir_handle; WCHAR pattern[260]; uint8_t buffer[4096]; uint32_t buf_pos; uint32_t buf_len; bool first_call; } FindState;

static HANDLE open_directory_for_enum(const char* pattern, WCHAR* out_pattern) {
    char dir_path[1024]; lib_strncpy(dir_path, pattern, sizeof(dir_path) - 1); dir_path[sizeof(dir_path) - 1] = '\0';
    char* last_sep = lib_strrchr(dir_path, '\\'); if (!last_sep) last_sep = lib_strrchr(dir_path, '/');
    const char* wildcard = last_sep ? (last_sep + 1) : pattern;
    if (last_sep) *last_sep = '\0'; else { dir_path[0] = '.'; dir_path[1] = '\0'; }
    utf8_to_utf16(wildcard, out_pattern, 260);
    WCHAR wdir[1024]; utf8_to_utf16(dir_path, wdir, 1024);
    return nt_open_file(wdir, FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_DIRECTORY_FILE);
}

static bool fill_finddata(FILE_BOTH_DIR_INFORMATION* info, lib_finddata_t* data) {
    data->attrib = info->FileAttributes;
    data->time_create = info->CreationTime.QuadPart;
    data->time_access = info->LastAccessTime.QuadPart;
    data->time_write = info->LastWriteTime.QuadPart;
    data->size = info->EndOfFile.QuadPart;
    utf16_to_utf8(info->FileName, data->name, 260);
    return true;
}

intptr_t lib_findfirst(const char* pattern, lib_finddata_t* data) {
    FindState* state = lib_malloc(sizeof(FindState));
    if (!state) return -1;
    lib_memset(state, 0, sizeof(FindState)); state->first_call = true;
    state->dir_handle = open_directory_for_enum(pattern, state->pattern);
    if (state->dir_handle == INVALID_HANDLE_VALUE) { lib_free(state); return -1; }
    if (lib_findnext((intptr_t)state, data) != 0) { NtClose(state->dir_handle); lib_free(state); return -1; }
    return (intptr_t)state;
}

int lib_findnext(intptr_t handle, lib_finddata_t* data) {
    if (handle == -1) return -1;
    FindState* state = (FindState*)handle;
    while (1) {
        if (state->buf_pos < state->buf_len) {
            FILE_BOTH_DIR_INFORMATION* info = (FILE_BOTH_DIR_INFORMATION*)(state->buffer + state->buf_pos);
            state->buf_pos = info->NextEntryOffset ? state->buf_pos + info->NextEntryOffset : state->buf_len;
            fill_finddata(info, data);
            return 0;
        }
        IO_STATUS_BLOCK iosb = {0}; UNICODE_STRING pattern_str = {0};
        if (state->first_call && state->pattern[0]) {
            pattern_str.Buffer = state->pattern; pattern_str.Length = 0;
            while (state->pattern[pattern_str.Length / 2]) pattern_str.Length += 2;
            pattern_str.MaximumLength = pattern_str.Length + 2;
        }
        NTSTATUS status = NtQueryDirectoryFile(state->dir_handle, NULL, NULL, NULL, &iosb, state->buffer, sizeof(state->buffer),
            FileBothDirectoryInformation, 0, state->first_call ? &pattern_str : NULL, state->first_call ? 1 : 0);
        state->first_call = false;
        if (status == STATUS_NO_MORE_FILES || !NT_SUCCESS(status)) return -1;
        state->buf_pos = 0; state->buf_len = (uint32_t)iosb.Information;
    }
}

int lib_findclose(intptr_t handle) {
    if (handle == -1) return 0;
    FindState* state = (FindState*)handle;
    NtClose(state->dir_handle); lib_free(state);
    return 0;
}

bool lib_set_file_times_ntfs(FILE* f, int64_t modified_time, int64_t access_time) {
    if (!f || !f->handle || f->handle == INVALID_HANDLE_VALUE) return false;
    FILE_BASIC_INFORMATION info = {0}; IO_STATUS_BLOCK iosb;
    NtQueryInformationFile(f->handle, &iosb, &info, sizeof(info), FileBasicInformation);
    info.LastWriteTime.QuadPart = modified_time;
    info.LastAccessTime.QuadPart = access_time;
    return NT_SUCCESS(NtSetInformationFile(f->handle, &iosb, &info, sizeof(info), FileBasicInformation));
}

static int lib_wutime_impl(const WCHAR* path, int64_t modified_time, int64_t access_time, bool is_dir) {
    HANDLE h = nt_open_file(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
        is_dir ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE);
    if (h == INVALID_HANDLE_VALUE) return -1;
    FILE_BASIC_INFORMATION info = {0}; IO_STATUS_BLOCK iosb;
    NtQueryInformationFile(h, &iosb, &info, sizeof(info), FileBasicInformation);
    info.LastAccessTime.QuadPart = access_time;
    info.LastWriteTime.QuadPart = modified_time;
    NTSTATUS status = NtSetInformationFile(h, &iosb, &info, sizeof(info), FileBasicInformation);
    NtClose(h);
    return NT_SUCCESS(status) ? 0 : -1;
}

int lib_wutime(const WCHAR* path, int64_t modified_time, int64_t access_time) { return lib_wutime_impl(path, modified_time, access_time, false); }
int lib_wutime_dir(const WCHAR* path, int64_t modified_time, int64_t access_time) { return lib_wutime_impl(path, modified_time, access_time, true); }

#else

int lib_mkdir(const char* path) {
    long ret = syscall3(SYS_mkdirat, AT_FDCWD, (long)path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    if (ret < 0) { lib_errno_val = (int)(-ret); return -1; }
    return 0;
}

int lib_remove(const char* path) {
    long ret = syscall3(SYS_unlinkat, AT_FDCWD, (long)path, 0);
    if (ret < 0) { lib_errno_val = (int)(-ret); return -1; }
    return 0;
}

int lib_rmdir(const char* path) {
    long ret = syscall3(SYS_unlinkat, AT_FDCWD, (long)path, 0x200);
    if (ret < 0) { lib_errno_val = (int)(-ret); return -1; }
    return 0;
}

int lib_rename(const char* old_path, const char* new_path) {
    long ret = syscall4(SYS_renameat, AT_FDCWD, (long)old_path, AT_FDCWD, (long)new_path);
    if (ret < 0) { lib_errno_val = (int)(-ret); return -1; }
    return 0;
}

typedef struct {
    int fd;
    char dir_path[1024];
    char pattern[260];
    uint8_t buffer[4096];
    uint32_t buf_pos;
    uint32_t buf_len;
} LinuxFindState;

static bool match_pattern(const char* name, const char* pattern) {
    while (*pattern) {
        if (*pattern == '*') {
            pattern++;
            if (!*pattern) return true;
            while (*name) { if (match_pattern(name, pattern)) return true; name++; }
            return false;
        }
        if (*pattern == '?' || *pattern == *name) { pattern++; name++; }
        else return false;
    }
    return *name == '\0';
}

intptr_t lib_findfirst(const char* pattern, lib_finddata_t* data) {
    LinuxFindState* state = lib_malloc(sizeof(LinuxFindState));
    if (!state) return -1;
    lib_memset(state, 0, sizeof(LinuxFindState));

    lib_strncpy(state->dir_path, pattern, sizeof(state->dir_path) - 1);
    char* last_slash = lib_strrchr(state->dir_path, '/');
    if (last_slash) {
        lib_strncpy(state->pattern, last_slash + 1, sizeof(state->pattern) - 1);
        *last_slash = '\0';
        if (state->dir_path[0] == '\0') lib_strcpy(state->dir_path, "/");
    } else {
        lib_strncpy(state->pattern, state->dir_path, sizeof(state->pattern) - 1);
        lib_strcpy(state->dir_path, ".");
    }

    long fd = syscall3(SYS_open, (long)state->dir_path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) { lib_free(state); lib_errno_val = (int)(-fd); return -1; }
    state->fd = (int)fd;

    if (lib_findnext((intptr_t)state, data) != 0) {
        syscall1(SYS_close, state->fd);
        lib_free(state);
        return -1;
    }
    return (intptr_t)state;
}

int lib_findnext(intptr_t handle, lib_finddata_t* data) {
    if (handle == -1) return -1;
    LinuxFindState* state = (LinuxFindState*)handle;

    while (1) {
        while (state->buf_pos < state->buf_len) {
            struct linux_dirent64* d = (struct linux_dirent64*)(state->buffer + state->buf_pos);
            state->buf_pos += d->d_reclen;

            if (d->d_name[0] == '.' && (d->d_name[1] == '\0' || (d->d_name[1] == '.' && d->d_name[2] == '\0')))
                continue;

            if (!match_pattern(d->d_name, state->pattern)) continue;

            lib_strncpy(data->name, d->d_name, 260);
            data->attrib = (d->d_type == DT_DIR) ? _A_SUBDIR : 0;

            char full_path[1280];
            lib_snprintf(full_path, sizeof(full_path), "%s/%s", state->dir_path, d->d_name);
            struct linux_stat st;
            if (syscall4(SYS_newfstatat, AT_FDCWD, (long)full_path, (long)&st, 0) >= 0) {
                data->size = st.st_size;
                data->time_write = st.st_mtime_sec;
                data->time_access = st.st_atime_sec;
                data->time_create = st.st_ctime_sec;
            }
            return 0;
        }

        long ret = syscall3(SYS_getdents64, state->fd, (long)state->buffer, sizeof(state->buffer));
        if (ret <= 0) return -1;
        state->buf_pos = 0;
        state->buf_len = (uint32_t)ret;
    }
}

int lib_findclose(intptr_t handle) {
    if (handle == -1) return 0;
    LinuxFindState* state = (LinuxFindState*)handle;
    syscall1(SYS_close, state->fd);
    lib_free(state);
    return 0;
}

#endif

int lib_atoi(const char* s) {
    int result = 0, sign = 1;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { sign = -1; s++; } else if (*s == '+') s++;
    while (*s >= '0' && *s <= '9') { result = result * 10 + (*s - '0'); s++; }
    return sign * result;
}

int lib_isxdigit(int c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

int* lib_errno_func(void) { return &lib_errno_val; }

#ifdef PLATFORM_WINDOWS
void lib_exit(int status) { lib_fflush(lib_stdout_file); lib_fflush(lib_stderr_file); RtlExitUserProcess((NTSTATUS)status); }
#else
void lib_exit(int status) { lib_fflush(lib_stdout_file); lib_fflush(lib_stderr_file); syscall1(SYS_exit_group, status); __builtin_unreachable(); }
#endif

#ifdef PLATFORM_WINDOWS

static void init_stdio_handles(void) {
    PEB* peb = lib_get_peb();
    RTL_USER_PROCESS_PARAMETERS* params = peb->ProcessParameters;
    lib_stdin_handle = params->StandardInput;
    lib_stdout_handle = params->StandardOutput;
    lib_stderr_handle = params->StandardError;

    lib_stdout_impl.handle = lib_stdout_handle;
    lib_stdout_impl.buffer = lib_malloc(4096);
    lib_stdout_impl.buf_cap = 4096;
    lib_stdout_impl.flags = LIB_FILE_WRITE;

    lib_stderr_impl.handle = lib_stderr_handle;
    lib_stderr_impl.buffer = lib_malloc(256);
    lib_stderr_impl.buf_cap = 256;
    lib_stderr_impl.flags = LIB_FILE_WRITE;

    lib_stdin_impl.handle = lib_stdin_handle;
    lib_stdin_impl.buffer = lib_malloc(4096);
    lib_stdin_impl.buf_cap = 4096;
    lib_stdin_impl.flags = LIB_FILE_READ;

    fd_table[0] = lib_stdin_handle;
    fd_table[1] = lib_stdout_handle;
    fd_table[2] = lib_stderr_handle;
}

void lib_init(void) {
    PEB* peb = lib_get_peb();
    lib_heap = peb->ProcessHeap;
    init_stdio_handles();
}

static int parse_command_line(char*** out_argv) {
    PEB* peb = lib_get_peb();
    RTL_USER_PROCESS_PARAMETERS* params = peb->ProcessParameters;
    WCHAR* cmd_line = params->CommandLine.Buffer;
    int cmd_len = params->CommandLine.Length / 2;

    char* utf8_cmd = lib_malloc(cmd_len * 4 + 1);
    if (!utf8_cmd) return 0;
    utf16_to_utf8(cmd_line, utf8_cmd, cmd_len * 4 + 1);

    int argc = 0;
    char* p = utf8_cmd;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        argc++;
        if (*p == '"') { p++; while (*p && *p != '"') p++; if (*p == '"') p++; }
        else { while (*p && *p != ' ' && *p != '\t') p++; }
    }

    char** argv = lib_malloc((argc + 1) * sizeof(char*));
    if (!argv) { lib_free(utf8_cmd); return 0; }

    p = utf8_cmd;
    int arg_idx = 0;
    while (*p && arg_idx < argc) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        char* arg_start, *arg_end;
        if (*p == '"') { arg_start = ++p; while (*p && *p != '"') p++; arg_end = p; if (*p == '"') p++; }
        else { arg_start = p; while (*p && *p != ' ' && *p != '\t') p++; arg_end = p; }
        size_t len = arg_end - arg_start;
        char* arg = lib_malloc(len + 1);
        if (arg) { lib_memcpy(arg, arg_start, len); arg[len] = '\0'; argv[arg_idx++] = arg; }
    }
    argv[arg_idx] = NULL;
    *out_argv = argv;
    lib_free(utf8_cmd);
    return argc;
}

void _start(void) {
    lib_init();
    char** argv; int argc = parse_command_line(&argv);
    int result = lib_main(argc, argv);
    for (int i = 0; i < argc; i++) lib_free(argv[i]);
    lib_free(argv);
    lib_exit(result);
}

#else

static uint8_t stdout_buf[4096];
static uint8_t stderr_buf[256];
static uint8_t stdin_buf[4096];

void lib_init(void) {
    heap_init();

    lib_stdout_impl.fd = 1;
    lib_stdout_impl.buffer = stdout_buf;
    lib_stdout_impl.buf_cap = sizeof(stdout_buf);
    lib_stdout_impl.flags = LIB_FILE_WRITE;

    lib_stderr_impl.fd = 2;
    lib_stderr_impl.buffer = stderr_buf;
    lib_stderr_impl.buf_cap = sizeof(stderr_buf);
    lib_stderr_impl.flags = LIB_FILE_WRITE;

    lib_stdin_impl.fd = 0;
    lib_stdin_impl.buffer = stdin_buf;
    lib_stdin_impl.buf_cap = sizeof(stdin_buf);
    lib_stdin_impl.flags = LIB_FILE_READ;
}

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile (
        "xor %%rbp, %%rbp\n\t"
        "mov (%%rsp), %%rdi\n\t"
        "lea 8(%%rsp), %%rsi\n\t"
        "call _start_main\n\t"
        "mov %%rax, %%rdi\n\t"
        "mov $231, %%rax\n\t"
        "syscall\n\t"
        ::: "memory"
    );
}

__attribute__((used)) int _start_main(int argc, char** argv) {
    lib_init();
    int ret = lib_main(argc, argv);
    lib_fflush(lib_stdout_file);
    lib_fflush(lib_stderr_file);
    return ret;
}

#endif
