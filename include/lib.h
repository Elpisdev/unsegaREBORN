#ifndef LIB_H
#define LIB_H

#if defined(_WIN32) || defined(_WIN64)
    #define PLATFORM_WINDOWS 1
#elif defined(__linux__) && defined(__x86_64__)
    #define PLATFORM_LINUX 1
#else
    #error "unsupported platform"
#endif

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef signed short int16_t;
typedef unsigned short uint16_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef signed long long int64_t;
typedef unsigned long long uint64_t;

#ifdef PLATFORM_WINDOWS
typedef uint64_t size_t;
typedef int64_t ssize_t;
typedef uint64_t uintptr_t;
typedef int64_t intptr_t;
#else
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned long uintptr_t;
typedef long intptr_t;
#endif

typedef int64_t off_t;
typedef int64_t time_t;
#ifndef __bool_true_false_are_defined
  #if __STDC_VERSION__ < 202311L
    typedef _Bool bool;
    #define true 1
    #define false 0
  #endif
  #define __bool_true_false_are_defined 1
#endif

#define NULL ((void*)0)

typedef __builtin_va_list va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)
#define va_end(ap) __builtin_va_end(ap)
#define va_arg(ap, type) __builtin_va_arg(ap, type)

#ifdef __cplusplus
extern "C" {
#endif

#define ENOENT  2
#define EACCES  13
#define EEXIST  17
#define EINVAL  22

#ifdef PLATFORM_WINDOWS

typedef long NTSTATUS;
typedef void* HANDLE;
typedef uint16_t WCHAR;
typedef uint32_t ULONG;
typedef int32_t LONG;
typedef uint64_t ULONGLONG;
typedef int64_t LONGLONG;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_END_OF_FILE          ((NTSTATUS)0xC0000011L)
#define STATUS_NO_MORE_FILES        ((NTSTATUS)0x80000006L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)

#define FILE_READ_DATA            0x0001
#define FILE_WRITE_DATA           0x0002
#define FILE_ADD_FILE             0x0002
#define FILE_APPEND_DATA          0x0004
#define FILE_READ_ATTRIBUTES      0x0080
#define FILE_WRITE_ATTRIBUTES     0x0100
#define FILE_TRAVERSE             0x0020
#define FILE_LIST_DIRECTORY       0x0001
#define DELETE                    0x00010000L
#define SYNCHRONIZE               0x00100000L

#define FILE_SHARE_READ           0x00000001
#define FILE_SHARE_WRITE          0x00000002
#define FILE_SHARE_DELETE         0x00000004

#define FILE_OPEN                 0x00000001
#define FILE_CREATE               0x00000002
#define FILE_OVERWRITE_IF         0x00000005
#define FILE_OPEN_IF              0x00000003

#define FILE_DIRECTORY_FILE           0x00000001
#define FILE_SEQUENTIAL_ONLY          0x00000004
#define FILE_NON_DIRECTORY_FILE       0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT  0x00000020
#define FILE_DELETE_ON_CLOSE          0x00001000

#define FILE_ATTRIBUTE_NORMAL         0x00000080
#define FILE_ATTRIBUTE_DIRECTORY      0x00000010

#define OBJ_CASE_INSENSITIVE      0x00000040

typedef struct _UNICODE_STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    WCHAR* Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG Attributes;
    void* SecurityDescriptor;
    void* SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union { NTSTATUS Status; void* Pointer; };
    uintptr_t Information;
} IO_STATUS_BLOCK;

typedef struct _LARGE_INTEGER {
    LONGLONG QuadPart;
} LARGE_INTEGER;

typedef struct _FILE_POSITION_INFORMATION {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    uint8_t DeletePending;
    uint8_t Directory;
} FILE_STANDARD_INFORMATION;

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    uint8_t ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS {
    FileBothDirectoryInformation = 3,
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FileRenameInformation = 10,
    FilePositionInformation = 14,
} FILE_INFORMATION_CLASS;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    uint8_t _Reserved0[0x20];
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    uint8_t _Reserved1[0x38];
    UNICODE_STRING CommandLine;
    WCHAR* Environment;
} RTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    uint8_t _Reserved0[0x20];
    RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    void* SubSystemData;
    HANDLE ProcessHeap;
} PEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    void* PebBaseAddress;
    uintptr_t AffinityMask;
    int32_t BasePriority;
    uintptr_t UniqueProcessId;
    uintptr_t InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    uint8_t Reserved1[48];
    UNICODE_STRING ImageName;
    int32_t BasePriority;
    uintptr_t UniqueProcessId;
} SYSTEM_PROCESS_INFORMATION;

#define ProcessBasicInformation 0
#define SystemProcessInformation 5

#define CRT_OFFSETOF(type, member) ((size_t)&(((type*)0)->member))

__declspec(dllimport) NTSTATUS __stdcall NtCreateFile(HANDLE*, ULONG, OBJECT_ATTRIBUTES*, IO_STATUS_BLOCK*, LARGE_INTEGER*, ULONG, ULONG, ULONG, ULONG, void*, ULONG);
__declspec(dllimport) NTSTATUS __stdcall NtReadFile(HANDLE, HANDLE, void*, void*, IO_STATUS_BLOCK*, void*, ULONG, LARGE_INTEGER*, ULONG*);
__declspec(dllimport) NTSTATUS __stdcall NtWriteFile(HANDLE, HANDLE, void*, void*, IO_STATUS_BLOCK*, const void*, ULONG, LARGE_INTEGER*, ULONG*);
__declspec(dllimport) NTSTATUS __stdcall NtClose(HANDLE);
__declspec(dllimport) NTSTATUS __stdcall NtQueryInformationFile(HANDLE, IO_STATUS_BLOCK*, void*, ULONG, FILE_INFORMATION_CLASS);
__declspec(dllimport) NTSTATUS __stdcall NtSetInformationFile(HANDLE, IO_STATUS_BLOCK*, void*, ULONG, FILE_INFORMATION_CLASS);
__declspec(dllimport) NTSTATUS __stdcall NtQueryDirectoryFile(HANDLE, HANDLE, void*, void*, IO_STATUS_BLOCK*, void*, ULONG, FILE_INFORMATION_CLASS, uint8_t, UNICODE_STRING*, uint8_t);
__declspec(dllimport) NTSTATUS __stdcall NtQuerySystemTime(LARGE_INTEGER*);
__declspec(dllimport) NTSTATUS __stdcall NtQueryInformationProcess(HANDLE, ULONG, void*, ULONG, ULONG*);
__declspec(dllimport) NTSTATUS __stdcall NtQuerySystemInformation(ULONG, void*, ULONG, ULONG*);
__declspec(dllimport) void* __stdcall RtlAllocateHeap(HANDLE, ULONG, size_t);
__declspec(dllimport) void* __stdcall RtlReAllocateHeap(HANDLE, ULONG, void*, size_t);
__declspec(dllimport) uint8_t __stdcall RtlFreeHeap(HANDLE, ULONG, void*);
__declspec(dllimport) void __stdcall RtlExitUserProcess(NTSTATUS);
__declspec(dllimport) NTSTATUS __stdcall RtlDosPathNameToNtPathName_U_WithStatus(const WCHAR*, UNICODE_STRING*, WCHAR**, void*);
__declspec(dllimport) void __stdcall RtlFreeUnicodeString(UNICODE_STRING*);

static inline PEB* lib_get_peb(void) {
    PEB* peb;
    __asm__ volatile ("mov %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

#else

#define SYS_read            0
#define SYS_write           1
#define SYS_open            2
#define SYS_close           3
#define SYS_lseek           8
#define SYS_mmap            9
#define SYS_munmap          11
#define SYS_getdents64      217
#define SYS_exit_group      231
#define SYS_mkdirat         258
#define SYS_newfstatat      262
#define SYS_unlinkat        263
#define SYS_renameat        264
#define SYS_utimensat       280

#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_TRUNC     0x0200
#define O_APPEND    0x0400
#define O_DIRECTORY 0x10000

#define S_IRWXU 0700
#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IRGRP 0040
#define S_IXGRP 0010
#define S_IROTH 0004
#define S_IXOTH 0001

#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define AT_FDCWD (-100)

#define DT_DIR  4

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
};

struct linux_stat {
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint32_t st_mode;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t __pad0;
    uint64_t st_rdev;
    int64_t st_size;
    int64_t st_blksize;
    int64_t st_blocks;
    int64_t st_atime_sec;
    int64_t st_atime_nsec;
    int64_t st_mtime_sec;
    int64_t st_mtime_nsec;
    int64_t st_ctime_sec;
    int64_t st_ctime_nsec;
    int64_t __unused[3];
};

struct linux_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

static inline long syscall1(long n, long a1) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall2(long n, long a1, long a2) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall3(long n, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall4(long n, long a1, long a2, long a3, long a4) {
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}

#endif

#define _A_SUBDIR 0x10

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

#define EOF (-1)

#ifdef PLATFORM_WINDOWS
extern HANDLE lib_heap;
extern HANDLE lib_stdout_handle;
extern HANDLE lib_stderr_handle;
extern HANDLE lib_stdin_handle;
#endif

extern int lib_errno_val;

void* lib_malloc(size_t size);
void* lib_calloc(size_t count, size_t size);
void* lib_realloc(void* ptr, size_t size);
void lib_free(void* ptr);

#define malloc lib_malloc
#define calloc lib_calloc
#define realloc lib_realloc
#define free lib_free

size_t lib_strlen(const char* s);
char* lib_strcpy(char* dst, const char* src);
char* lib_strncpy(char* dst, const char* src, size_t n);
int lib_strcmp(const char* s1, const char* s2);
int lib_strncmp(const char* s1, const char* s2, size_t n);
char* lib_strchr(const char* s, int c);
char* lib_strrchr(const char* s, int c);
char* lib_strstr(const char* haystack, const char* needle);
char* lib_strncat(char* dst, const char* src, size_t n);
void* lib_memcpy(void* dst, const void* src, size_t n);
void* lib_memset(void* dst, int c, size_t n);
int lib_memcmp(const void* s1, const void* s2, size_t n);

#define strlen lib_strlen
#define strcpy lib_strcpy
#define strncpy lib_strncpy
#define strcmp lib_strcmp
#define strncmp lib_strncmp
#define strchr lib_strchr
#define strrchr lib_strrchr
#define strstr lib_strstr
#define strncat lib_strncat

#define memcpy lib_memcpy
#define memset lib_memset
#define memcmp lib_memcmp

#define LIB_FILE_READ   0x01
#define LIB_FILE_WRITE  0x02
#define LIB_FILE_EOF    0x04
#define LIB_FILE_ERROR  0x08
#define LIB_FILE_APPEND 0x10

#define LIB_IOBUF_SIZE (64 * 1024)

typedef struct {
#ifdef PLATFORM_WINDOWS
    HANDLE handle;
#else
    int fd;
#endif
    uint8_t* buffer;
    uint32_t buf_cap;
    uint32_t buf_pos;
    uint32_t buf_fill;
    int64_t file_pos;
    uint32_t flags;
} FILE;

extern FILE* lib_stdout_file;
extern FILE* lib_stderr_file;
extern FILE* lib_stdin_file;

#define stdin  lib_stdin_file
#define stdout lib_stdout_file
#define stderr lib_stderr_file

FILE* lib_fopen(const char* path, const char* mode);
size_t lib_fread(void* buf, size_t size, size_t count, FILE* f);
size_t lib_fwrite(const void* buf, size_t size, size_t count, FILE* f);
int lib_fseeki64(FILE* f, int64_t offset, int whence);
int64_t lib_ftelli64(FILE* f);
int lib_fclose(FILE* f);
int lib_fflush(FILE* f);
int lib_feof(FILE* f);
char* lib_fgets(char* buf, int n, FILE* f);
void lib_rewind(FILE* f);

#define fopen lib_fopen
#define fread lib_fread
#define fwrite lib_fwrite
#define _fseeki64 lib_fseeki64
#define fseeko lib_fseeki64
#define _ftelli64 lib_ftelli64
#define ftello lib_ftelli64
#define fclose lib_fclose
#define fflush lib_fflush
#define feof lib_feof
#define fgets lib_fgets
#define rewind lib_rewind

#ifdef PLATFORM_WINDOWS
size_t utf8_to_utf16(const char* utf8, WCHAR* utf16, size_t utf16_max);
FILE* lib_wfopen(const WCHAR* path, const WCHAR* mode);
FILE* lib_wfopen_prealloc(const WCHAR* path, uint64_t size);
HANDLE lib_open_dir_handle(const WCHAR* path);
FILE* lib_fopen_relative(HANDLE dir_handle, const WCHAR* filename, uint64_t prealloc_size);
bool lib_set_file_times_ntfs(FILE* f, int64_t modified_time, int64_t access_time);
int lib_wutime(const WCHAR* path, int64_t modified_time, int64_t access_time);
int lib_wutime_dir(const WCHAR* path, int64_t modified_time, int64_t access_time);
#define _wfopen lib_wfopen
size_t lib_fwrite_direct(FILE* f, const void* buf, size_t size);
#endif

int lib_printf(const char* fmt, ...);
int lib_fprintf(FILE* f, const char* fmt, ...);
int lib_snprintf(char* buf, size_t n, const char* fmt, ...);
int lib_vprintf(const char* fmt, va_list ap);
int lib_vfprintf(FILE* f, const char* fmt, va_list ap);
int lib_vsnprintf(char* buf, size_t n, const char* fmt, va_list ap);
int lib_puts(const char* s);

#define printf lib_printf
#define fprintf lib_fprintf
#define snprintf lib_snprintf
#define vprintf lib_vprintf
#define vfprintf lib_vfprintf
#define vsnprintf lib_vsnprintf
#define puts lib_puts

int lib_mkdir(const char* path);
int lib_rmdir(const char* path);
int lib_remove(const char* path);
int lib_rename(const char* old_path, const char* new_path);

#define mkdir lib_mkdir
#define rmdir lib_rmdir
#define _rmdir lib_rmdir
#define remove lib_remove
#define rename lib_rename

#ifdef PLATFORM_WINDOWS
int lib_wmkdir(const WCHAR* path);
int lib_wremove(const WCHAR* path);
#define _wmkdir lib_wmkdir
#define _wremove lib_wremove
#endif

typedef struct {
    uint32_t attrib;
    int64_t time_create;
    int64_t time_access;
    int64_t time_write;
    int64_t size;
    char name[260];
} lib_finddata_t;

intptr_t lib_findfirst(const char* pattern, lib_finddata_t* data);
int lib_findnext(intptr_t handle, lib_finddata_t* data);
int lib_findclose(intptr_t handle);

#define _finddata_t lib_finddata_t
#define _findfirst lib_findfirst
#define _findnext lib_findnext
#define _findclose lib_findclose

time_t lib_time(time_t* t);
double lib_difftime(time_t t1, time_t t0);

#define time lib_time
#define difftime lib_difftime

int lib_atoi(const char* s);
int lib_isxdigit(int c);

#define atoi lib_atoi
#define isxdigit lib_isxdigit

int* lib_errno_func(void);

#define errno (*lib_errno_func())

void lib_exit(int status);

#define exit lib_exit

#ifdef PLATFORM_WINDOWS
#define PATH_SEPARATOR "\\"
#define PATH_SEP_CHAR '\\'
#else
#define PATH_SEPARATOR "/"
#define PATH_SEP_CHAR '/'
#endif

void lib_init(void);
int lib_main(int argc, char** argv);

#ifdef __cplusplus
}
#endif

#endif
