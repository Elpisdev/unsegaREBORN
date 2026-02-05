#ifndef ERROR_H
#define ERROR_H

#include "lib.h"

typedef enum {
    ERR_OK = 0,
    ERR_MEMORY,
    ERR_FILE_OPEN,
    ERR_FILE_READ,
    ERR_FILE_WRITE,
    ERR_FILE_SEEK,
    ERR_INVALID_BOOTID,
    ERR_UNKNOWN_CONTAINER,
    ERR_KEY_NOT_FOUND,
    ERR_INVALID_KEY_FILE,
    ERR_AES_ALIGNMENT,
    ERR_IV_CALCULATION,
    ERR_INVALID_NTFS,
    ERR_INVALID_EXFAT,
    ERR_INVALID_VHD,
    ERR_MFT_CORRUPT,
    ERR_PATH_UNSAFE,
    ERR_DIR_CREATE,
    ERR_EXTRACTION_FAILED
} ErrorCode;

static inline const char* error_string(ErrorCode code) {
    static const char* const errs[] = {
        "ok", "mem", "open", "read", "write", "seek", "bootid", "container",
        "key", "keyfile", "align", "iv", "ntfs", "exfat", "vhd", "mft", "path", "mkdir", "extract"
    };
    return (code < sizeof(errs)/sizeof(errs[0])) ? errs[code] : "?";
}

#define FAIL(code) do { \
    fprintf(stderr, "error: %s\n", error_string(code)); \
} while(0)

#define FAIL_MSG(code, msg) do { \
    fprintf(stderr, "error: %s - %s\n", error_string(code), (msg)); \
} while(0)

#endif
