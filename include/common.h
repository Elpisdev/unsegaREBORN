#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
  #include <direct.h>
  #define MKDIR(path) _mkdir(path)
  #define PATH_SEPARATOR "\\"
  #define STRDUP _strdup
  #define FSEEKO _fseeki64
  #define FTELLO _ftelli64
#else
  #include <sys/stat.h>
  #include <sys/types.h>
  #define MKDIR(path) mkdir((path), 0755)
  #define PATH_SEPARATOR "/"
  #define STRDUP strdup
  #define FSEEKO fseeko
  #define FTELLO ftello
#endif

#define MAX_PATH_LENGTH 256
#define MAX_FILENAME_LENGTH 256

#ifndef min
  #define min(a,b) ((a) < (b) ? (a) : (b))
#endif
#ifndef max
  #define max(a,b) ((a) > (b) ? (a) : (b))
#endif

#define SNPRINTF snprintf

#ifdef _WIN32
  #ifdef _MSC_VER
    #define STRCPY_S(dst, size, src) strcpy_s(dst, size, src)
    #define STRCAT_S(dst, size, src) strcat_s(dst, size, src)
  #else
    #define STRCPY_S(dst, size, src) do { strncpy(dst, src, (size)-1); (dst)[(size)-1] = '\0'; } while(0)
    #define STRCAT_S(dst, size, src) strncat(dst, src, (size) - strlen(dst) - 1)
  #endif
#else
  #define STRCPY_S(dst, size, src) do { strncpy(dst, src, (size)-1); (dst)[(size)-1] = '\0'; } while(0)
  #define STRCAT_S(dst, size, src) strncat(dst, src, (size) - strlen(dst) - 1)
#endif

#endif /* COMMON_H */

