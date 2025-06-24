cmake_minimum_required(VERSION 3.16)
project(unsegaREBORN C)

set(CMAKE_C_STANDARD 11)

option(BUILD_STATIC "Build a static executable" OFF)

if(BUILD_STATIC)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(OPENSSL_MSVC_STATIC_RT TRUE)
    if(WIN32)
        set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a)
    else()
        set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
    endif()
endif()

find_package(OpenSSL REQUIRED)

add_library(unsega STATIC
    src/crypto.c
    src/keys.c
    include/crypto.h
    src/exfat.c
    include/exfat.h
    src/ntfs.c
    include/ntfs.h
    src/bootid.c
    include/bootid.h
    include/common.h
)

target_include_directories(unsega PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(unsega PUBLIC OpenSSL::Crypto)

if (MSVC)
    target_compile_definitions(unsega PUBLIC _CRT_SECURE_NO_WARNINGS)
    if (MSVC_VERSION LESS 1900)
        target_compile_definitions(unsega PUBLIC snprintf=_snprintf)
    endif()
elseif(UNIX)
    target_compile_definitions(unsega PUBLIC _FILE_OFFSET_BITS=64)
endif()

add_executable(unsegareborn src/main.c)
target_link_libraries(unsegareborn PRIVATE unsega)

if(BUILD_STATIC)
    if(MSVC)
        set_property(TARGET unsegareborn PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        set_property(TARGET unsega PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        
        target_link_libraries(unsegareborn PRIVATE 
            ws2_32 
            crypt32 
            bcrypt
            Advapi32
        )
        
        target_link_options(unsegareborn PRIVATE /INCREMENTAL:NO)
    else()
        target_link_options(unsegareborn PRIVATE -static)
        if(UNIX AND NOT APPLE)
            target_link_libraries(unsegareborn PRIVATE dl pthread)
        endif()
    endif()
endif()

install(TARGETS unsegareborn RUNTIME DESTINATION bin)
