# unsegaREBORN

An all-in-one tool that unpacks (and optionally extracts) arcade SEGA images.

---

## Features

*   Decrypts update/app containers
*   Extracts the embedded
    * NTFS archives (with nested VHDs)
    * exFAT archives (cluster-by-cluster walker)
*   Cross-platform (Windows / Linux / macOS)  
    Uses plain C11 + OpenSSL, no fancy dependencies.
*   Can be built fully static (`--static`) if you need a drop-in binary.

---

## Building

### Unix-like (Linux / macOS)

```bash
./build.sh               # release build
./build.sh --debug       # debug symbols, no optimisation
./build.sh --static      # link everything statically

### Windows (MSVC or MinGW)

build.bat                :: release build
build.bat --debug        :: debug build
build.bat --static       :: static CRT + OpenSSL


## Usage

unsegareborn [-no] <image1> [image2 …]

  -no   just decrypt, do NOT auto-extract the embedded file system

The program writes a decrypted .ntfs or .exfat file next to the input
and, unless -no is given, immediately unpacks its contents into a folder
with the same stem.

You can also just drag and drop the image(s) on the program. ("-no" flag is disabled by default)

## Where do the keys come from?

They were all collected from leaks over time. 
If you have additional keys and want to contribute, feel free to open a PR.
If you are a gatekeeper, you can just use the built in custom key function.

## License

UNLICENSE

## Caveats / TODO

No APM3 support. Maybe will be added when I feel like it.
Child VHD won't be processed for app files. If the output VHD number is not zero (e.g. internal_1, internal_2) you are on your own.