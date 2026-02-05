# unsegaREBORN

SEGA arcade image toolkit

## features

- APP/OPT/APM3 decryption
- NTFS/exFAT support
- VHD support (fixed, dynamic, differencing)
- stream directly from encrypted image (no temp files)
- preserved timestamps
- AES-NI accelerated with software fallback

## build

```
build.cmd          # windows
sh build.cmd       # linux
```

output: `build/unsegareborn-{platform}-x64[.exe]`

## usage

```
unsegareborn [flags] <files>
```

flags:
- `-o dir` output directory
- `-n` decrypt only, skip extraction
- `-w` write intermediate .ntfs/.exfat files
- `-p file` parent for differencing VHD
- `-s` silent
- `-v` verbose
- `-vn` version

drag and drop works on windows

## keys

prebuilt releases include keys. source does not.

to build from source:
1. copy `include/keys.inc.example` to `include/keys.inc`
2. add your keys in the format shown

format:
```c
{"SDEZ", {0xd1,0x36,...}, {0xc4,0x84,...}, true},
```

## platforms

|   platform  |         method          |
|-------------|-------------------------|
| win x64     | native (ntdll only)     |
| win arm64   | x64 emulation           |
| linux x64   | native (static no libc) |
| linux arm64 | box64/qemu              |
| macos       | wine (untested)         |

## release

push version tag:
```
git tag 2026020501
git push origin 2026020501
```

ci builds both platforms and creates a github release with binaries

## license

UNLICENSE