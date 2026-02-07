# unsegaREBORN

SEGA arcade image toolkit

## features

- APP/PACK and OPT (including APM3 type)
- NTFS and exFAT
- VHD (fixed, dynamic, differencing)
- direct stream from encrypted image
- timestamps
- AES-NI hardware acceleration

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
- `-k` keep all versions (each delta gets its own folder instead of stacking)
- `-s` silent
- `-v` verbose
- `-vn` version
- `-h` available flags

### deltas (differencing VHD)

base + update files are stacked into a single output by order.

```
unsegareborn -o out -p BASE DELTA1 DELTA2
```

result: `out/DELTA2/` with merged content (base + all updates applied in order)

### drag and drop

drag and drop is available on windows. multiple files are handled automatically.

## keys

prebuilt releases include keys. source does not.

to build from source:
1. copy `include/keys.inc.example` to `include/keys.inc`
2. add your keys in the format shown

format:
```c
{"SDEZ", {0xd1,0x36,...}},
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

build generates a version tag automatically (`YYYYMMDDNN`, revision increments per day):
```
sh build.cmd        # or build.cmd on windows
git tag $(./build/unsegareborn-* -vn | awk '{print $2}')
git push origin --tags
```

ci builds both platforms and creates a github release with binaries

## license

UNLICENSE
