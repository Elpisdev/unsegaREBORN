:<<"::BATCH_SECTION"
@echo off
goto :WINDOWS
::BATCH_SECTION
#!/bin/sh
set -e
mkdir -p build
DATESTR=$(date +%Y%m%d)
REV=-1
TAG_REV=$(git tag -l "${DATESTR}*" 2>/dev/null | sed "s/^${DATESTR}//" | sort -rn | head -1)
[ -n "$TAG_REV" ] && REV=$((10#$TAG_REV))
if [ -f build/.buildrev ]; then
    read LAST_DATE LAST_REV < build/.buildrev
    [ "$LAST_DATE" = "$DATESTR" ] && [ "$LAST_REV" -gt "$REV" ] && REV=$LAST_REV
fi
REV=$((REV + 1))
DATECODE=$(printf "%s%02d" "$DATESTR" "$REV")
echo "$DATESTR $REV" > build/.buildrev

SRC="src/lib.c src/main.c src/crypto.c src/keys.c src/exfat.c src/ntfs.c src/stream.c src/aes.c"

# Check for clang
command -v clang >/dev/null 2>&1 || { echo "error: clang not found"; exit 1; }

# Detect OS
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        OUT="build/unsegareborn-win-x64.exe"
        CFLAGS="-target x86_64-pc-windows-gnu -Oz -maes -msse4.1 -I include -fno-asynchronous-unwind-tables -fno-ident -ffunction-sections -fdata-sections -flto -ffreestanding -fno-builtin -fno-stack-protector -nostdlib -fno-unwind-tables -fno-exceptions -fmerge-all-constants -fno-addrsig"
        LDFLAGS="-fuse-ld=lld -Wl,--gc-sections -Wl,--icf=all -Wl,-e,_start -Wl,--subsystem,console -Wl,-s -Wl,--lto-Oz -L/mingw64/lib"
        LIBS="-lntdll"
        ;;
    *)
        OUT="build/unsegareborn-linux-x64"
        CFLAGS="-Oz -maes -msse4.1 -I include -fno-asynchronous-unwind-tables -fno-ident -ffunction-sections -fdata-sections -flto -ffreestanding -fno-builtin -fno-stack-protector -nostdlib -fno-unwind-tables -fno-exceptions -fmerge-all-constants -fno-addrsig"
        LDFLAGS="-fuse-ld=lld -Wl,--gc-sections -Wl,--icf=all -Wl,-e,_start -Wl,-s -Wl,--lto-O2 -static"
        LIBS=""
        ;;
esac

echo "building..."
clang $CFLAGS $LDFLAGS -DVERSION="\"$DATECODE\"" -o $OUT $SRC $LIBS
echo "done: $OUT ($(stat -c%s "$OUT" 2>/dev/null || stat -f%z "$OUT") bytes)"
exit 0

:WINDOWS
setlocal
if not exist build mkdir build

set SRC=src\lib.c src\main.c src\crypto.c src\keys.c src\exfat.c src\ntfs.c src\stream.c src\aes.c

:: Find Clang
where clang >nul 2>&1 || (
    for %%P in (
        "C:\Program Files\LLVM\bin"
        "C:\LLVM\bin"
        "%LOCALAPPDATA%\LLVM\bin"
        "C:\msys64\clang64\bin"
        "C:\msys64\mingw64\bin"
    ) do if exist "%%~P\clang.exe" set "PATH=%%~P;%PATH%"& goto :clang_found
    echo error: clang not found - install LLVM or add to PATH
    exit /b 1
)
:clang_found

:: Find libraries
set LIBPATH=
for %%L in (
    "C:\msys64\mingw64\lib"
    "C:\msys64\clang64\lib"
    "C:\msys64\ucrt64\lib"
) do if exist "%%~L\libntdll.a" set "LIBPATH=-L%%~L"& goto :lib_found
:lib_found

set CFLAGS=-target x86_64-pc-windows-gnu -Oz -maes -msse4.1 -I include -fno-asynchronous-unwind-tables -fno-ident -ffunction-sections -fdata-sections -flto -ffreestanding -fno-builtin -fno-stack-protector -nostdlib -fno-unwind-tables -fno-exceptions -fmerge-all-constants -fno-addrsig
set LDFLAGS=-fuse-ld=lld -Wl,--gc-sections -Wl,--icf=all -Wl,-e,_start -Wl,--subsystem,console -Wl,-s -Wl,--lto-Oz %LIBPATH%

for /f %%a in ('wmic os get localdatetime /value ^| find "="') do for /f "tokens=2 delims==" %%b in ("%%a") do set "DT=%%b"
set "DATESTR=%DT:~0,8%"
set REV=-1
set "LASTTAG="
for /f %%r in ('git tag -l "%DATESTR%*" 2^>nul ^| sort') do set "LASTTAG=%%r"
if defined LASTTAG call :parsetag
if exist build\.buildrev (
    for /f "tokens=1,2" %%x in (build\.buildrev) do (
        if "%%x"=="%DATESTR%" if %%y GTR %REV% set REV=%%y
    )
)
set /a REV+=1
set "REVSTR=0%REV%"
set "DATECODE=%DATESTR%%REVSTR:~-2%"
(echo %DATESTR% %REV%)>build\.buildrev
goto :buildstart

:parsetag
set /a "REV=1%LASTTAG:~8% - 100"
goto :eof

:buildstart
echo building...
clang %CFLAGS% %LDFLAGS% -DVERSION="\"%DATECODE%\"" -o build\unsegareborn-win-x64.exe %SRC% -lntdll

if exist build\unsegareborn-win-x64.exe (
    for %%F in (build\unsegareborn-win-x64.exe) do echo done: %%~nxF ^(%%~zF bytes^)
) else (
    echo build failed
    exit /b 1
)
exit /b 0