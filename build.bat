@echo off
REM Build script for unsegaREBORN on Windows

set BUILD_TYPE=Release
set STATIC_BUILD=OFF

:parse_args
if "%1"=="" goto build
if "%1"=="--static" (
    set STATIC_BUILD=ON
    echo Building static executable...
)
if "%1"=="--debug" (
    set BUILD_TYPE=Debug
    echo Building debug version...
)
shift
goto parse_args

:build
if not exist build mkdir build
cd build

echo Configuring with CMake...
cmake -DBUILD_STATIC=%STATIC_BUILD% -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ..

echo Building...
cmake --build . --config %BUILD_TYPE%

echo.
echo Build complete!
echo Executable: build\%BUILD_TYPE%\unsegareborn.exe
if "%STATIC_BUILD%"=="ON" (
    echo Built as static executable - no external DLLs required
)
cd ..