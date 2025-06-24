#!/bin/bash
# Build script for unsegaREBORN on Linux/macOS

BUILD_TYPE=Release
STATIC_BUILD=OFF

while [[ $# -gt 0 ]]; do
    case $1 in
        --static)
            STATIC_BUILD=ON
            echo "Building static executable..."
            shift
            ;;
        --debug)
            BUILD_TYPE=Debug
            echo "Building debug version..."
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--static] [--debug]"
            exit 1
            ;;
    esac
done

mkdir -p build
cd build

echo "Configuring with CMake..."
cmake -DBUILD_STATIC=$STATIC_BUILD -DCMAKE_BUILD_TYPE=$BUILD_TYPE ..

echo "Building..."
cmake --build . --config $BUILD_TYPE

cd ..

echo ""
echo "Build complete!"
echo "Executable: build/unsegareborn"
if [ "$STATIC_BUILD" = "ON" ]; then
    echo "Built as static executable - no external dependencies required"
fi