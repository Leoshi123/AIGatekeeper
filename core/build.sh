#!/usr/bin/env bash
set -euo pipefail

# 🛡️ AIGatekeeper Core — Build Script
# Uso: ./build.sh [release|debug|test|clean|all]
#   release  → build optimizado (default)
#   debug    → build con símbolos y ASan
#   test     → build + run tests
#   clean    → limpiar build
#   all      → clean + release + test

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
MODE="${1:-release}"

case "${MODE}" in
    release)
        echo "🔧 Building RELEASE..."
        cmake -B "${BUILD_DIR}" -S "${SCRIPT_DIR}" -DCMAKE_BUILD_TYPE=Release
        cmake --build "${BUILD_DIR}" -j"$(nproc)"
        ;;
    debug)
        echo "🔧 Building DEBUG with ASan..."
        cmake -B "${BUILD_DIR}" -S "${SCRIPT_DIR}" \
            -DCMAKE_BUILD_TYPE=Debug \
            -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer"
        cmake --build "${BUILD_DIR}" -j"$(nproc)"
        ;;
    test)
        echo "🔧 Building + Testing..."
        cmake -B "${BUILD_DIR}" -S "${SCRIPT_DIR}" -DCMAKE_BUILD_TYPE=Release
        cmake --build "${BUILD_DIR}" -j"$(nproc)"
        echo ""
        echo "🧪 Running tests..."
        "${BUILD_DIR}/test_core"
        ;;
    clean)
        echo "🧹 Cleaning..."
        rm -rf "${BUILD_DIR}"
        echo "   Done."
        ;;
    all)
        echo "🧹 Clean build + test..."
        rm -rf "${BUILD_DIR}"
        cmake -B "${BUILD_DIR}" -S "${SCRIPT_DIR}" -DCMAKE_BUILD_TYPE=Release
        cmake --build "${BUILD_DIR}" -j"$(nproc)"
        echo ""
        "${BUILD_DIR}/test_core"
        ;;
    *)
        echo "❌ Unknown mode: ${MODE}"
        echo "Usage: ./build.sh [release|debug|test|clean|all]"
        exit 1
        ;;
esac

echo ""
echo "✅ Build complete (${MODE})"
