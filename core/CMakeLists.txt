cmake_minimum_required(VERSION 3.20)
project(aigatekeeper-core VERSION 2.0.0 LANGUAGES CXX)

# ============================================================================
# Custom CMake modules (Findre2.cmake for cross-distro re2 support)
# ============================================================================
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ============================================================================
# Configuración del compilador
# ============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ============================================================================
# Dependencias del sistema
# ============================================================================
find_package(Python COMPONENTS Interpreter Development REQUIRED)
find_package(pybind11 CONFIG REQUIRED)
find_package(re2 REQUIRED)

# ============================================================================
# Core library — estática para tests, linkeada en el módulo Python
# ============================================================================
add_library(agcore STATIC
    src/sanitizer.cpp
    src/scanner.cpp
    src/injection.cpp
)

target_include_directories(agcore PUBLIC include)
target_link_libraries(agcore PUBLIC re2::re2)

# ============================================================================
# Python binding module (pybind11)
# ============================================================================
pybind11_add_module(pyagcore
    bindings/pyag.cpp
)
target_link_libraries(pyagcore PRIVATE agcore)
target_include_directories(pyagcore PRIVATE include)

# ============================================================================
# Tests unitarios C++
# ============================================================================
add_executable(test_core
    tests/test_core.cpp
)
target_link_libraries(test_core PRIVATE agcore)
target_include_directories(test_core PRIVATE include)

# ============================================================================
# Instalación — scikit-build-core coloca pyagcore.so en wheel root
# ============================================================================
install(TARGETS pyagcore LIBRARY DESTINATION .)

# ============================================================================
# Tests con CTest
# ============================================================================
enable_testing()
add_test(NAME test_core COMMAND test_core)
