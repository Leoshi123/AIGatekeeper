# Findre2.cmake — Find re2 (Google RE2) library
#
# Tries CONFIG mode first (Arch/CachyOS provides re2Config.cmake),
# falls back to pkg-config, then manual search (Ubuntu's libre2-dev).
#
# Sets the re2::re2 imported target.
#
# Usage: find_package(re2 REQUIRED)

# --- Try CMake config mode first ---
if(NOT re2_FOUND)
    find_package(re2 CONFIG QUIET)
endif()

# --- Fallback: pkg-config ---
if(NOT re2_FOUND)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(PC_re2 QUIET re2)
        if(PC_re2_FOUND)
            add_library(re2::re2 INTERFACE IMPORTED)
            set_target_properties(re2::re2 PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${PC_re2_INCLUDE_DIRS}"
                INTERFACE_LINK_LIBRARIES "${PC_re2_LINK_LIBRARIES}"
                INTERFACE_COMPILE_OPTIONS "${PC_re2_CFLAGS_OTHER}"
            )
            message(STATUS "Found re2 (pkg-config): ${PC_re2_LINK_LIBRARIES}")
            set(re2_FOUND TRUE)
        endif()
    endif()
endif()

# --- Final fallback: manual search ---
if(NOT re2_FOUND)
    find_library(RE2_LIBRARY
        NAMES re2
        PATHS /usr/lib /usr/lib64 /usr/local/lib /usr/lib/x86_64-linux-gnu
        NO_DEFAULT_PATH
    )
    find_path(RE2_INCLUDE_DIR
        NAMES re2/re2.h
        PATHS /usr/include /usr/local/include
        NO_DEFAULT_PATH
    )

    if(RE2_LIBRARY AND RE2_INCLUDE_DIR)
        add_library(re2::re2 UNKNOWN IMPORTED)
        set_target_properties(re2::re2 PROPERTIES
            IMPORTED_LOCATION "${RE2_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${RE2_INCLUDE_DIR}"
        )
        message(STATUS "Found re2 (manual): ${RE2_LIBRARY}")
        mark_as_advanced(RE2_LIBRARY RE2_INCLUDE_DIR)
        set(re2_FOUND TRUE)
    endif()
endif()

# --- Final check ---
if(NOT re2_FOUND)
    if(re2_FIND_REQUIRED)
        message(FATAL_ERROR "Could NOT find re2 library. "
            "Install: apt install libre2-dev (Debian/Ubuntu) / "
            "yum install re2-devel (Fedora) / "
            "pacman -S re2 (Arch/CachyOS)")
    endif()
endif()
