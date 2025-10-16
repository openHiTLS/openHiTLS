# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# CMake wrapper for building libboundscheck (Secure C) submodule.
#
# This file is maintained in the openHiTLS repository
# to avoid git conflicts with the upstream libboundscheck repository.

# ============================================================
# Build Configuration for libboundscheck (Secure C)
# ============================================================

message(STATUS "")
message(STATUS "=== Configuring libboundscheck (Secure C) ===")

# Define paths relative to openHiTLS root
# Use CMAKE_CURRENT_LIST_DIR to get the platform/ directory
get_filename_component(PLATFORM_DIR "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
set(SECUREC_SOURCE_DIR "${PLATFORM_DIR}/Secure_C")
set(SECUREC_INCLUDE_DIR "${SECUREC_SOURCE_DIR}/include")
set(SECUREC_SRC_DIR "${SECUREC_SOURCE_DIR}/src")
set(SECUREC_OUTPUT_DIR "${SECUREC_SOURCE_DIR}/lib")

# Check if securec submodule is initialized
if(NOT EXISTS "${SECUREC_INCLUDE_DIR}/securec.h")
    message(WARNING "Securec submodule not initialized!")
    message(WARNING "Please run: git submodule update --init platform/Secure_C")
    message(WARNING "Or run: python3 configure.py (automatic initialization)")
    return()
endif()

# ============================================================
# Collect Source Files
# ============================================================
message(STATUS "Searching for sources in: ${SECUREC_SRC_DIR}")
file(GLOB SECUREC_SOURCES "${SECUREC_SRC_DIR}/*.c")

list(LENGTH SECUREC_SOURCES SOURCE_COUNT)
message(STATUS "Found ${SOURCE_COUNT} securec source files")

if(NOT SECUREC_SOURCES)
    message(FATAL_ERROR "No source files found in ${SECUREC_SRC_DIR}")
endif()

# ============================================================
# Platform-Specific Configuration
# ============================================================

# Detect platform and compiler
message(STATUS "System: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")

# ============================================================
# Compiler Flags Function
# ============================================================
function(configure_securec_compiler_flags target_name)
    # Base flags for all configurations
    target_compile_options(${target_name} PRIVATE
        -Wall
        -DNDEBUG
    )

    # Optimization flags
    target_compile_options(${target_name} PRIVATE
        $<$<CONFIG:Release>:-O2>
        $<$<CONFIG:Debug>:-O0 -g>
    )

    # Security hardening flags for GCC and Clang
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
        target_compile_options(${target_name} PRIVATE
            -fstack-protector-all
            -D_FORTIFY_SOURCE=2
            -Wformat=2
            -Wformat-security
            -Wextra
        )

        # GCC-specific warnings (may not work with all Clang versions)
        if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
            target_compile_options(${target_name} PRIVATE
                -Wfloat-equal
                -Wshadow
                -Wconversion
                -Warray-bounds
                -Wpointer-arith
                -Wcast-qual
                -Wstrict-prototypes
                -Wmissing-prototypes
                -Wstrict-overflow=1
                -Wstrict-aliasing=2
                -Wswitch
                -Wswitch-default
            )

            # GCC-specific parameter
            if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL "4.4")
                target_compile_options(${target_name} PRIVATE
                    --param=ssp-buffer-size=4
                )
            endif()
        endif()

        # Clang-specific adjustments
        if(CMAKE_C_COMPILER_ID MATCHES "Clang|AppleClang")
            target_compile_options(${target_name} PRIVATE
                -Wfloat-equal
                -Wshadow
                -Wconversion
                -Wpointer-arith
                -Wcast-qual
                -Wstrict-prototypes
                -Wmissing-prototypes
            )
        endif()
    endif()

    # MSVC-specific flags
    if(MSVC)
        target_compile_options(${target_name} PRIVATE
            /W4          # Warning level 4
            /GS          # Buffer security check
            /sdl         # Enable additional security checks
            /DNDEBUG
        )
    endif()
endfunction()

# ============================================================
# Linker Flags Function
# ============================================================
function(configure_securec_linker_flags target_name)
    # Linux: RELRO, BIND_NOW, NX protection
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(${target_name} PRIVATE
            -Wl,-z,relro
            -Wl,-z,now
            -Wl,-z,noexecstack
        )

        # Strip symbols in release builds
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            target_link_options(${target_name} PRIVATE
                -Wl,-s
            )
        endif()
    endif()

    # macOS: equivalent security features
    if(APPLE)
        # Note: macOS ld64 doesn't support -z flags
        # Use -Wl,-dead_strip for optimization
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            target_link_options(${target_name} PRIVATE
                -Wl,-dead_strip
            )
        endif()
    endif()

    # Windows/MSVC: DEP, ASLR
    if(MSVC)
        target_link_options(${target_name} PRIVATE
            /DYNAMICBASE    # ASLR
            /NXCOMPAT       # DEP
        )
    endif()

    # Stack protector for GCC/Clang
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
        target_link_options(${target_name} PRIVATE
            -fstack-protector-all
        )
    endif()
endfunction()

# ============================================================
# Build Static Library Target
# ============================================================
# Note: Using static library for better integration with openHiTLS
# Static linking avoids runtime dependency issues and simplifies deployment

# Create static library target
add_library(securec_boundscheck STATIC ${SECUREC_SOURCES})

# Set target properties
set_target_properties(securec_boundscheck PROPERTIES
    OUTPUT_NAME "boundscheck"
    POSITION_INDEPENDENT_CODE ON  # Still needed for static lib used in shared libs

    # Output to submodule's lib directory (consistent with Makefile)
    ARCHIVE_OUTPUT_DIRECTORY "${SECUREC_OUTPUT_DIR}"
)

# Multi-config generators (Visual Studio, Xcode)
foreach(CONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG} CONFIG_UPPER)
    set_target_properties(securec_boundscheck PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_UPPER} "${SECUREC_OUTPUT_DIR}"
    )
endforeach()

# Include directories
target_include_directories(securec_boundscheck
    PUBLIC
        $<BUILD_INTERFACE:${SECUREC_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${SECUREC_SRC_DIR}
)

# Apply compiler flags
# Note: Linker flags are not applied to static libraries
# They will be inherited by the final executable/shared library that links securec
configure_securec_compiler_flags(securec_boundscheck)

# ============================================================
# Create output directory if it doesn't exist
# ============================================================
file(MAKE_DIRECTORY "${SECUREC_OUTPUT_DIR}")

# ============================================================
# Export for parent project
# ============================================================

# Make target available to parent CMakeLists.txt
# Other targets can link with: target_link_libraries(foo securec_boundscheck)

# Create an alias for compatibility
add_library(boundscheck ALIAS securec_boundscheck)

# Note: PARENT_SCOPE not used because this file is included via include()
# rather than add_subdirectory(). The securec_boundscheck target is directly
# available in the parent CMakeLists.txt scope.

# ============================================================
# Installation Rules (optional)
# ============================================================

# Install static library to openHiTLS output directory
install(TARGETS securec_boundscheck
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)

# Install headers
install(FILES
    ${SECUREC_INCLUDE_DIR}/securec.h
    ${SECUREC_INCLUDE_DIR}/securectype.h
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include
)

# ============================================================
# Summary
# ============================================================
message(STATUS "Securec library configured:")
message(STATUS "  Source dir:   ${SECUREC_SRC_DIR}")
message(STATUS "  Include dir:  ${SECUREC_INCLUDE_DIR}")
message(STATUS "  Output dir:   ${SECUREC_OUTPUT_DIR}")
message(STATUS "  Library type: STATIC")
message(STATUS "  Library name: libboundscheck.a (Linux/macOS) / boundscheck.lib (Windows)")
message(STATUS "========================================")
message(STATUS "")
