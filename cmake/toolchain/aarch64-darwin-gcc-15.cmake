# ARMv8 64-bit macOS with GCC 15 from Homebrew (Apple Silicon)

set(CMAKE_SYSTEM_NAME Darwin)

# Compiler configuration
set(CMAKE_C_COMPILER "/opt/homebrew/bin/gcc-15")
set(CMAKE_CXX_COMPILER "/opt/homebrew/bin/g++-15")
set(CMAKE_ASM_COMPILER "/opt/homebrew/bin/gcc-15")

# Compiler identification
set(CMAKE_C_COMPILER_ID "GNU")
set(CMAKE_CXX_COMPILER_ID "GNU")

# Metadata
set(TOOLCHAIN_DETECTED_COMPILER "gcc")
set(TOOLCHAIN_DETECTED_LINKER "gnu-ld")
set(TOOLCHAIN_DETECTED_PLATFORM "darwin")
