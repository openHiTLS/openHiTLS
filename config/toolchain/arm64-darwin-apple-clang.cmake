# ARMv8 64-bit macOS with Apple Clang from Xcode Command Line Tools (Apple Silicon native)

set(CMAKE_SYSTEM_NAME Darwin)

# Compiler configuration
set(CMAKE_C_COMPILER "/usr/bin/cc")
set(CMAKE_CXX_COMPILER "/usr/bin/c++")
set(CMAKE_ASM_COMPILER "/usr/bin/cc")

# Compiler identification
set(CMAKE_C_COMPILER_ID "AppleClang")
set(CMAKE_CXX_COMPILER_ID "AppleClang")

# Metadata
set(TOOLCHAIN_DETECTED_COMPILER "apple-clang")
set(TOOLCHAIN_DETECTED_LINKER "ld64")
set(TOOLCHAIN_DETECTED_PLATFORM "darwin")
