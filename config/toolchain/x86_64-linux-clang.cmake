# x86_64 (64-bit) Linux with LLVM Clang toolchain

set(CMAKE_SYSTEM_NAME Linux)

# Compiler configuration
find_program(CMAKE_C_COMPILER clang)
find_program(CMAKE_CXX_COMPILER clang++)
find_program(CMAKE_ASM_COMPILER clang)

# Compiler identification
set(CMAKE_C_COMPILER_ID "Clang")
set(CMAKE_CXX_COMPILER_ID "Clang")

# Metadata
set(TOOLCHAIN_DETECTED_COMPILER "clang")
set(TOOLCHAIN_DETECTED_LINKER "lld")
set(TOOLCHAIN_DETECTED_PLATFORM "linux")
