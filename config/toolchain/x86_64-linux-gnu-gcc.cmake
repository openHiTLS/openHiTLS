# x86_64 (64-bit) Linux with GNU GCC toolchain

set(CMAKE_SYSTEM_NAME Linux)

# Compiler configuration
find_program(CMAKE_C_COMPILER gcc)
find_program(CMAKE_CXX_COMPILER g++)
find_program(CMAKE_ASM_COMPILER gcc)

# Compiler identification
set(CMAKE_C_COMPILER_ID "GNU")
set(CMAKE_CXX_COMPILER_ID "GNU")

# Metadata
set(TOOLCHAIN_DETECTED_COMPILER "gcc")
set(TOOLCHAIN_DETECTED_LINKER "gnu-ld")
set(TOOLCHAIN_DETECTED_PLATFORM "linux")
