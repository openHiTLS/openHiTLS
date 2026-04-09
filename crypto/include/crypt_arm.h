/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef CRYPT_ARM_H
#define CRYPT_ARM_H

#ifndef CRYPT_VAL
#define CRYPT_VAL               16
#endif
#ifndef CRYPT_VAL2
#define CRYPT_VAL2              26
#endif
#if defined(__arm__) || defined (__arm)
#define CRYPT_CAP               CRYPT_VAL
#define CRYPT_CE                CRYPT_VAL2
#define CRYPT_ARM_NEON          (1 << 12)
#define CRYPT_ARM_AES           (1 << 0)
#define CRYPT_ARM_PMULL         (1 << 1)
#define CRYPT_ARM_SHA1          (1 << 2)
#define CRYPT_ARM_SHA256        (1 << 3)
#elif defined(__aarch64__)
#define CRYPT_CAP               CRYPT_VAL
#define CRYPT_CE                CRYPT_VAL
#define CRYPT_ARM_NEON          (1 << 1)
#define CRYPT_ARM_AES           (1 << 3)
#define CRYPT_ARM_PMULL         (1 << 4)
#define CRYPT_ARM_SHA1          (1 << 5)
#define CRYPT_ARM_SHA256        (1 << 6)
#define CRYPT_ARM_SM3           (1 << 18)
#define CRYPT_ARM_SM4           (1 << 19)
#define CRYPT_ARM_SHA512        (1 << 21)

#define CRYPT_CAP2              CRYPT_VAL2
#define CRYPT_ARM_CAP2_RNG      (1 << 16)
#endif

#ifndef __ASSEMBLER__
extern uint32_t g_cryptArmCpuInfo;
#else
#  ifdef HITLS_AARCH64_PACIASP
#   define AARCH64_PACIASP hint #25
#   define AARCH64_AUTIASP hint #29
#  else
#   define AARCH64_PACIASP
#   define AARCH64_AUTIASP
#  endif
#endif

/*
 * ARMv8/AArch64 assembly compatibility layer for Linux (ELF/GNU as) and macOS (Mach-O/clang).
 * Use __APPLE__ and __aarch64__ to keep one source tree building on both platforms.
 */

/* Assembly symbol name (with optional leading underscore on macOS) */
#define CRYPT_AARCH64_SYM_CONCAT_HELP(a, b) a ## b
#define CRYPT_AARCH64_SYM_CONCAT(a, b) CRYPT_AARCH64_SYM_CONCAT_HELP(a, b)
#define CRYPT_AARCH64_SYM(name) CRYPT_AARCH64_SYM_CONCAT(CRYPT_AARCH64_PREFIX, name)

#if defined(__aarch64__)
#  if defined(__APPLE__) 
/* macOS arm64 (Mach-O): no .type/.size, symbol has leading underscore */
#    define CRYPT_AARCH64_PREFIX _
#    define CRYPT_AARCH64_TYPE_FUNCTION(sym)
#    define CRYPT_AARCH64_SIZE_FUNCTION(sym)
#    define CRYPT_AARCH64_TYPE_OBJECT(sym)
#    define CRYPT_AARCH64_SIZE_OBJECT(sym)
#    define CRYPT_AARCH64_RODATA_SECTION .section __TEXT,__const
#    define CRYPT_AARCH64_ARCH_CRYPTO
#    define CRYPT_AARCH64_ARCH_BASE
/* Mach-O: adrp/add need @PAGE and @PAGEOFF for section-relative data */
#    define CRYPT_AARCH64_GET_RELA(reg, sym) \
        adrp reg, sym@PAGE %% \
        add reg, reg, sym@PAGEOFF
/* Mach-O: .hidden -> .private_extern; .extern not needed */
#    define CRYPT_AARCH64_EXTERN(sym) .private_extern CRYPT_AARCH64_SYM(sym)

/* Mach-O: Load address of external global variables via GOT (Global Offset Table).
   Unlike GET_RELA which uses section-relative addressing for local symbols,
   GET_GOTSYM dereferences the GOT entry to obtain the runtime address of
   an external symbol, which is required on Mach-O for position-independent code. */
#    define CRYPT_AARCH64_GET_GOTSYM(reg, sym) \
        adrp reg, CRYPT_AARCH64_SYM(sym)@GOTPAGE %% \
        ldr reg, [reg, CRYPT_AARCH64_SYM(sym)@GOTPAGEOFF]

#    define CRYPT_AARCH64_FUNC_START(name) \
        .globl CRYPT_AARCH64_SYM(name) %% \
        .p2align 4 %% \
        CRYPT_AARCH64_SYM(name):
#    define CRYPT_AARCH64_FUNC_END(name)

#    define CRYPT_AARCH64_LOCAL_FUNC_START(name) \
        .p2align 4 %% \
        CRYPT_AARCH64_SYM(name):
#    define CRYPT_AARCH64_LOCAL_FUNC_END(name)
#  else
/* Linux aarch64 (ELF/GNU as) */
#    define CRYPT_AARCH64_PREFIX
#    define CRYPT_AARCH64_TYPE_FUNCTION(sym) .type sym, %function
#    define CRYPT_AARCH64_SIZE_FUNCTION(sym) .size sym, .-sym
#    define CRYPT_AARCH64_TYPE_OBJECT(sym) .type sym, %object
#    define CRYPT_AARCH64_SIZE_OBJECT(sym) .size sym, .-sym
#    define CRYPT_AARCH64_RODATA_SECTION .section .rodata
#    define CRYPT_AARCH64_ARCH_CRYPTO .arch armv8-a+crypto
#    define CRYPT_AARCH64_ARCH_BASE .arch armv8-a
/* ELF: standard adrp + :lo12: */
#    define CRYPT_AARCH64_GET_RELA(reg, sym) \
        adrp reg, sym ; \
        add reg, reg, :lo12:sym
#    define CRYPT_AARCH64_EXTERN(sym) \
       .extern sym ; \
       .hidden sym ;
/* CRYPT_AARCH64_GET_RELA is avaliable for linux ELF, using it here to keep consistent with original code. */
#    define CRYPT_AARCH64_GET_GOTSYM(reg, sym) CRYPT_AARCH64_GET_RELA(reg, sym)

#    define CRYPT_AARCH64_FUNC_START(name) \
        .globl CRYPT_AARCH64_SYM(name) ; \
        .p2align 4 ; \
        CRYPT_AARCH64_TYPE_FUNCTION(CRYPT_AARCH64_SYM(name)) ; \
        CRYPT_AARCH64_SYM(name):
#    define CRYPT_AARCH64_FUNC_END(name) CRYPT_AARCH64_SIZE_FUNCTION(CRYPT_AARCH64_SYM(name))

#    define CRYPT_AARCH64_LOCAL_FUNC_START(name) \
        CRYPT_AARCH64_TYPE_FUNCTION(name) ; \
        .p2align 4 ; \
        name:
#    define CRYPT_AARCH64_LOCAL_FUNC_END(name) CRYPT_AARCH64_SIZE_FUNCTION(name)
#  endif /* __APPLE__ */
#endif /* __aarch64__ */

#endif