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

#include <errno.h>
#include <limits.h>
#include <memory.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include "stub_replace.h"

#ifdef HITLS_BIG_ENDIAN
#include "crypt_utils.h"
#endif

/* The LSB of the function pointer indicates the thumb function. The LSB of the actual address needs to be cleared. */
#define REAL_ADDR(ptr) (void *)(((uintptr_t)(ptr)) & (~(uintptr_t)1))
/*
 * Used to record the size of the system memory page.
 */
static long g_pageSize = -1;

/*
 * Obtains the start address of the memory page where the specified function code is located.
 * fn - Function Address (Function Pointer)
 */
static inline void *FuncPageGet(uintptr_t fn)
{
    return (void *)(fn & (~(g_pageSize - 1)));
}

/*
 * This file does not use the memcpy function of the system. In this way, the mempcy function of
 * the system can be dynamically replaced by STUB_Replace.
 */
static int32_t StubCopy(void *dest, void *src, uint32_t size)
{
    if ((src == NULL) || (dest == NULL)) {
        return ERANGE;
    }

    uint8_t *localDst = (uint8_t *)(dest);
    uint8_t *localSrc = (uint8_t *)(src);
    for (uint32_t i = 0; i < size; i++) {
        localDst[i] = localSrc[i];
    }
    return 0;
}

/*
 * This file does not use the memset function of the system. In this way, the memset function of
 * the system can be dynamically replaced by STUB_Replace.
 */
static void StubSet(void *dest, int val, uint32_t size)
{
    if (dest == NULL) {
        return;
    }

    uint8_t *localDst = (uint8_t *)(dest);
    for (uint32_t i = 0; i < size; i++) {
        localDst[i] = val;
    }
}

#if defined(__arm__) || defined(__thumb__)

static int ReplaceT32(void *srcFn, const void *stubFn)
{
    uint16_t instr1 = 0xF000;
    uint16_t instr2;
    uint32_t imm;
    /*
     * The difference between the jump instruction and srcFn is 4 bytes. The current address is obtained by
     * subtracting 4 bytes from the PC.
     */
    uint32_t addrDiff = REAL_ADDR(stubFn) - (REAL_ADDR(srcFn) + 4) - 4;

    /*
     * 32-bit test occurrence address: srcFn - stubFn, the scope is out of range,
     * temporarily comment on the following scope judgment.
     * if (abs((int32_t)addrDiff) >= 0x100000) { // Max jump range
     *   return -1;
     * }
    */
    if (((uintptr_t)stubFn) & 0x01) {
        // Thumb instruction set BL corresponding machine code is [1 1 1 1 0 S imm10][1 1 J1 1 J2 imm11]
        // Address offset calculation: I1: NOT(J1 EOR S); I2: NOT(J2 EOR S);
        // imm32: SignExtend(S:I1:I2:imm10:imm11:'0', 32)
        instr2 = 0xF800;                // Corresponding bit of machine code J1  J2 take 1
        if (stubFn < srcFn) {
            instr1 = 0xF400;            // The corresponding bit S of the machine code is 1.
        }
        imm = addrDiff >> 1;            // The address is shifted right by one bit.
        imm &= (1 << 21) - 1;           // Lower 21 bits
        instr1 |= (imm >> 11) & 0x3FF;  // Move rightwards by 11 digits and take imm10.
        instr2 |= (imm & 0x7FF);
    } else {
        // Thumb instruction set BLX corresponding machine code is [1 1 1 1 0 S imm10H][1 1 J1 0 J2 imm10L H]
        // Address offset calculation: I1 = NOT(J1 EOR S); I2 = NOT(J2 EOR S)
        // imm32 = SignExtend(S:I1:I2:imm10H:imm10L:'00', 32)
        instr2 = 0xE800;                // J1 and J2 corresponding to the machine code are set to 1.
        if (stubFn < srcFn) {
            instr1 = 0xF400;            // The corresponding bit S of the machine code is 1.
        }
        imm = addrDiff >> 2;            // Shift right by 2 bits
        imm &= (1 << 20) - 1;           // Take lower 20 bits
        instr1 |= (imm >> 10) & 0x3FF;  // Take 10 bits
        instr2 |= (imm & 0x3FF) << 1;   // Take lower 10 bits
    }
    uint8_t *text = (uint8_t*)REAL_ADDR(srcFn);
    ((uint16_t *)text)[0] = 0xb580;
    ((uint16_t *)text)[1] = 0xaf00;
    ((uint16_t *)text)[2] = instr1;     // BL/BLX offset 2
    ((uint16_t *)text)[3] = instr2;     // Offset 3
    ((uint16_t *)text)[4] = 0xaf00;     // Offset 4
    ((uint16_t *)text)[5] = 0xbd80;     // Offset 5
    return 0;
}

static int ReplaceA32(void *srcFn, const void *stubFn)
{
    uint32_t inst;
    uint32_t addrDiff = REAL_ADDR(stubFn) - (srcFn + 4) - 8;
    uint32_t imm24;
    if (abs((int32_t)addrDiff) >= 0x1000000) {  // Max jump range
        return -1;
    }
    if (((uintptr_t)stubFn) & 0x01) {
        // a32 instruction set BLX corresponding machine code is [1 1 1 1 1 0 1 H imm24]
        // imm32 = SignExtend(imm24:H:'0', 32)
        uint32_t h = (addrDiff & 0b10) >> 1;    // bit[1] of the address difference
        imm24 = (addrDiff >> 2);                // Shift right by 2 bits
        imm24 &= (1 << 24) - 1;                 // Take lower 24 bits
        inst = 0xfa000000 | imm24 | (h << 24);  // h is located in bit[24].
    } else {
        // a32 instruction set BL corresponding machine code is [(!= 1111) 1 0 1 1 imm24]
        // imm32 = SignExtend(imm24:'00', 32)
        imm24 = (addrDiff >> 2);                // Shift right by 2 bits
        imm24 &= (1 << 24) - 1;                 // Take lower 24 bits
        inst = 0xeb000000 | imm24;
    }
    ((uint32_t *)srcFn)[0] = 0xe92d4000;
    ((uint32_t *)srcFn)[1] = inst;              // BL/BLX
    ((uint32_t *)srcFn)[2] = 0xe8bd8000;        // Offset 2
    return 0;
}
#endif
/*
 * Replaces the specified function with the specified stub function.
 * stubInfo - Record information about stub replacement, which is used for STUB_Reset restoration.
 * srcFn - Functions in the source code
 * stubFn - You need to replace the stub function that is inserted into the run.
 * return - 0:Success, non-zero:Error code
 */
int STUB_Replace(FuncStubInfo *stubInfo, void *srcFn, const void *stubFn)
{
    (void)stubFn;
#if defined(__arm__) || defined(__thumb__)
    stubInfo->fn = REAL_ADDR(srcFn);
#else
    stubInfo->fn = srcFn;
#endif
    StubCopy(stubInfo->codeBuf, (char *)(stubInfo->fn), CODESIZE);
    bool nextPage = false;
    uintptr_t srcPoint = (uintptr_t)srcFn;
    if ((g_pageSize - (srcPoint % g_pageSize)) < CODESIZE) {
        nextPage = true;
    }

    /* To modify instruction content corresponding to the source function, add memory write permission first */
    if (mprotect(FuncPageGet(srcPoint), g_pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        perror("STUB_Replace: set error mprotect to w+r+x faild");
        return -1;
    }
    if (nextPage) {
        if (mprotect(FuncPageGet(srcPoint + CODESIZE), g_pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
            perror("STUB_Replace: set error mprotect to w+r+x faild");
            return -1;
        }
    }
#if defined(__x86_64__)
    /*
     * Short jump mode: Change to jmp jump instruction, and set jump position (the offset of the current position).
     * However, the offset cannot exceed 32 bits. There is a restriction on 64-bit systems.
     * [*(unsigned char *)srcFn = (unsigned char)0xE9;] [*(unsigned int *)((unsigned char *)srcFn + 1) =
     * (unsigned char *)stubFn - (unsigned char *)srcFn - CODESIZE;] Long jump mode:
     * Directly use a 64-bit address to jump, the following method is used.
     */
    unsigned char *tmpBuf = (unsigned char *)srcFn;
    int idx = 0;
    tmpBuf[idx++] = 0xFF; // 0xFF 0x25 Constructing a long jump instruction
    tmpBuf[idx++] = 0x25; // 0xFF 0x25 Constructing a long jump instruction
    tmpBuf[idx++] = 0x0;
    tmpBuf[idx++] = 0x0;
    tmpBuf[idx++] = 0x0;
    tmpBuf[idx++] = 0x0;

    tmpBuf[idx++] = (((uintptr_t)stubFn) & 0xff);
    tmpBuf[idx++] = ((((uintptr_t)stubFn) >> 8) & 0xff);  // Obtain the address by little-endian shift by 8 bits
    tmpBuf[idx++] = ((((uintptr_t)stubFn) >> 16) & 0xff); // Obtain the address by little-endian shift by 16 bits
    tmpBuf[idx++] = ((((uintptr_t)stubFn) >> 24) & 0xff); // Obtain the address by little-endian shift by 24 bits
    tmpBuf[idx++] = ((((uintptr_t)stubFn) >> 32) & 0xff); // Obtain the address by little-endian shift by 32 bits
    tmpBuf[idx++] = ((((uintptr_t)stubFn) >> 40) & 0xff); // Obtain the address by little-endian shift by 40 bits
    tmpBuf[idx++] = ((((uintptr_t)stubFn) >> 48) & 0xff); // Obtain the address by little-endian shift by 48 bits
    tmpBuf[idx++] = ((((uintptr_t)stubFn) >> 56) & 0xff); // Obtain the address by little-endian shift by 56 bits
#elif defined(__aarch64__) || defined(_M_ARM64)
    /* ldr x9, PC+8
       br x9
       addr  */
    uint32_t ldrIns = 0x58000040 | 9;        // 9 = 1001
    uint32_t brIns = 0xd61f0120 | (9 << 5); // 9 << 5
#ifdef HITLS_BIG_ENDIAN
    ldrIns = CRYPT_SWAP32(ldrIns);
    brIns = CRYPT_SWAP32(brIns);
#endif
    ((uint32_t *)srcFn)[0] = ldrIns;
    ((uint32_t *)srcFn)[1] = brIns;
    /* ldr x9, + 8 */
    *(long long *)((char *)srcFn + 8) = (long long)stubFn;
#elif defined(__arm__) || defined(__thumb__)
    if (((uintptr_t)srcFn) & 0x01) {
        if (ReplaceT32(srcFn, stubFn) != 0) {
            return -1;
        }
    } else {
        if (ReplaceA32(srcFn, stubFn) != 0) {
            return -1;
        }
    }
#elif defined(__i386__)
    unsigned long tmpAdd = (unsigned long)stubFn - (unsigned long)(srcFn + 5);
    unsigned char *tmpBuf = (unsigned char *)srcFn;
    *(tmpBuf + 0) = 0xe9;
    *(unsigned long *)(tmpBuf + 1) = tmpAdd;
#endif
    /* Flush cached instructions into */
    __builtin___clear_cache((char *)(stubInfo->fn), (char *)(stubInfo->fn) + CODESIZE);
    /* The modification is complete. Remove the memory write permission. */
    if (mprotect(FuncPageGet(srcPoint), g_pageSize, PROT_READ | PROT_EXEC) < 0) {
        perror("STUB_Replace: set error mprotect to r+x failed");
        return -1;
    }
    if (nextPage) {
        if (mprotect(FuncPageGet(srcPoint + CODESIZE), g_pageSize, PROT_READ | PROT_EXEC) < 0) {
            perror("STUB_Replace: set error mprotect to r+x failed");
            return -1;
        }
    }
    return 0;
}

/*
 * Restore the source function and remove the instrumentation.
 * stubInfo - Information logged when instrumentation
 * return - 0:Success, non-zero:Error code
 */
int STUB_Reset(FuncStubInfo *stubInfo)
{
    bool nextPage = false;

    if (stubInfo->fn == NULL) {
        return -1;
    }

    uintptr_t srcPoint = (uintptr_t)stubInfo->fn;
    if ((g_pageSize - (srcPoint % g_pageSize)) < CODESIZE) {
        nextPage = true;
    }

    /* To modify instruction content corresponding to the source function, add memory write permission first */
    if (mprotect(FuncPageGet((uintptr_t)stubInfo->fn), g_pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        perror("STUB_Reset: error mprotect to w+r+x faild");
        return -1;
    }
    if (nextPage) {
        if (mprotect(FuncPageGet(srcPoint + CODESIZE), g_pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
            perror("STUB_Replace: set error mprotect to w+r+x faild");
            return -1;
        }
    }

    /* Restore the recorded rewritten original function mov/push/mov a few instructions */
    if (StubCopy(stubInfo->fn, stubInfo->codeBuf, CODESIZE) < 0) {
        return -1;
    }
    /* Flush cached instructions into */
    __builtin___clear_cache((char *)stubInfo->fn, (char *)stubInfo->fn + CODESIZE);
    /* If recovered, disable the memory modification permission. */
    if (mprotect(FuncPageGet((uintptr_t)stubInfo->fn), g_pageSize, PROT_READ | PROT_EXEC) < 0) {
        perror("STUB_Reset: error mprotect to r+x failed");
        return -1;
    }
    if (nextPage) {
        if (mprotect(FuncPageGet(srcPoint + CODESIZE), g_pageSize, PROT_READ | PROT_EXEC) < 0) {
            perror("STUB_Replace: set error mprotect to r+x failed");
            return -1;
        }
    }

    StubSet(stubInfo, 0, sizeof(FuncStubInfo));
    return 0;
}

/*
 * Initialize the dynamic stub change function and obtain the memory page size. Invoke the function once.
 * return - 0:Success, non-zero:Error code
 */
int STUB_Init(void)
{
    if (g_pageSize != -1) {
        return 0;
    }
    g_pageSize = sysconf(_SC_PAGE_SIZE);
    if (g_pageSize < 0) {
        perror("STUB_Init: get system _SC_PAGE_SIZE configure failed");
        return -1;
    }
    return 0;
}
