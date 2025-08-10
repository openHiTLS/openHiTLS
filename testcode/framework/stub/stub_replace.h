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

#ifndef STUB_REPALCE_H
#define STUB_REPALCE_H

#include <stdint.h>


#if defined(__x86_64__)
/*
 * The first 14 bytes of the function entry are used to construct the jump instruction.
 * Short jump instruction is 5 bytes, and Long jump instruction is 14 bytes.
 */
#define CODESIZE 14U
#elif defined(__aarch64__) || defined(_M_ARM64) || defined(__riscv) || defined(__riscv64)
/* ARM64 needs 16 bytes to construct the jump instruction. */
#define CODESIZE 16U
#elif defined(__arm__)
/* ARM32 needs 12 bytes to construct the jump instruction. */
#define CODESIZE 12U
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *fn;
    unsigned char codeBuf[CODESIZE];
} FuncStubInfo;

/*
 * Initialize the dynamic stub change function. Invoke the function once.
 * return - 0:Success, non-zero:Error code
 */
int STUB_Init(void);

/*
 * Replaces the specified function with the specified stub function.
 * stubInfo - Record information about stub replacement, which is used for STUB_Reset restoration.
 * srcFn - Functions in the source code
 * stubFn - Need to replace the stub function that is inserted into the run.
 * return - 0:Success, non-zero:Error code
 */
int STUB_Replace(FuncStubInfo *stubInfo, void *srcFn, const void *stubFn);

/*
 * Restore the source function and remove the instrumentation.
 * stubInfo - Information logged when instrumentation
 * return - 0:Success, non-zero:Error code
 */
int STUB_Reset(FuncStubInfo *stubInfo);

#ifdef __cplusplus
}
#endif

#endif // STUB_REPALCE_H
