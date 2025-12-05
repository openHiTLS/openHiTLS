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

#ifndef UIO_ABSTRACTION_H
#define UIO_ABSTRACTION_H

#include "hitls_build.h"
#ifdef HITLS_BSL_UIO_PLT

#include <stdint.h>
#include <stdbool.h>
#include "uio_base.h"
#include "sal_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IP_ADDR_V4_LEN 4
#define IP_ADDR_V6_LEN 16
#define IP_ADDR_MAX_LEN IP_ADDR_V6_LEN

struct UIO_ControlBlock {
    struct BSL_UIO_MethodStruct method;

    uint32_t flags;             // Read/write retry flag. For details, see BSL_UIO_FLAGS_* in bsl_uio.h
    bool init;              // Initialization flag. 1 means it's initialized, and 0 means it's not initialized.

    int64_t writeNum;          // count of write
    int64_t readNum;           // count of read

    void *ctx;                  // Context
    uint32_t ctxLen;            // Context length

    void *userData;             // User data
    BSL_UIO_USERDATA_FREE_FUNC userDataFreeFunc;  // Release User Data

    struct UIO_ControlBlock *prev; // Previous UIO object of the current UIO object in the UIO chain
    struct UIO_ControlBlock *next; // Next UIO object of the current UIO object in the UIO chain

    bool isUnderlyingClosedByUio; // Indicates whether related resources are released together with the UIO.
    BSL_SAL_RefCount references;    // reference count
};

typedef struct {
    uint8_t *data;
    uint64_t size;
} BSL_UIO_CtrlGetInfoParam;

/**
 * @brief Check whether a given error code is a fatal error.
 *
 * @param err [IN] Error code.
 *
 * @return true: A fatal error occurs.
 *         false: No fatal error occurs.
 */
bool UioIsNonFatalErr(int32_t err);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_UIO_PLT */

#endif // UIO_ABSTRACTION_H

