/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef UIO_ABSTRACTION_H
#define UIO_ABSTRACTION_H

#include "hitls_build.h"
#ifdef HITLS_BSL_UIO_PLT

#include "bsl_uio.h"
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

