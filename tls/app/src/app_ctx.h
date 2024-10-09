/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef APP_CTX_H
#define APP_CTX_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls_cert_type
 * @brief   Describe the APP cache linked list.
 */
typedef struct BslList AppList;

typedef struct {
    uint8_t *buf;       /* buffer */
    uint32_t bufSize;   /* size of the buffer */
    uint32_t start;     /* start position */
    uint32_t end;       /* end position */
} AppBuf;

/**
 * AppDataCtx struct, used to transfer app data information
 */
struct AppDataCtx {
    AppBuf appReadBuf;      /* buffer received by the app */
    AppList *appList;       /* cache unexpected app messages */
};

#ifdef __cplusplus
}
#endif
#endif