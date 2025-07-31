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
#ifndef UI_TYPE_H
#define UI_TYPE_H

#include "hitls_build.h"
#ifdef HITLS_BSL_UI

#include <stdint.h>
#include "bsl_sal.h"
#include "bsl_ui.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

struct UI_ControlMethod {
    int32_t (*uiOpen) (BSL_UI *ui);   // Open the input and output streams
    int32_t (*uiWrite) (BSL_UI *ui, BSL_UI_DataPack *data); // Write callback
    int32_t (*uiRead) (BSL_UI *ui, BSL_UI_DataPack *data); // Read callback
    int32_t (*uiClose) (BSL_UI *ui);  // Close the input and output streams.
};


struct UI_Control {
    const BSL_UI_Method *method;
    BSL_SAL_ThreadLockHandle lock;
    void *in;
    void *out;
    void *exData;
};

struct UI_ControlDataPack {
    uint32_t type;
    uint32_t flags;
    char *data;
    uint32_t dataLen;
    char *verifyData;
};

#define BSL_UI_SUPPORT_ABILITY(cap, pos) (((cap) & (pos)) != 0)

#define BSL_UI_READ_BUFF_MAX_LEN 1025 // 1024 + '\0'

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* HITLS_BSL_UI */

#endif /* UI_TYPE_H */
