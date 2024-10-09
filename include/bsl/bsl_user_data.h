/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/**
 * @defgroup bsl_userdata
 * @ingroup bsl
 * @brief user data module
 */

#ifndef BSL_USER_DATA_H
#define BSL_USER_DATA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_userdata
 *
 * Modify the BSL_MAX_EX_TYPE if a new index is added.
 */
#define BSL_USER_DATA_EX_INDEX_SSL              0
#define BSL_USER_DATA_EX_INDEX_X509_STORE_CTX   1
#define BSL_USER_DATA_EX_INDEX_SSL_CTX          2
#define BSL_USER_DATA_EX_INDEX_X509_STORE       3
#define BSL_USER_DATA_EX_INDEX_UIO              4

#define BSL_MAX_EX_TYPE 5
#define BSL_MAX_EX_DATA 20

typedef struct {
    void *sk[BSL_MAX_EX_DATA];
} BSL_USER_ExData;

typedef void BSL_USER_ExDataNew(void *parent, void *ptr, BSL_USER_ExData *ad, int idx, long argl, void *argp);
typedef void BSL_USER_ExDataFree(void *parent, void *ptr, BSL_USER_ExData *ad, int idx, long argl, void *argp);
typedef int BSL_USER_ExDataDup(BSL_USER_ExData *to, const BSL_USER_ExData *from, void **fromD, int idx, long argl,
    void *argp);

int BSL_USER_SetExData(BSL_USER_ExData *ad, int32_t idx, void *val);

void *BSL_USER_GetExData(const BSL_USER_ExData *ad, int32_t idx);

int BSL_USER_GetExDataNewIndex(int32_t index, int64_t argl, const void *argp, void *newFunc, void *dupFunc,
    void *freeFunc);

void BSL_USER_FreeExDataIndex(int32_t index, void *obj, BSL_USER_ExData *ad);

#ifdef __cplusplus
}
#endif

#endif // BSL_USER_DATA_H
