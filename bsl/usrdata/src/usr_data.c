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

#include "hitls_build.h"
#ifdef HITLS_BSL_USRDATA

#include <stddef.h>
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_user_data.h"

typedef struct {
    long argl;  /* Arbitrary long */
    void *argp; /* Arbitrary void * */
    BSL_USER_ExDataNew *newFunc;
    BSL_USER_ExDataFree *freeFunc;
    BSL_USER_ExDataDup *dupFunc;
} BSL_EX_CALLBACK;

BSL_EX_CALLBACK g_exCallBack[BSL_MAX_EX_TYPE][BSL_MAX_EX_DATA];

int BSL_USER_GetExDataNewIndex(int32_t index, int64_t argl, const void *argp, const void *newFunc, const void *dupFunc,
    void *freeFunc)
{
    if (index < 0 || index >= BSL_MAX_EX_TYPE) {
        return -1;
    }

    (void)argl;
    (void)argp;
    (void)newFunc;
    (void)dupFunc;
    // The preceding parameters will not be used. Only the freefunc will be used.
    static int idxSsl = 1; // The index starts from 1, 0 indicates app data.
    static int idxX509StoreCtx = 1;
    static int idxSslCtx = 1;
    static int idxX509Store = 1;
    static int idxUio = 1;
    int idx = -1;
    switch (index) {
        case BSL_USER_DATA_EX_INDEX_SSL:
            idx = idxSsl++;
            break;
        case BSL_USER_DATA_EX_INDEX_X509_STORE_CTX:
            idx = idxX509StoreCtx++;
            break;
        case BSL_USER_DATA_EX_INDEX_SSL_CTX:
            idx = idxSslCtx++;
            break;
        case BSL_USER_DATA_EX_INDEX_X509_STORE:
            idx = idxX509Store++;
            break;
        case BSL_USER_DATA_EX_INDEX_UIO:
            idx = idxUio++;
            break;
        default:
            return -1;
    }

    if (idx != -1 && idx < BSL_MAX_EX_DATA) {
        g_exCallBack[index][idx].freeFunc = freeFunc;
    }

    return idx;
}

int BSL_USER_SetExData(BSL_USER_ExData *ad, int32_t idx, void *val)
{
    if (ad == NULL || idx >= BSL_MAX_EX_DATA || idx < 0) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    ad->sk[idx] = val;
    return BSL_SUCCESS;
}

void *BSL_USER_GetExData(const BSL_USER_ExData *ad, int32_t idx)
{
    if (ad == NULL || idx >= BSL_MAX_EX_DATA || idx < 0) {
        return NULL;
    }
    return ad->sk[idx];
}

void BSL_USER_FreeExDataIndex(int32_t index, void *obj, BSL_USER_ExData *ad)
{
    if (index < 0 || index >= BSL_MAX_EX_TYPE || ad == NULL) {
        return;
    }

    for (int32_t i = 0; i < BSL_MAX_EX_DATA; i++) {
        if (ad->sk[i] != NULL && g_exCallBack[index][i].freeFunc != NULL) {
            g_exCallBack[index][i].freeFunc(obj, ad->sk[i], ad, 0, 0, 0);
        }
    }
    return;
}
#endif /* HITLS_BSL_USRDATA */
