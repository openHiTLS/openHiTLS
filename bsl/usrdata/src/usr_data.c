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
#include "bsl_sal.h"

typedef struct {
    long argl; /* Arbitrary long */
    void *argp; /* Arbitrary void * */
    BSL_USER_ExDataNew *newFunc;
    BSL_USER_ExDataFree *freeFunc;
    BSL_USER_ExDataDup *dupFunc;
} BSL_EX_CALLBACK;

BSL_EX_CALLBACK g_exCallBack[BSL_MAX_EX_TYPE][BSL_MAX_EX_DATA];

static BSL_SAL_ThreadLockHandle g_exDataLock = NULL;

static uint32_t g_exDataInit = BSL_SAL_ONCE_INIT;
static void BSL_USER_ExDataInitOnce(void)
{
    int32_t ret = BSL_SAL_ThreadLockNew(&g_exDataLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
}

static int BSL_USER_GetLock(bool isWrite)
{
    int32_t ret = BSL_SAL_ThreadRunOnce(&g_exDataInit, BSL_USER_ExDataInitOnce);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (isWrite) {
        ret = BSL_SAL_ThreadWriteLock(g_exDataLock);
    } else {
        ret = BSL_SAL_ThreadReadLock(g_exDataLock);
    }

    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return BSL_SUCCESS;
}

int BSL_USER_GetExDataNewIndex(int32_t classIndex, int64_t argl, void *argp, void *newFunc, void *dupFunc,
                               void *freeFunc)
{
    if (classIndex < 0 || classIndex >= BSL_MAX_EX_TYPE) {
        return -1;
    }
    int ret = BSL_USER_GetLock(false);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    static int classIndexList[BSL_MAX_EX_TYPE] = {0};
    if (classIndexList[classIndex] == 0) {
        classIndexList[classIndex] = 1; // Initialize the index for this class
    }
    int idx = -1;
    if (classIndexList[classIndex] < BSL_MAX_EX_DATA) {
        idx = classIndexList[classIndex]++;
        g_exCallBack[classIndex][idx].argl = argl;
        g_exCallBack[classIndex][idx].argp = argp;
        g_exCallBack[classIndex][idx].freeFunc = freeFunc;
        g_exCallBack[classIndex][idx].newFunc = newFunc;
        g_exCallBack[classIndex][idx].dupFunc = dupFunc;
    }
    (void)BSL_SAL_ThreadUnlock(g_exDataLock);
    return idx;
}

int BSL_USER_SetExData(BSL_USER_ExData *ad, int32_t idx, void *val)
{
    if (ad == NULL || idx >= BSL_MAX_EX_DATA || idx < 0) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    int ret = BSL_USER_GetLock(true);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ad->sk[idx] = val;
    (void)BSL_SAL_ThreadUnlock(g_exDataLock);
    return BSL_SUCCESS;
}

void *BSL_USER_GetExData(const BSL_USER_ExData *ad, int32_t idx)
{
    if (ad == NULL || idx >= BSL_MAX_EX_DATA || idx < 0) {
        return NULL;
    }
    return ad->sk[idx];
}

int BSL_USER_NewExData(int32_t classIndex, void *obj, BSL_USER_ExData *ad)
{
    if (classIndex < 0 || classIndex >= BSL_MAX_EX_TYPE || ad == NULL) {
        return BSL_NULL_INPUT;
    }
    int ret = BSL_USER_GetLock(true);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_EX_CALLBACK exCallBack[BSL_MAX_EX_DATA];
    for (int32_t i = 0; i < BSL_MAX_EX_DATA; i++) {
        exCallBack[i] = g_exCallBack[classIndex][i];
    }
    (void)BSL_SAL_ThreadUnlock(g_exDataLock);
    for (int32_t i = 0; i < BSL_MAX_EX_DATA; i++) {
        if (exCallBack[i].newFunc != NULL) {
            exCallBack[i].newFunc(obj, ad->sk[i], ad, i, exCallBack[i].argl, exCallBack[i].argp);
        }
    }
    return BSL_SUCCESS;
}

int BSL_USER_AllocExData(int32_t classIndex, void *obj, BSL_USER_ExData *ad, int index)
{
    if (classIndex < 0 || classIndex >= BSL_MAX_EX_TYPE || ad == NULL || index < 0 || index >= BSL_MAX_EX_DATA) {
        return -1;
    }
    if (BSL_USER_GetExData(ad, index) != NULL) {
        return BSL_SUCCESS;
    }
    int ret = BSL_USER_GetLock(true);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_EX_CALLBACK exCallBack;
    exCallBack = g_exCallBack[classIndex][index];
    (void)BSL_SAL_ThreadUnlock(g_exDataLock);
    if (exCallBack.newFunc != NULL) {
        exCallBack.newFunc(obj, NULL, ad, index, exCallBack.argl, exCallBack.argp);
    }
    return BSL_SUCCESS;
}

void BSL_USER_FreeExData(int32_t classIndex, void *obj, BSL_USER_ExData *ad)
{
    if (classIndex < 0 || classIndex >= BSL_MAX_EX_TYPE || ad == NULL) {
        return;
    }
    int ret = BSL_USER_GetLock(true);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return;
    }
    BSL_EX_CALLBACK exCallBack[BSL_MAX_EX_DATA];
    for (int32_t i = 0; i < BSL_MAX_EX_DATA; i++) {
        exCallBack[i] = g_exCallBack[classIndex][i];
    }
    (void)BSL_SAL_ThreadUnlock(g_exDataLock);
    for (int32_t i = 0; i < BSL_MAX_EX_DATA; i++) {
        if (ad->sk[i] != NULL && exCallBack[i].freeFunc != NULL) {
            exCallBack[i].freeFunc(obj, ad->sk[i], ad, i, exCallBack[i].argl, exCallBack[i].argp);
        }
    }
}

int BSL_USER_FreeExIndex(int32_t classIndex, int idx)
{
    if (classIndex < 0 || classIndex >= BSL_MAX_EX_TYPE || idx < 0 || idx >= BSL_MAX_EX_DATA) {
        return -1;
    }
    int ret = -1;
    ret = BSL_USER_GetLock(true);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return -1;
    }
    BSL_EX_CALLBACK *exCallBack = &g_exCallBack[classIndex][idx];
    if (exCallBack != NULL) {
        exCallBack->freeFunc = NULL;
        exCallBack->newFunc = NULL;
        exCallBack->dupFunc = NULL;
        ret = BSL_SUCCESS;
    }

    (void)BSL_SAL_ThreadUnlock(g_exDataLock);
    return ret;
}

#endif /* HITLS_BSL_USRDATA */
