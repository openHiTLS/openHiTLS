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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_PKEY)

#include <stdlib.h>
#include <stdbool.h>
#include "securec.h"
#include "eal_pkey_local.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_local_types.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "eal_md_local.h"
#include "eal_common.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_pkey.h"
#include "bsl_err_internal.h"
#include "crypt_provider.h"

static void EalPkeyCopyMethod(const EAL_PkeyMethod *method, EAL_PkeyUnitaryMethod *dest)
{
    dest->newCtx = method->newCtx;
    dest->dupCtx = method->dupCtx;
    dest->freeCtx = method->freeCtx;
    dest->setPara = method->setPara;
    dest->getPara = method->getPara;
    dest->gen = method->gen;
    dest->ctrl = method->ctrl;
    dest->setPub = method->setPub;
    dest->setPrv = method->setPrv;
    dest->getPub = method->getPub;
    dest->getPrv = method->getPrv;
    dest->sign = method->sign;
    dest->signData = method->signData;
    dest->verify = method->verify;
    dest->verifyData = method->verifyData;
    dest->computeShareKey = method->computeShareKey;
    dest->encrypt = method->encrypt;
    dest->decrypt = method->decrypt;
    dest->check = method->check;
    dest->cmp = method->cmp;
    dest->copyPara = method->copyPara;
}

CRYPT_EAL_PkeyCtx *PkeyNewDefaultCtx(CRYPT_PKEY_AlgId id)
{
    /* Obtain the method based on the algorithm ID. */
    const EAL_PkeyMethod *method = CRYPT_EAL_PkeyFindMethod(id);
    if (method == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_EAL_ERR_ALGID);
        return NULL;
    }
    EAL_PkeyUnitaryMethod *temp = BSL_SAL_Calloc(1, sizeof(EAL_PkeyUnitaryMethod));
    if (temp == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    EalPkeyCopyMethod(method, temp);
    /* Resource application and initialization */
    CRYPT_EAL_PkeyCtx *pkey = BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_PkeyCtx));
    if (pkey == NULL) {
        BSL_SAL_FREE(temp);
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    pkey->key = method->newCtx();
    if (pkey->key == NULL) {
        BSL_SAL_FREE(temp);
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    pkey->method = temp;
    pkey->id = id;
    BSL_SAL_ReferencesInit(&(pkey->references));
    return pkey;
ERR:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return NULL;
}

CRYPT_EAL_PkeyCtx *CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_AlgId id)
{
    return PkeyNewDefaultCtx(id);
}


static int32_t PkeyCopyCtx(CRYPT_EAL_PkeyCtx *to, const CRYPT_EAL_PkeyCtx *from)
{
    if (from->method == NULL || from->method->dupCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, from->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    (void)memcpy_s(to, sizeof(CRYPT_EAL_PkeyCtx), from, sizeof(CRYPT_EAL_PkeyCtx));
    to->key = from->method->dupCtx(from->key);
    if (to->key == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, from->id, CRYPT_EAL_PKEY_DUP_ERROR);
        return CRYPT_EAL_PKEY_DUP_ERROR;
    }
    EAL_PkeyUnitaryMethod *temp = BSL_SAL_Calloc(1, sizeof(EAL_PkeyUnitaryMethod));
    if (temp == NULL) {
        from->method->freeCtx(to->key);
        to->key = NULL;
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, from->id, CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    to->method = temp;
    *(EAL_PkeyUnitaryMethod *)(uintptr_t)to->method = *from->method;
    BSL_SAL_ReferencesInit(&(to->references));
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_PkeyCopyCtx(CRYPT_EAL_PkeyCtx *to, const CRYPT_EAL_PkeyCtx *from)
{
    if (to == NULL || from == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (to->key != NULL) {
        if (to->method->freeCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        to->method->freeCtx(to->key);
        to->key = NULL;
    }
    return PkeyCopyCtx(to, from);
}

CRYPT_EAL_PkeyCtx *CRYPT_EAL_PkeyDupCtx(const CRYPT_EAL_PkeyCtx *pkey)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_EAL_PkeyCtx *newPkey = BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_PkeyCtx));
    if (newPkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    if (PkeyCopyCtx(newPkey, pkey) != CRYPT_SUCCESS) {
        BSL_SAL_FREE(newPkey);
        return NULL;
    }
    return newPkey;
}

void CRYPT_EAL_PkeyFreeCtx(CRYPT_EAL_PkeyCtx *pkey)
{
    if (pkey == NULL) {
        return;
    }
    if (pkey->method == NULL || pkey->method->freeCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        BSL_SAL_ReferencesFree(&(pkey->references));
        BSL_SAL_FREE(pkey->method);
        BSL_SAL_FREE(pkey);
        return;
    }
    int ref = 0;
    BSL_SAL_AtomicDownReferences(&(pkey->references), &ref);
    if (ref > 0) {
        return;
    }
    EAL_EventReport(CRYPT_EVENT_ZERO, CRYPT_ALGO_KDF, pkey->id, CRYPT_SUCCESS);
    BSL_SAL_ReferencesFree(&(pkey->references));
    pkey->method->freeCtx(pkey->key);
    BSL_SAL_FREE(pkey->method);
    BSL_SAL_FREE(pkey);
    return;
}

static int32_t ParaIsVaild(const CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPara *para)
{
    bool isInputValid = (pkey == NULL) || (para == NULL);
    if (isInputValid) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pkey->id != para->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_PkeySetPara(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPara *para)
{
    int32_t ret;
    ret = ParaIsVaild(pkey, para);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, ret);
        return ret;
    }
    if (pkey->method == NULL || pkey->method->setPara == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    CRYPT_Param cryptParam = {0};
    cryptParam.type = DEFAULT_PROVIDER_PARAM_TYPE;
    cryptParam.param = (void *)&(para->para);
    ret = pkey->method->setPara(pkey->key, &cryptParam);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeyGetPara(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPara *para)
{
    int32_t ret;
    ret = ParaIsVaild(pkey, para);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, ret);
        return ret;
    }
    if (pkey->method == NULL || pkey->method->getPara == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    CRYPT_Param cryptParam;
    cryptParam.type = DEFAULT_PROVIDER_PARAM_TYPE;
    cryptParam.param = (void *)&(para->para);
    ret = pkey->method->getPara(pkey->key, &cryptParam);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeyCtrl(CRYPT_EAL_PkeyCtx *pkey, int32_t opt, void *val, uint32_t len)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method == NULL || pkey->method->ctrl == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = pkey->method->ctrl(pkey->key, opt, val, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeySetParaById(CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_ParaId id)
{
    return CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID, &id, sizeof(id));
}

int32_t CRYPT_EAL_PkeyGen(CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t ret;
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method == NULL || pkey->method->gen == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    /* Invoke the algorithm entity to generate a key pair. */
    ret = pkey->method->gen(pkey->key);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
        return ret;
    }
    EAL_EventReport(CRYPT_EVENT_GEN, CRYPT_ALGO_PKEY, pkey->id, CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
}

static int32_t PriAndPubParamIsValid(const CRYPT_EAL_PkeyCtx *pkey, const void *key, bool isPriKey)
{
    bool isInputValid = (pkey == NULL) || (key == NULL);
    if (isInputValid) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    // false indicates the public key path, and true indicates the private key path
    if (isPriKey == false) {
        CRYPT_EAL_PkeyPub *keyParam = (CRYPT_EAL_PkeyPub *)(uintptr_t)key;
        if (keyParam->id != pkey->id) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ERR_ALGID);
            return CRYPT_EAL_ERR_ALGID;
        }
    } else {
        CRYPT_EAL_PkeyPrv *keyParam = (CRYPT_EAL_PkeyPrv *)(uintptr_t)key;
        if (keyParam->id != pkey->id) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ERR_ALGID);
            return CRYPT_EAL_ERR_ALGID;
        }
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_PkeySetPub(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPub *key)
{
    int32_t ret = PriAndPubParamIsValid(pkey, key, false);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, (pkey == NULL) ? CRYPT_PKEY_MAX : pkey->id, ret);
        return ret;
    }
    if (pkey->method == NULL || pkey->method->setPub == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    CRYPT_Param cryptParam = {0};
    cryptParam.type = DEFAULT_PROVIDER_PARAM_TYPE;
    cryptParam.param = (void *)&(key->key.rsaPub);
    ret = pkey->method->setPub(pkey->key, &cryptParam);
    EAL_EventReport((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_SETSSP : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

int32_t CRYPT_EAL_PkeySetPrv(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPrv *key)
{
    int32_t ret = PriAndPubParamIsValid(pkey, key, true);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, (pkey == NULL) ? CRYPT_PKEY_MAX : pkey->id, ret);
        return ret;
    }
    if (pkey->method == NULL || pkey->method->setPrv == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    CRYPT_Param cryptParam = {0};
    cryptParam.type = DEFAULT_PROVIDER_PARAM_TYPE;
    cryptParam.param = (void *)&(key->key.rsaPrv);
    ret = pkey->method->setPrv(pkey->key, &cryptParam);
    EAL_EventReport((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_SETSSP : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

int32_t CRYPT_EAL_PkeyGetPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPub *key)
{
    int32_t ret = PriAndPubParamIsValid(pkey, key, false);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, (pkey == NULL) ? CRYPT_PKEY_MAX : pkey->id, ret);
        return ret;
    }
    if (pkey->method == NULL || pkey->method->getPub == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    CRYPT_Param cryptParam = {0};
    cryptParam.type = DEFAULT_PROVIDER_PARAM_TYPE;
    cryptParam.param = (void *)&(key->key.rsaPub);
    ret = pkey->method->getPub(pkey->key, &cryptParam);
    EAL_EventReport((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_GETSSP : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

int32_t CRYPT_EAL_PkeyGetPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPrv *key)
{
    int32_t ret = PriAndPubParamIsValid(pkey, key, true);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, (pkey == NULL) ? CRYPT_PKEY_MAX : pkey->id, ret);
        return ret;
    }
    if (pkey->method == NULL || pkey->method->getPrv == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    CRYPT_Param cryptParam = {0};
    cryptParam.type = DEFAULT_PROVIDER_PARAM_TYPE;
    cryptParam.param = (void *)&(key->key.rsaPrv);
    ret = pkey->method->getPrv(pkey->key, &cryptParam);
    EAL_EventReport((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_GETSSP : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

uint32_t CRYPT_EAL_PkeyGetSignLen(const CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t result = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)pkey, CRYPT_CTRL_GET_SIGNLEN, &result, sizeof(result));
    return ret == CRYPT_SUCCESS ? result : 0;
}

uint32_t CRYPT_EAL_PkeyGetKeyLen(const CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t result = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)pkey, CRYPT_CTRL_GET_BITS, &result, sizeof(result));
    return ret == CRYPT_SUCCESS ? ((result + 7) >> 3) : 0; // bytes = (bits + 7) >> 3
}

uint32_t CRYPT_EAL_PkeyGetKeyBits(const CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t result = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)pkey, CRYPT_CTRL_GET_BITS, &result, sizeof(result));
    return ret  == CRYPT_SUCCESS ? result : 0;
}

uint32_t CRYPT_EAL_PkeyGetSecurityBits(const CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t result = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)pkey, CRYPT_CTRL_GET_SECBITS, &result, sizeof(result));
    return ret  == CRYPT_SUCCESS ? result : 0;
}

CRYPT_PKEY_AlgId CRYPT_EAL_PkeyGetId(const CRYPT_EAL_PkeyCtx *pkey)
{
    if (pkey == NULL) {
        return CRYPT_PKEY_MAX;
    }
    return pkey->id;
}

CRYPT_PKEY_ParaId CRYPT_EAL_PkeyGetParaId(const CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t result = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)pkey, CRYPT_CTRL_GET_PARAID, &result, sizeof(result));
    return ret  == CRYPT_SUCCESS ? result : CRYPT_PKEY_PARAID_MAX;
}


int32_t CRYPT_EAL_PkeyCmp(const CRYPT_EAL_PkeyCtx *a, const CRYPT_EAL_PkeyCtx *b)
{
    if (a == NULL || b == NULL) {
        if (a == b) {
            return CRYPT_SUCCESS;
        }
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (a->id != b->id) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_EAL_PKEY_CMP_DIFF_KEY_TYPE);
        return CRYPT_EAL_PKEY_CMP_DIFF_KEY_TYPE;
    }
    if (a->method == NULL || b->method == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (a->method->cmp == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, a->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    return a->method->cmp(a->key, b->key);
}

// Set the user's personal data. The life cycle is processed by the user. The value of data can be NULL,
// which is used to release the personal data and is set NULL.
int32_t CRYPT_EAL_PkeySetExtData(CRYPT_EAL_PkeyCtx *pkey, void *data)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    pkey->extData = data;
    return CRYPT_SUCCESS;
}

// Obtain user's personal data.
void *CRYPT_EAL_PkeyGetExtData(const CRYPT_EAL_PkeyCtx *pkey)
{
    if (pkey == NULL) {
        return NULL;
    }
    return pkey->extData;
}

bool CRYPT_EAL_PkeyIsValidAlgId(CRYPT_PKEY_AlgId id)
{
    return CRYPT_EAL_PkeyFindMethod(id) != NULL;
}

int32_t CRYPT_EAL_PkeyUpRef(CRYPT_EAL_PkeyCtx *pkey)
{
    int i = 0;
    if (pkey == NULL) {
        return CRYPT_NULL_INPUT;
    }
    return BSL_SAL_AtomicUpReferences(&(pkey->references), &i);
}

static int32_t CRYPT_EAL_SetKeyMethod(CRYPT_EAL_Func *funcsKeyMgmt, EAL_PkeyUnitaryMethod *method)
{
    int32_t index = 0;
    if (funcsKeyMgmt != NULL) {
        while (funcsKeyMgmt[index].id != 0) {
            switch (funcsKeyMgmt[index].id) {
                case CRYPT_EAL_IMPLPKEYMGMT_NEWCTX:
                    method->provNewCtx = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_SETPARAM:
                    method->setPara = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_GETPARAM:
                    method->getPara = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_GENKEY:
                    method->gen = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_SETPRV:
                    method->setPrv = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_SETPUB:
                    method->setPub = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_GETPRV:
                    method->getPrv = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_GETPUB:
                    method->getPub = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_DUPCTX:
                    method->dupCtx = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_CHECK:
                    method->check = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_COMPARE:
                    method->cmp = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_COPYPARAM:
                    method->copyPara = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_CTRL:
                    method->ctrl = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_FREECTX:
                    method->freeCtx = funcsKeyMgmt[index].func;
                    break;
                default:
                    BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                    return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        }
        index++;
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_EAL_SetCipherMethod(CRYPT_EAL_Func *funcsAsyCipher, EAL_PkeyUnitaryMethod *method)
{
    int32_t index = 0;
    if (funcsAsyCipher!=NULL) {
        while (funcsAsyCipher[index].id != 0) {
            switch (funcsAsyCipher[index].id) {
                case CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT:
                    method->encrypt = funcsAsyCipher[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT:
                    method->decrypt = funcsAsyCipher[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYCIPHER_CTRL:
                    method->ctrl = funcsAsyCipher[index].func;
                    break;
                default:
                    BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                    return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
            }
        index++;
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_EAL_SetExchMethod(CRYPT_EAL_Func *funcsExch, EAL_PkeyUnitaryMethod *method)
{
    int32_t index = 0;
    if (funcsExch!=NULL) {
        while (funcsExch[index].id != 0) {
            switch (funcsExch[index].id) {
                case CRYPT_EAL_IMPLPKEYEXCH_EXCH:
                    method->computeShareKey = funcsExch[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYEXCH_CTRL:
                    method->ctrl = funcsExch[index].func;
                    break;
                default:
                    BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                    return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
            }
        index++;
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_EAL_SetSignMethod(CRYPT_EAL_Func *funcSign, EAL_PkeyUnitaryMethod *method)
{
    int32_t index = 0;
    if (funcSign!=NULL) {
        while (funcSign[index].id != 0) {
            switch (funcSign[index].id) {
                case CRYPT_EAL_IMPLPKEYSIGN_SIGN:
                    method->sign = funcSign[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA:
                    method->signData = funcSign[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYSIGN_VERIFY:
                    method->verify = funcSign[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA:
                    method->verifyData = funcSign[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYSIGN_RECOVER:
                    method->recover = funcSign[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYSIGN_CTRL:
                    method->ctrl = funcSign[index].func;
                    break;
                default:
                    BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                    return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
            }
        index++;
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_EAL_SetPkeyMethod(CRYPT_EAL_PkeyCtx *ctx, CRYPT_EAL_Func *funcsKeyMgmt,
    CRYPT_EAL_Func *funcsAsyCipher, CRYPT_EAL_Func *funcsExch, CRYPT_EAL_Func *funcSign)
{
    int32_t ret;
    EAL_PkeyUnitaryMethod *method = BSL_SAL_Calloc(1, sizeof(EAL_PkeyUnitaryMethod));
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
        return BSL_MALLOC_FAIL;
    }
    
    ret = CRYPT_EAL_SetKeyMethod(funcsKeyMgmt, method);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(method);
        return ret;
    }
    
    ret = CRYPT_EAL_SetCipherMethod(funcsAsyCipher, method);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(method);
        return ret;
    }

    ret = CRYPT_EAL_SetExchMethod(funcsExch, method);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(method);
        return ret;
    }

    ret = CRYPT_EAL_SetSignMethod(funcSign, method);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(method);
        return ret;
    }
    ctx->method = method;
    return CRYPT_SUCCESS;
}

CRYPT_EAL_PkeyCtx *CRYPT_EAL_ProviderPkeyNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, uint32_t pkeyOperType,
    const char *attrName)
{
    CRYPT_EAL_Func *funcsKeyMgmt = NULL;
    CRYPT_EAL_Func *funcsAsyCipher = NULL;
    CRYPT_EAL_Func *funcsExch = NULL;
    CRYPT_EAL_Func *funcSign = NULL;
    void *provCtx = NULL;
    int32_t ret;
    ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_KEYMGMT, algId, attrName,
        (const CRYPT_EAL_Func **)&funcsKeyMgmt, &provCtx);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, algId, ret);
        return NULL;
    }
    if ((pkeyOperType & CRYPT_EAL_PKEY_CIPHER_OPERATE) == CRYPT_EAL_PKEY_CIPHER_OPERATE) {
        ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_ASYMCIPHER, algId, attrName,
            (const CRYPT_EAL_Func **)&funcsAsyCipher, &provCtx);
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, algId, ret);
            return NULL;
        }
    }
    if ((pkeyOperType & CRYPT_EAL_PKEY_EXCH_OPERATE) == CRYPT_EAL_PKEY_EXCH_OPERATE) {
        ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_KEYEXCH, algId, attrName,
            (const CRYPT_EAL_Func **)&funcsExch, &provCtx);
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, algId, ret);
            return NULL;
        }
    }
    if ((pkeyOperType & CRYPT_EAL_PKEY_SIGN_OPERATE) == CRYPT_EAL_PKEY_SIGN_OPERATE) {
        ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_SIGN, algId, attrName,
            (const CRYPT_EAL_Func **)&funcSign, &provCtx);
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, algId, ret);
            return NULL;
        }
    }
    CRYPT_EAL_PkeyCtx *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_PkeyCtx));
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, algId, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ret = CRYPT_EAL_SetPkeyMethod(ctx, funcsKeyMgmt, funcsAsyCipher, funcsExch, funcSign);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    if (ctx->method->provNewCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, algId, CRYPT_PROVIDER_ERR_IMPL_NULL);
        BSL_SAL_FREE(ctx->method);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    ctx->key = ctx->method->provNewCtx(provCtx, algId);
    if (ctx->key == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, algId, CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(ctx->method);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    ctx->isProvider = true;
    ctx->id = algId;
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}
#endif
