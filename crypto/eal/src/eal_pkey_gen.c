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
#include "crypt_types.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "eal_md_local.h"
#include "eal_common.h"
#include "crypt_ealinit.h"
#include "bsl_err_internal.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "eal_pkey.h"
#ifdef HITLS_CRYPTO_PROVIDER
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#endif

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
    dest->recover = method->recover;
    dest->computeShareKey = method->computeShareKey;
    dest->encrypt = method->encrypt;
    dest->decrypt = method->decrypt;
    dest->headd = method->headd;
    dest->hemul = method->hemul;
    dest->check = method->check;
    dest->cmp = method->cmp;
    dest->pkeyEncaps = method->pkeyEncaps;
    dest->pkeyDecaps = method->pkeyDecaps;
    dest->blind = method->blind;
    dest->unBlind = method->unBlind;
}

CRYPT_EAL_PkeyCtx *PkeyNewDefaultCtx(CRYPT_PKEY_AlgId id)
{
    /* Obtain the method based on the algorithm ID. */
    const EAL_PkeyMethod *method = CRYPT_EAL_PkeyFindMethod(id);
    if (method == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_EAL_ERR_ALGID);
        return NULL;
    }
    /* Resource application and initialization */
    CRYPT_EAL_PkeyCtx *pkey = BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_PkeyCtx));
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    EalPkeyCopyMethod(method, &pkey->method);
    pkey->key = pkey->method.newCtx();
    if (pkey->key == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(pkey);
        return NULL;
    }
    pkey->id = id;
    BSL_SAL_ReferencesInit(&(pkey->references));
    return pkey;
}

CRYPT_EAL_PkeyCtx *CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_AlgId id)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Pkey(id) != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    return PkeyNewDefaultCtx(id);
}


static int32_t PkeyCopyCtx(CRYPT_EAL_PkeyCtx *to, const CRYPT_EAL_PkeyCtx *from)
{
    if (from->method.dupCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, from->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    (void)memcpy_s(to, sizeof(CRYPT_EAL_PkeyCtx), from, sizeof(CRYPT_EAL_PkeyCtx));
    (void)memset_s(&(to->references), sizeof(BSL_SAL_RefCount), 0, sizeof(BSL_SAL_RefCount));
    to->key = from->method.dupCtx(from->key);
    if (to->key == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, from->id, CRYPT_EAL_PKEY_DUP_ERROR);
        return CRYPT_EAL_PKEY_DUP_ERROR;
    }
    to->method = from->method;
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
        if (to->method.freeCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        to->method.freeCtx(to->key);
        to->key = NULL;
    }
    BSL_SAL_ReferencesFree(&(to->references));
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
    int ref = 0;
    BSL_SAL_AtomicDownReferences(&(pkey->references), &ref);
    if (ref > 0) {
        return;
    }

    if (pkey->method.freeCtx != NULL) {
        pkey->method.freeCtx(pkey->key);
        pkey->key = NULL;
    }
    BSL_SAL_ReferencesFree(&(pkey->references));
    EAL_EVENT_REPORT(CRYPT_EVENT_ZERO, CRYPT_ALGO_PKEY, pkey->id, CRYPT_SUCCESS);
    BSL_SAL_Free(pkey);
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
    int32_t ret = ParaIsVaild(pkey, para);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, ret);
        return ret;
    }

    if (pkey->method.setPara == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    ret = PkeyProviderSetPara(pkey, para);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeySetParaEx(CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *param)
{
    if (pkey == NULL || param == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pkey->method.setPara == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = pkey->method.setPara(pkey->key, param);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeyGetPara(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPara *para)
{
    int32_t ret = ParaIsVaild(pkey, para);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, ret);
        return ret;
    }

    if (pkey->method.getPara == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    ret = PkeyProviderGetPara(pkey, para);
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
    if (pkey->method.ctrl == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = pkey->method.ctrl(pkey->key, opt, val, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeySetParaById(CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_ParaId id)
{
    int32_t paraId = (int32_t)id;
    return CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID, &paraId, sizeof(paraId));
}

int32_t CRYPT_EAL_PkeyGen(CRYPT_EAL_PkeyCtx *pkey)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pkey->method.gen == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    /* Invoke the algorithm entity to generate a key pair. */
    int32_t ret = pkey->method.gen(pkey->key);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
        return ret;
    }
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
    CRYPT_PKEY_AlgId id =
        isPriKey == true ? ((CRYPT_EAL_PkeyPrv *)(uintptr_t)key)->id : ((CRYPT_EAL_PkeyPub *)(uintptr_t)key)->id;
    if (id != pkey->id) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
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
    if (pkey->method.setPub == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    ret = PkeyProviderSetPub(pkey, key);
    EAL_EVENT_REPORT((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_SETSSP : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

int32_t CRYPT_EAL_PkeySetPrv(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPrv *key)
{
    int32_t ret = PriAndPubParamIsValid(pkey, key, true);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, (pkey == NULL) ? CRYPT_PKEY_MAX : pkey->id, ret);
        return ret;
    }
    if (pkey->method.setPrv == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    ret = PkeyProviderSetPrv(pkey, key);
    EAL_EVENT_REPORT((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_SETSSP : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

static int32_t CommonParaGet(const CRYPT_EAL_PkeyCtx *pkey, BSL_Param *param,
    int32_t (*getFunc)(const void *key, void *para))
{
    if (pkey == NULL || param == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (getFunc == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = getFunc(pkey->key, param);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

static int32_t CommonParaSet(CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *param,
    int32_t (*setFunc)(void *key, const void *para))
{
    if (pkey == NULL || param == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (setFunc == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = setFunc(pkey->key, param);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeyGetPubEx(const CRYPT_EAL_PkeyCtx *pkey, BSL_Param *param)
{
    return CommonParaGet(pkey, param, pkey == NULL ? NULL : pkey->method.getPub);
}

int32_t CRYPT_EAL_PkeySetPubEx(CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *param)
{
    return CommonParaSet(pkey, param, pkey == NULL ? NULL : pkey->method.setPub);
}

int32_t CRYPT_EAL_PkeyGetPrvEx(const CRYPT_EAL_PkeyCtx *pkey, BSL_Param *param)
{
    return CommonParaGet(pkey, param, pkey == NULL ? NULL : pkey->method.getPrv);
}

int32_t CRYPT_EAL_PkeySetPrvEx(CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *param)
{
    return CommonParaSet(pkey, param, pkey == NULL ? NULL : pkey->method.setPrv);
}

int32_t CRYPT_EAL_PkeyGetPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPub *key)
{
    int32_t ret = PriAndPubParamIsValid(pkey, key, false);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, (pkey == NULL) ? CRYPT_PKEY_MAX : pkey->id, ret);
        return ret;
    }
    if (pkey->method.getPub == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    ret = PkeyProviderGetPub(pkey, key);
    EAL_EVENT_REPORT((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_GETSSP : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

int32_t CRYPT_EAL_PkeyGetPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPrv *key)
{
    int32_t ret = PriAndPubParamIsValid(pkey, key, true);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, (pkey == NULL) ? CRYPT_PKEY_MAX : pkey->id, ret);
        return ret;
    }
    if (pkey->method.getPrv == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    ret = PkeyProviderGetPrv(pkey, key);
    EAL_EVENT_REPORT((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_GETSSP : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

uint32_t CRYPT_EAL_PkeyGetSignLen(const CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t result = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)(uintptr_t)pkey,
        CRYPT_CTRL_GET_SIGNLEN, &result, sizeof(result));
    return ret == CRYPT_SUCCESS ? result : 0;
}

uint32_t CRYPT_EAL_PkeyGetKeyLen(const CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t result = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)(uintptr_t)pkey,
        CRYPT_CTRL_GET_BITS, &result, sizeof(result));
    return ret == CRYPT_SUCCESS ? ((result + 7) >> 3) : 0; // bytes = (bits + 7) >> 3
}

uint32_t CRYPT_EAL_PkeyGetKeyBits(const CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t result = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)(uintptr_t)pkey,
        CRYPT_CTRL_GET_BITS, &result, sizeof(result));
    return ret  == CRYPT_SUCCESS ? result : 0;
}

uint32_t CRYPT_EAL_PkeyGetSecurityBits(const CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t result = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)(uintptr_t)pkey,
        CRYPT_CTRL_GET_SECBITS, &result, sizeof(result));
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
    int32_t ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)(uintptr_t)pkey, CRYPT_CTRL_GET_PARAID,
        &result, sizeof(result));
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

    if (a->method.cmp == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, a->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    return a->method.cmp(a->key, b->key);
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

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t CRYPT_EAL_SetKeyMethod(const CRYPT_EAL_Func *funcsKeyMgmt, EAL_PkeyUnitaryMethod *method)
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
                case CRYPT_EAL_IMPLPKEYMGMT_CTRL:
                    method->ctrl = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_FREECTX:
                    method->freeCtx = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_IMPORT:
                    method->import = funcsKeyMgmt[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYMGMT_EXPORT:
                    method->export = funcsKeyMgmt[index].func;
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

#ifdef HITLS_CRYPTO_PKEY_CRYPT
static int32_t CRYPT_EAL_SetCipherMethod(const CRYPT_EAL_Func *funcsAsyCipher, EAL_PkeyUnitaryMethod *method)
{
    int32_t index = 0;
    if (funcsAsyCipher != NULL) {
        while (funcsAsyCipher[index].id != 0) {
            switch (funcsAsyCipher[index].id) {
                case CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT:
                    method->encrypt = funcsAsyCipher[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT:
                    method->decrypt = funcsAsyCipher[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYCIPHER_HEADD:
                    method->headd = funcsAsyCipher[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYCIPHER_HEMUL:
                    method->hemul = funcsAsyCipher[index].func;
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
#endif

#ifdef HITLS_CRYPTO_PKEY_EXCH
static int32_t CRYPT_EAL_SetExchMethod(const CRYPT_EAL_Func *funcsExch, EAL_PkeyUnitaryMethod *method)
{
    int32_t index = 0;
    if (funcsExch != NULL) {
        while (funcsExch[index].id != 0) {
            switch (funcsExch[index].id) {
                case CRYPT_EAL_IMPLPKEYEXCH_EXCH:
                    method->computeShareKey = funcsExch[index].func;
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
#endif

#ifdef HITLS_CRYPTO_PKEY_SIGN
static int32_t CRYPT_EAL_SetSignMethod(const CRYPT_EAL_Func *funcSign, EAL_PkeyUnitaryMethod *method)
{
    int32_t index = 0;
    if (funcSign != NULL) {
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
                case CRYPT_EAL_IMPLPKEYSIGN_BLIND:
                    method->blind = funcSign[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYSIGN_UNBLIND:
                    method->unBlind = funcSign[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYSIGN_RECOVER:
                    method->recover = funcSign[index].func;
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
#endif

#ifdef HITLS_CRYPTO_PKEY_KEM
static int32_t CRYPT_EAL_SetKemMethod(const CRYPT_EAL_Func *funcKem, EAL_PkeyUnitaryMethod *method)
{
    int32_t index = 0;
    if (funcKem != NULL) {
        while (funcKem[index].id != 0) {
            switch (funcKem[index].id) {
                case CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE_INIT:
                    method->encapsInit = funcKem[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE_INIT:
                    method->decapsInit = funcKem[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE:
                    method->pkeyEncaps = funcKem[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE:
                    method->pkeyDecaps = funcKem[index].func;
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
#endif

int32_t CRYPT_EAL_SetPkeyMethod(EAL_PkeyUnitaryMethod *method, const CRYPT_EAL_Func *funcsKeyMgmt,
    const CRYPT_EAL_Func *funcsAsyCipher, const CRYPT_EAL_Func *funcsExch, const CRYPT_EAL_Func *funcSign,
    const CRYPT_EAL_Func *funcKem)
{
    (void)funcsAsyCipher;
    (void)funcsExch;
    (void)funcSign;
    (void)funcKem;
    int32_t ret = CRYPT_EAL_SetKeyMethod(funcsKeyMgmt, method);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
#ifdef HITLS_CRYPTO_PKEY_CRYPT
    ret = CRYPT_EAL_SetCipherMethod(funcsAsyCipher, method);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
#endif
#ifdef HITLS_CRYPTO_PKEY_EXCH
    ret = CRYPT_EAL_SetExchMethod(funcsExch, method);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
#endif
#ifdef HITLS_CRYPTO_PKEY_SIGN
    ret = CRYPT_EAL_SetSignMethod(funcSign, method);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(method);
        return ret;
    }
#endif
#ifdef HITLS_CRYPTO_PKEY_KEM
    ret = CRYPT_EAL_SetKemMethod(funcKem, method);
#endif
    return ret;
}

static int32_t ProviderGetTargetFuncs(CRYPT_EAL_LibCtx *libCtx, int32_t operaId, int32_t algId,
    const char *attrName, const CRYPT_EAL_Func **funcs, CRYPT_EAL_ProvMgrCtx **mgrCtx)
{
    int32_t ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, operaId, algId, attrName, funcs, mgrCtx, true);
    return ret == CRYPT_NOT_SUPPORT ? CRYPT_SUCCESS : ret;
}

int32_t CRYPT_EAL_ProviderGetAsyAlgFuncs(CRYPT_EAL_LibCtx *libCtx, int32_t algId, uint32_t pkeyOperType,
    const char *attrName, CRYPT_EAL_AsyAlgFuncsInfo *funcs)
{
    int32_t ret = CRYPT_PROVIDER_NOT_SUPPORT;
    if (pkeyOperType == CRYPT_EAL_PKEY_UNKNOWN_OPERATE) {
#ifdef HITLS_CRYPTO_PKEY_CRYPT
        RETURN_RET_IF_ERR(ProviderGetTargetFuncs(libCtx, CRYPT_EAL_OPERAID_ASYMCIPHER, algId,
            attrName, &funcs->funcsAsyCipher, &funcs->mgrCtx), ret);
#endif
#ifdef HITLS_CRYPTO_PKEY_EXCH
        RETURN_RET_IF_ERR(ProviderGetTargetFuncs(libCtx, CRYPT_EAL_OPERAID_KEYEXCH, algId,
            attrName, &funcs->funcsExch, &funcs->mgrCtx), ret);
#endif
#ifdef HITLS_CRYPTO_PKEY_SIGN
        RETURN_RET_IF_ERR(ProviderGetTargetFuncs(libCtx, CRYPT_EAL_OPERAID_SIGN, algId,
            attrName, &funcs->funcSign, &funcs->mgrCtx), ret);
#endif
#ifdef HITLS_CRYPTO_PKEY_KEM
        RETURN_RET_IF_ERR(ProviderGetTargetFuncs(libCtx, CRYPT_EAL_OPERAID_KEM, algId,
            attrName, &funcs->funcKem, &funcs->mgrCtx), ret);
#endif
    }
#ifdef HITLS_CRYPTO_PKEY_CRYPT
    if ((pkeyOperType & CRYPT_EAL_PKEY_CIPHER_OPERATE) == CRYPT_EAL_PKEY_CIPHER_OPERATE) {
        ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, CRYPT_EAL_OPERAID_ASYMCIPHER, algId, attrName,
            &funcs->funcsAsyCipher, &funcs->mgrCtx, false);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
#endif
#ifdef HITLS_CRYPTO_PKEY_EXCH
    if ((pkeyOperType & CRYPT_EAL_PKEY_EXCH_OPERATE) == CRYPT_EAL_PKEY_EXCH_OPERATE) {
        ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, CRYPT_EAL_OPERAID_KEYEXCH, algId, attrName,
            &funcs->funcsExch, &funcs->mgrCtx, false);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
#endif
#ifdef HITLS_CRYPTO_PKEY_SIGN
    if ((pkeyOperType & CRYPT_EAL_PKEY_SIGN_OPERATE) == CRYPT_EAL_PKEY_SIGN_OPERATE) {
        ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, CRYPT_EAL_OPERAID_SIGN, algId, attrName,
            &funcs->funcSign, &funcs->mgrCtx, false);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
#endif
#ifdef HITLS_CRYPTO_PKEY_KEM
    if ((pkeyOperType & CRYPT_EAL_PKEY_KEM_OPERATE) == CRYPT_EAL_PKEY_KEM_OPERATE) {
        ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, CRYPT_EAL_OPERAID_KEM, algId, attrName,
            &funcs->funcKem, &funcs->mgrCtx, false);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
#endif
    ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, CRYPT_EAL_OPERAID_KEYMGMT, algId, attrName,
        &funcs->funcsKeyMgmt, &funcs->mgrCtx, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

CRYPT_EAL_PkeyCtx *CRYPT_EAL_ProviderPkeyNewCtxInner(CRYPT_EAL_LibCtx *libCtx, int32_t algId, uint32_t pkeyOperType,
    const char *attrName)
{
    void *provCtx = NULL;
    CRYPT_EAL_AsyAlgFuncsInfo funcInfo = {NULL, NULL, NULL, NULL, NULL, NULL};
    int32_t ret = CRYPT_EAL_ProviderGetAsyAlgFuncs(libCtx, algId, pkeyOperType, attrName, &funcInfo);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, algId, ret);
        return NULL;
    }
    ret = CRYPT_EAL_ProviderCtrl(funcInfo.mgrCtx, CRYPT_PROVIDER_GET_USER_CTX, &provCtx, sizeof(provCtx));
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, algId, ret);
        return NULL;
    }
    CRYPT_EAL_PkeyCtx *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_PkeyCtx));
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, algId, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    GOTO_ERR_IF(CRYPT_EAL_SetPkeyMethod(&(ctx->method), funcInfo.funcsKeyMgmt, funcInfo.funcsAsyCipher,
        funcInfo.funcsExch, funcInfo.funcSign, funcInfo.funcKem), ret);

    if (ctx->method.provNewCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, algId, CRYPT_PROVIDER_ERR_IMPL_NULL);
        goto ERR;
    }

    ctx->key = ctx->method.provNewCtx(provCtx, algId);
    if (ctx->key == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, algId, CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    ctx->isProvider = true;
    ctx->id = algId;
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
ERR:
    BSL_SAL_Free(ctx);
    return NULL;
}
#endif // HITLS_CRYPTO_PROVIDER

CRYPT_EAL_PkeyCtx *CRYPT_EAL_ProviderPkeyNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, uint32_t pkeyOperType,
    const char *attrName)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return CRYPT_EAL_ProviderPkeyNewCtxInner(libCtx, algId, pkeyOperType, attrName);
#else
    (void)libCtx;
    (void)pkeyOperType;
    (void)attrName;
    return CRYPT_EAL_PkeyNewCtx(algId);
#endif
}

#endif
