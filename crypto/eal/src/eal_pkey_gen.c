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
#include "crypt_method.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_local_types.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "eal_md_local.h"
#include "eal_common.h"
#include "crypt_method.h"

typedef struct {
    CRYPT_PKEY_AlgId pkeyId;
    CRYPT_PkeyCtrl ctrOpt;
    CRYPT_MD_AlgId mdId;
} PkeyNewOpt;

static const PkeyNewOpt NEW_OPT[] =  {
    {CRYPT_PKEY_SM2, CRYPT_CTRL_SET_SM2_HASH_METHOD, CRYPT_MD_SM3},
    {CRYPT_PKEY_ED25519, CRYPT_CTRL_SET_ED25519_HASH_METHOD, CRYPT_MD_SHA512}
};

static const PkeyNewOpt *PkeyGetOpt(CRYPT_PKEY_AlgId id)
{
    const uint32_t cnt = sizeof(NEW_OPT) / sizeof(PkeyNewOpt);
    for (uint32_t i = 0; i < cnt; i++) {
        if (id == NEW_OPT[i].pkeyId) {
            return &(NEW_OPT[i]);
        }
    }
    return NULL;
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

    const PkeyNewOpt *opt = PkeyGetOpt(id);
    pkey->key = method->newCtx();
    if (pkey->key == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    pkey->method = method;
    pkey->id = id;
    BSL_SAL_ReferencesInit(&(pkey->references));
    if (opt != NULL) {
        // The algorithm needs to register the specified hash method for calculation.
        const EAL_MdMethod *mdMethod = EAL_MdFindMethod(opt->mdId);
        if (mdMethod == NULL) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_EAL_ALG_NOT_SUPPORT);
            goto ERR;
        }
        int32_t ret = pkey->method->ctrl(pkey->key, opt->ctrOpt,
            (EAL_MdMethod *)(uintptr_t)mdMethod, sizeof(EAL_MdMethod));
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, ret);
            goto ERR;
        }
    }
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
    if (from->method->dupCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, from->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    (void)memcpy_s(to, sizeof(CRYPT_EAL_PkeyCtx), from, sizeof(CRYPT_EAL_PkeyCtx));
    to->key = from->method->dupCtx(from->key);
    if (to->key == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, from->id, CRYPT_EAL_PKEY_DUP_ERROR);
        return CRYPT_EAL_PKEY_DUP_ERROR;
    }
    BSL_SAL_ReferencesInit(&(to->references));
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_PkeyCopyCtx(CRYPT_EAL_PkeyCtx *to, const CRYPT_EAL_PkeyCtx *from)
{
    if (to == NULL || from == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (to->key != NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
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
    int ref = 0;
    BSL_SAL_AtomicDownReferences(&(pkey->references), &ref);
    if (ref > 0) {
        return;
    }
    BSL_SAL_ReferencesFree(&(pkey->references));
    if (pkey->method != NULL) {
        if (pkey->method->freeCtx != NULL) {
            pkey->method->freeCtx(pkey->key);
        }
    }
    EAL_EventReport(CRYPT_EVENT_ZERO, CRYPT_ALGO_PKEY, pkey->id, CRYPT_SUCCESS);
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
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return ret;
    }

    if (pkey->method == NULL || pkey->method->newPara == NULL ||
        pkey->method->setPara == NULL || pkey->method->freePara == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    void *pkeyPara = pkey->method->newPara(&(para->para.dsaPara));
    if (pkeyPara == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ERR_NEW_PARA_FAIL);
        return CRYPT_EAL_ERR_NEW_PARA_FAIL;
    }
    ret = pkey->method->setPara(pkey->key, pkeyPara);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    pkey->method->freePara(pkeyPara);
    return ret;
}

int32_t CRYPT_EAL_PkeyGetPara(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPara *para)
{
    int32_t ret;
    ret = ParaIsVaild(pkey, para);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return ret;
    }

    if (pkey->method == NULL || pkey->method->getPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    ret = pkey->method->getPara(pkey->key, &(para->para.dsaPara));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeySetParaById(CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_ParaId id)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method == NULL || pkey->method->newParaById == NULL ||
        pkey->method->setPara == NULL || pkey->method->freePara == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    void *pkeyPara = pkey->method->newParaById(id);
    if (pkeyPara == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ERR_NEW_PARA_FAIL);
        return CRYPT_EAL_ERR_NEW_PARA_FAIL;
    }
    int32_t ret = pkey->method->setPara(pkey->key, pkeyPara);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    pkey->method->freePara(pkeyPara);
    return ret;
}

int32_t CRYPT_EAL_PkeyGen(CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t ret;
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method == NULL || pkey->method->gen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    // If it's the ED25519 algorithm, hash method needs to be registered.
    if (pkey->id == CRYPT_PKEY_ED25519) {
        const EAL_MdMethod *mdMethod = EAL_MdFindMethod(CRYPT_MD_SHA512);
        if (pkey->method->ctrl == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
            return CRYPT_EAL_ALG_NOT_SUPPORT;
        }
        ret = pkey->method->ctrl(pkey->key, CRYPT_CTRL_SET_ED25519_HASH_METHOD, (EAL_MdMethod *)(uintptr_t)mdMethod,
            sizeof(EAL_MdMethod));
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
            return ret;
        }
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
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    // false indicates the public key path, and true indicates the private key path
    if (isPriKey == false) {
        CRYPT_EAL_PkeyPub *keyParam = (CRYPT_EAL_PkeyPub *)(uintptr_t)key;
        if (keyParam->id != pkey->id) {
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
            return CRYPT_EAL_ERR_ALGID;
        }
    } else {
        CRYPT_EAL_PkeyPrv *keyParam = (CRYPT_EAL_PkeyPrv *)(uintptr_t)key;
        if (keyParam->id != pkey->id) {
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
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
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    ret = pkey->method->setPub(pkey->key, &(key->key.rsaPub));
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
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    ret = pkey->method->setPrv(pkey->key, &(key->key.rsaPrv));
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
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    ret = pkey->method->getPub(pkey->key, &(key->key.rsaPub));
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
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    ret = pkey->method->getPrv(pkey->key, &(key->key.rsaPrv));
    EAL_EventReport((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_GETSSP : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

uint32_t CRYPT_EAL_PkeyGetSignLen(const CRYPT_EAL_PkeyCtx *pkey)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return 0;
    }
    if (pkey->method == NULL || pkey->method->signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return 0;
    }
    return pkey->method->signLen(pkey->key);
}

uint32_t CRYPT_EAL_PkeyGetKeyLen(const CRYPT_EAL_PkeyCtx *pkey)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return 0;
    }
    if (pkey->method == NULL || pkey->method->bits == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return 0;
    }
    uint32_t keyBytes = (pkey->method->bits(pkey->key) + 7) >> 3; // bytes = (bits + 7) >> 3
    return keyBytes;
}

static int32_t MdIdCheckSha1Sha2(CRYPT_MD_AlgId id)
{
    if (id < CRYPT_MD_MD5 || id > CRYPT_MD_SHA512) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    return CRYPT_SUCCESS;
}

uint32_t CRYPT_EAL_PkeyGetKeyBits(const CRYPT_EAL_PkeyCtx *pkey)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return 0;
    }
    if (pkey->method == NULL || pkey->method->bits == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return 0;
    }
    return pkey->method->bits(pkey->key);
}

uint32_t CRYPT_EAL_PkeyGetSecurityBits(const CRYPT_EAL_PkeyCtx *pkey)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return 0;
    }
    if (pkey->method == NULL || pkey->method->getSecBits == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return 0;
    }
    
    return (uint32_t) pkey->method->getSecBits(pkey->key);
}

static int32_t SetOaep(CRYPT_EAL_PkeyCtx *pkey, const void *val, uint32_t len)
{
    RSA_PadingPara padPara;
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const CRYPT_RSA_OaepPara *opad = val;
    if (len != sizeof(CRYPT_RSA_OaepPara)) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_PKEY_CTRL_ERROR);
        return CRYPT_EAL_PKEY_CTRL_ERROR;
    }
    int32_t ret = MdIdCheckSha1Sha2(opad->mdId);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = MdIdCheckSha1Sha2(opad->mgfId);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    padPara.mdId = opad->mdId;
    padPara.mgfId = opad->mgfId;
    padPara.mdMeth = EAL_MdFindMethod(opad->mdId);
    padPara.mgfMeth = EAL_MdFindMethod(opad->mgfId);
    if (padPara.mdMeth == NULL || padPara.mgfMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    return pkey->method->ctrl(pkey->key, CRYPT_CTRL_SET_RSA_RSAES_OAEP, &padPara,
        sizeof(RSA_PadingPara));
}

static int32_t SetPss(CRYPT_EAL_PkeyCtx *pkey, void *val, uint32_t len)
{
    RSA_PadingPara padPara;
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_RSA_PssPara *pad = val;
    if (len != sizeof(CRYPT_RSA_PssPara)) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_PKEY_CTRL_ERROR);
        return CRYPT_EAL_PKEY_CTRL_ERROR;
    }
    int32_t ret = MdIdCheckSha1Sha2(pad->mdId);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = MdIdCheckSha1Sha2(pad->mgfId);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    padPara.saltLen = pad->saltLen;
    padPara.mdId = pad->mdId;
    padPara.mgfId = pad->mgfId;
    padPara.mdMeth = EAL_MdFindMethod(pad->mdId);
    padPara.mgfMeth = EAL_MdFindMethod(pad->mgfId);
    if (padPara.mdMeth == NULL || padPara.mgfMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    return pkey->method->ctrl(pkey->key, CRYPT_CTRL_SET_RSA_EMSA_PSS, &padPara,
        sizeof(RSA_PadingPara));
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
    if (opt == CRYPT_CTRL_SET_ED25519_HASH_METHOD || opt == CRYPT_CTRL_SET_SM9_HASH_METHOD
        || opt == CRYPT_CTRL_SET_SM2_HASH_METHOD) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret;
    switch (opt) {
        case CRYPT_CTRL_SET_RSA_EMSA_PSS:
            ret = SetPss(pkey, val, len);
            break;
        case CRYPT_CTRL_SET_RSA_RSAES_OAEP:
            ret = SetOaep(pkey, val, len);
            break;
        default:
            ret = pkey->method->ctrl(pkey->key, opt, val, len);
            break;
    }
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
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
    if (pkey == NULL) {
        return CRYPT_PKEY_PARAID_MAX;
    }
    if (pkey->method == NULL || pkey->method->getParaId == NULL) {
        return CRYPT_PKEY_PARAID_MAX;
    }
    return pkey->method->getParaId(pkey->key);
}

int32_t CRYPT_EAL_PkeyCheck(const CRYPT_EAL_PkeyCtx *pkey)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pkey->method == NULL || pkey->method->check == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    return pkey->method->check(pkey->key);
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
    if (a->method->id != b->method->id) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_EAL_PKEY_CMP_DIFF_KEY_TYPE);
        return CRYPT_EAL_PKEY_CMP_DIFF_KEY_TYPE;
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
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
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
#endif
