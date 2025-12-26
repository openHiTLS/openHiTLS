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
#include "crypt_eal_implprovider.h"
#include "crypt_ealinit.h"
#include "bsl_err_internal.h"
#include "crypt_provider.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "eal_pkey.h"

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
    dest->check = method->check;
    dest->cmp = method->cmp;
    dest->encaps = method->encaps;
    dest->decaps = method->decaps;
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
    if (from->method == NULL || from->method->dupCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, from->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    EAL_PkeyUnitaryMethod *temp = to->method;
    (void)memcpy_s(to, sizeof(CRYPT_EAL_PkeyCtx), from, sizeof(CRYPT_EAL_PkeyCtx));
    (void)memset_s(&(to->references), sizeof(BSL_SAL_RefCount), 0, sizeof(BSL_SAL_RefCount));
    to->key = from->method->dupCtx(from->key);
    if (to->key == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, from->id, CRYPT_EAL_PKEY_DUP_ERROR);
        return CRYPT_EAL_PKEY_DUP_ERROR;
    }
    if (temp == NULL) {
        temp = BSL_SAL_Calloc(1, sizeof(EAL_PkeyUnitaryMethod));
        if (temp == NULL) {
            from->method->freeCtx(to->key);
            to->key = NULL;
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, from->id, CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
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
    EAL_EventReport(CRYPT_EVENT_ZERO, CRYPT_ALGO_PKEY, pkey->id, CRYPT_SUCCESS);
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

static int32_t SetDsaParams(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_DsaPara *dsaPara)
{
    BSL_Param param[4] = {
        {CRYPT_PARAM_DSA_P, BSL_PARAM_TYPE_OCTETS, dsaPara->p, dsaPara->pLen, 0},
        {CRYPT_PARAM_DSA_Q, BSL_PARAM_TYPE_OCTETS, dsaPara->q, dsaPara->qLen, 0},
        {CRYPT_PARAM_DSA_G, BSL_PARAM_TYPE_OCTETS, dsaPara->g, dsaPara->gLen, 0},
        BSL_PARAM_END
    };
    return pkey->method->setPara(pkey->key, param);
}

static int32_t SetRsaParams(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_RsaPara *rsaPara)
{
    uint32_t bits = rsaPara->bits;
    BSL_Param param[3] = {
        {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, rsaPara->e, rsaPara->eLen, 0},
        {CRYPT_PARAM_RSA_BITS, BSL_PARAM_TYPE_UINT32, &bits, sizeof(bits), 0},
        BSL_PARAM_END
    };
    return pkey->method->setPara(pkey->key, param);
}

static int32_t SetDhParams(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_DhPara *dhPara)
{
    BSL_Param param[4] = {
        {CRYPT_PARAM_DH_P, BSL_PARAM_TYPE_OCTETS, dhPara->p, dhPara->pLen, 0},
        {CRYPT_PARAM_DH_Q, BSL_PARAM_TYPE_OCTETS, dhPara->q, dhPara->qLen, 0},
        {CRYPT_PARAM_DH_G, BSL_PARAM_TYPE_OCTETS, dhPara->g, dhPara->gLen, 0},
        BSL_PARAM_END
    };
    return pkey->method->setPara(pkey->key, param);
}

static int32_t SetEccParams(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EccPara *eccPara)
{
    BSL_Param param[8] = {
        {CRYPT_PARAM_EC_P, BSL_PARAM_TYPE_OCTETS, eccPara->p, eccPara->pLen, 0},
        {CRYPT_PARAM_EC_A, BSL_PARAM_TYPE_OCTETS, eccPara->a, eccPara->aLen, 0},
        {CRYPT_PARAM_EC_B, BSL_PARAM_TYPE_OCTETS, eccPara->b, eccPara->bLen, 0},
        {CRYPT_PARAM_EC_N, BSL_PARAM_TYPE_OCTETS, eccPara->n, eccPara->nLen, 0},
        {CRYPT_PARAM_EC_H, BSL_PARAM_TYPE_OCTETS, eccPara->h, eccPara->hLen, 0},
        {CRYPT_PARAM_EC_X, BSL_PARAM_TYPE_OCTETS, eccPara->x, eccPara->xLen, 0},
        {CRYPT_PARAM_EC_Y, BSL_PARAM_TYPE_OCTETS, eccPara->y, eccPara->yLen, 0},
        BSL_PARAM_END
    };
    return pkey->method->setPara(pkey->key, param);
}

static int32_t SetPaillierParams(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_PaillierPara *paillierPara)
{
    uint32_t bits = paillierPara->bits;
    BSL_Param param[4] = {
        {CRYPT_PARAM_PAILLIER_P, BSL_PARAM_TYPE_OCTETS, paillierPara->p, paillierPara->pLen, 0},
        {CRYPT_PARAM_PAILLIER_Q, BSL_PARAM_TYPE_OCTETS, paillierPara->q, paillierPara->qLen, 0},
        {CRYPT_PARAM_PAILLIER_BITS, BSL_PARAM_TYPE_UINT32, &bits, sizeof(bits), 0},
        BSL_PARAM_END
    };
    return pkey->method->setPara(pkey->key, param);
}

static int32_t SetElGamalParams(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_ElGamalPara *elgamalPara)
{
    uint32_t bits = elgamalPara->bits;
    uint32_t k_bits = elgamalPara->k_bits;
    BSL_Param param[4] = {
        {CRYPT_PARAM_ELGAMAL_Q, BSL_PARAM_TYPE_OCTETS, elgamalPara->q, elgamalPara->qLen, 0},
        {CRYPT_PARAM_ELGAMAL_BITS, BSL_PARAM_TYPE_UINT32, &bits, sizeof(bits), 0},
        {CRYPT_PARAM_ELGAMAL_KBITS, BSL_PARAM_TYPE_UINT32, &k_bits, sizeof(k_bits), 0},
        BSL_PARAM_END
    };
    return pkey->method->setPara(pkey->key, param);
}

static int32_t GetDsaParams(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_DsaPara *dsaPara)
{
    BSL_Param param[4] = {
        {CRYPT_PARAM_DSA_P, BSL_PARAM_TYPE_OCTETS, dsaPara->p, dsaPara->pLen, 0},
        {CRYPT_PARAM_DSA_Q, BSL_PARAM_TYPE_OCTETS, dsaPara->q, dsaPara->qLen, 0},
        {CRYPT_PARAM_DSA_G, BSL_PARAM_TYPE_OCTETS, dsaPara->g, dsaPara->gLen, 0},
        BSL_PARAM_END
    };
    int32_t ret = pkey->method->getPara(pkey->key, param);
    if (ret == CRYPT_SUCCESS) {
        dsaPara->pLen = param[0].useLen;
        dsaPara->qLen = param[1].useLen;
        dsaPara->gLen = param[2].useLen;
    }
    return ret;
}

static int32_t GetDhParams(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_DhPara *dhPara)
{
    BSL_Param param[4] = {
        {CRYPT_PARAM_DH_P, BSL_PARAM_TYPE_OCTETS, dhPara->p, dhPara->pLen, 0},
        {CRYPT_PARAM_DH_Q, BSL_PARAM_TYPE_OCTETS, dhPara->q, dhPara->qLen, 0},
        {CRYPT_PARAM_DH_G, BSL_PARAM_TYPE_OCTETS, dhPara->g, dhPara->gLen, 0},
        BSL_PARAM_END
    };
    int32_t ret = pkey->method->getPara(pkey->key, param);
    if (ret == CRYPT_SUCCESS) {
        dhPara->pLen = param[0].useLen;
        dhPara->qLen = param[1].useLen;
        dhPara->gLen = param[2].useLen;
    }
    return ret;
}

static int32_t GetEccParams(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EccPara *eccPara)
{
    BSL_Param param[8] = {
        {CRYPT_PARAM_EC_P, BSL_PARAM_TYPE_OCTETS, eccPara->p, eccPara->pLen, 0},
        {CRYPT_PARAM_EC_A, BSL_PARAM_TYPE_OCTETS, eccPara->a, eccPara->aLen, 0},
        {CRYPT_PARAM_EC_B, BSL_PARAM_TYPE_OCTETS, eccPara->b, eccPara->bLen, 0},
        {CRYPT_PARAM_EC_N, BSL_PARAM_TYPE_OCTETS, eccPara->n, eccPara->nLen, 0},
        {CRYPT_PARAM_EC_H, BSL_PARAM_TYPE_OCTETS, eccPara->h, eccPara->hLen, 0},
        {CRYPT_PARAM_EC_X, BSL_PARAM_TYPE_OCTETS, eccPara->x, eccPara->xLen, 0},
        {CRYPT_PARAM_EC_Y, BSL_PARAM_TYPE_OCTETS, eccPara->y, eccPara->yLen, 0},
        BSL_PARAM_END
    };
    int32_t ret = pkey->method->getPara(pkey->key, param);
    if (ret == CRYPT_SUCCESS) {
        eccPara->pLen = param[0].useLen;
        eccPara->aLen = param[1].useLen;
        eccPara->bLen = param[2].useLen;
        eccPara->nLen = param[3].useLen;
        eccPara->hLen = param[4].useLen;
        eccPara->xLen = param[5].useLen;
        eccPara->yLen = param[6].useLen;
    }
    return ret;
}

static int32_t CvtBslParamAndSetParams(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPara *para)
{
    int32_t ret = CRYPT_NOT_SUPPORT;
    switch (pkey->id) {
        case CRYPT_PKEY_DSA:
            ret = SetDsaParams(pkey, &para->para.dsaPara);
            break;
        case CRYPT_PKEY_RSA:
            ret = SetRsaParams(pkey, &para->para.rsaPara);
            break;
        case CRYPT_PKEY_DH:
            ret = SetDhParams(pkey, &para->para.dhPara);
            break;
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_ECDH:
            ret =  SetEccParams(pkey, &para->para.eccPara);
            break;
        case CRYPT_PKEY_PAILLIER:
            ret = SetPaillierParams(pkey, &para->para.paillierPara);
            break;
         case CRYPT_PKEY_ELGAMAL:
            ret = SetElGamalParams(pkey, &para->para.elgamalPara);
            break;
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519:
        case CRYPT_PKEY_SM2:
        default:
            return CRYPT_NOT_SUPPORT;
    }
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

static int32_t CvtBslParamAndGetParams(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPara *para)
{
    int32_t ret = CRYPT_NOT_SUPPORT;
    switch (pkey->id) {
        case CRYPT_PKEY_DSA:
            ret =  GetDsaParams(pkey, &para->para.dsaPara);
            break;
        case CRYPT_PKEY_DH:
            ret =  GetDhParams(pkey, &para->para.dhPara);
            break;
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_ECDH:
            ret =  GetEccParams(pkey, &para->para.eccPara);
            break;
        case CRYPT_PKEY_PAILLIER:
        case CRYPT_PKEY_ELGAMAL:
        case CRYPT_PKEY_RSA:
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519:
        case CRYPT_PKEY_SM2:
        default:
            return CRYPT_NOT_SUPPORT;
    }
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
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
    ret = CvtBslParamAndSetParams(pkey, para);
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
    ret = CvtBslParamAndGetParams(pkey, para);
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

    switch (key->id) {
        case CRYPT_PKEY_RSA: {
            BSL_Param rsa[3] = {{CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, key->key.rsaPub.e, key->key.rsaPub.eLen, 0},
                {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, key->key.rsaPub.n, key->key.rsaPub.nLen, 0}, BSL_PARAM_END};
            ret = pkey->method->setPub(pkey->key, &rsa);
            break;
        }
        case CRYPT_PKEY_DSA: {
            BSL_Param dsa[2] = {{CRYPT_PARAM_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.dsaPub.data,
                key->key.dsaPub.len, 0}, BSL_PARAM_END};
            ret = pkey->method->setPub(pkey->key, &dsa);
            break;
        }
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519: {
            BSL_Param para[2] = {{CRYPT_PARAM_CURVE25519_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.curve25519Pub.data,
                key->key.curve25519Pub.len, 0}, BSL_PARAM_END};
            ret = pkey->method->setPub(pkey->key, &para);
            break;
        }
        case CRYPT_PKEY_DH: {
            BSL_Param dhParam[2] = {{CRYPT_PARAM_DH_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.dhPub.data,
                key->key.dhPub.len, 0}, BSL_PARAM_END};
            ret = pkey->method->setPub(pkey->key, &dhParam);
            break;
        }
        case CRYPT_PKEY_ECDH:
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_SM2: {
            BSL_Param ecParam[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.eccPub.data,
                key->key.eccPub.len, 0}, BSL_PARAM_END};
            ret = pkey->method->setPub(pkey->key, &ecParam);
            break;
        }
        case CRYPT_PKEY_PAILLIER: {
            BSL_Param paParam[4] = {{CRYPT_PARAM_PAILLIER_N, BSL_PARAM_TYPE_OCTETS, key->key.paillierPub.n,
                key->key.paillierPub.nLen, 0},
                {CRYPT_PARAM_PAILLIER_G, BSL_PARAM_TYPE_OCTETS, key->key.paillierPub.g, key->key.paillierPub.gLen, 0},
                {CRYPT_PARAM_PAILLIER_N2, BSL_PARAM_TYPE_OCTETS, key->key.paillierPub.n2, key->key.paillierPub.n2Len,
                    0},
                 BSL_PARAM_END};
            ret = pkey->method->setPub(pkey->key, &paParam);
            break;
        }
        case CRYPT_PKEY_ML_KEM: {
            BSL_Param paParam[2] = {{CRYPT_PARAM_ML_KEM_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.kemEk.data,
                key->key.kemEk.len, 0},
                BSL_PARAM_END};
            ret = pkey->method->setPub(pkey->key, &paParam);
            break;
        }
        case CRYPT_PKEY_ML_DSA: {
            BSL_Param paParam[2] = {{CRYPT_PARAM_ML_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.mldsaPub.data,
                key->key.mldsaPub.len, 0},
                BSL_PARAM_END};
            ret = pkey->method->setPub(pkey->key, &paParam);
            break;
        }
        case CRYPT_PKEY_ELGAMAL: {
            BSL_Param paParam[5] = {{CRYPT_PARAM_ELGAMAL_P, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPub.p,
                key->key.elgamalPub.pLen, 0},
                {CRYPT_PARAM_ELGAMAL_G, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPub.g, key->key.elgamalPub.gLen, 0},
                {CRYPT_PARAM_ELGAMAL_Y, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPub.y, key->key.elgamalPub.pLen,
                    0},
                {CRYPT_PARAM_ELGAMAL_Q, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPub.q, key->key.elgamalPub.qLen,
                0},
                 BSL_PARAM_END};
            ret = pkey->method->setPub(pkey->key, &paParam);
            break;
        }
        case CRYPT_PKEY_SLH_DSA: {
            BSL_Param slhDsaPub[3] = {{CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, key->key.slhDsaPub.seed,
                key->key.slhDsaPub.len, 0},
                {CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, key->key.slhDsaPub.root, key->key.slhDsaPub.len,
                    0},
                BSL_PARAM_END};
            ret = pkey->method->setPub(pkey->key, &slhDsaPub);
            break;
        }
		case CRYPT_PKEY_HYBRID_KEM: {
            BSL_Param paParam[2] = {{CRYPT_PARAM_HYBRID_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.kemEk.data,
                key->key.kemEk.len, 0},
                BSL_PARAM_END};
            ret = pkey->method->setPub(pkey->key, &paParam);
            break;
        }
        default:
            ret = CRYPT_EAL_ALG_NOT_SUPPORT;
    }

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
    switch(key->id) {
        case CRYPT_PKEY_RSA: {
            BSL_Param rsaParam[] = {{CRYPT_PARAM_RSA_D, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.d,
                    key->key.rsaPrv.dLen, 0},
                {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.n, key->key.rsaPrv.nLen, 0},
                {CRYPT_PARAM_RSA_P, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.p, key->key.rsaPrv.pLen, 0},
                {CRYPT_PARAM_RSA_Q, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.q, key->key.rsaPrv.qLen, 0},
                {CRYPT_PARAM_RSA_DP, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.dP, key->key.rsaPrv.dPLen, 0},
                {CRYPT_PARAM_RSA_DQ, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.dQ, key->key.rsaPrv.dQLen, 0},
                {CRYPT_PARAM_RSA_QINV, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.qInv, key->key.rsaPrv.qInvLen, 0},
                {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.e, key->key.rsaPrv.eLen, 0},
                BSL_PARAM_END};
            ret = pkey->method->setPrv(pkey->key, &rsaParam);
            break;
        }
        case CRYPT_PKEY_DSA: {
            BSL_Param dsaParam[2] = {{CRYPT_PARAM_DSA_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.dsaPrv.data,
                key->key.dsaPrv.len, 0}, BSL_PARAM_END};
            ret = pkey->method->setPrv(pkey->key, &dsaParam);
            break;
        }
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519: {
            BSL_Param para[2] = {{CRYPT_PARAM_CURVE25519_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.curve25519Prv.data,
                key->key.curve25519Prv.len, 0}, BSL_PARAM_END};
            ret = pkey->method->setPrv(pkey->key, &para);
            break;
        }
        case CRYPT_PKEY_DH: {
            BSL_Param dhParam[2] = {{CRYPT_PARAM_DH_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.dhPrv.data,
                key->key.dhPrv.len, 0}, BSL_PARAM_END};
            ret = pkey->method->setPrv(pkey->key, &dhParam);
            break;
        }
        case CRYPT_PKEY_ECDH:
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_SM2: {
            BSL_Param ecParam[2] = {{CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.eccPrv.data,
                key->key.eccPrv.len, 0}, BSL_PARAM_END};
            ret = pkey->method->setPrv(pkey->key, &ecParam);
            break;
        }
        case CRYPT_PKEY_PAILLIER: {
            BSL_Param paParam[5] = {{CRYPT_PARAM_PAILLIER_N, BSL_PARAM_TYPE_OCTETS, key->key.paillierPrv.n,
                    key->key.paillierPrv.nLen, 0},
                {CRYPT_PARAM_PAILLIER_LAMBDA, BSL_PARAM_TYPE_OCTETS, key->key.paillierPrv.lambda,
                    key->key.paillierPrv.lambdaLen, 0},
                {CRYPT_PARAM_PAILLIER_MU, BSL_PARAM_TYPE_OCTETS, key->key.paillierPrv.mu, key->key.paillierPrv.muLen,
                    0},
                {CRYPT_PARAM_PAILLIER_N2, BSL_PARAM_TYPE_OCTETS, key->key.paillierPrv.n2, key->key.paillierPrv.n2Len,
                    0},
                 BSL_PARAM_END};
            ret = pkey->method->setPrv(pkey->key, &paParam);
            break;
        }   
        case CRYPT_PKEY_SLH_DSA: {
            BSL_Param slhDsaParam[5] = {{CRYPT_PARAM_SLH_DSA_PRV_SEED, BSL_PARAM_TYPE_OCTETS, key->key.slhDsaPrv.seed,
                key->key.slhDsaPrv.pub.len, 0},
                {CRYPT_PARAM_SLH_DSA_PRV_PRF, BSL_PARAM_TYPE_OCTETS, key->key.slhDsaPrv.prf, key->key.slhDsaPrv.pub.len,
                    0},
                {CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, key->key.slhDsaPrv.pub.seed, key->key.slhDsaPrv.pub.len,
                    0},
                {CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, key->key.slhDsaPrv.pub.root, key->key.slhDsaPrv.pub.len,
                    0},
                BSL_PARAM_END};
            ret = pkey->method->setPrv(pkey->key, &slhDsaParam);
            break;
        }
        case CRYPT_PKEY_ELGAMAL: {
            BSL_Param paParam[4] = {
                {CRYPT_PARAM_ELGAMAL_P, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPrv.p, key->key.elgamalPrv.pLen, 0},
                {CRYPT_PARAM_ELGAMAL_G, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPrv.g, key->key.elgamalPrv.gLen, 0},
                {CRYPT_PARAM_ELGAMAL_X, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPrv.x, key->key.elgamalPrv.xLen, 0},
                BSL_PARAM_END};
            ret = pkey->method->setPrv(pkey->key, &paParam);
            break;
        }
		case CRYPT_PKEY_ML_KEM: {
            BSL_Param paParam[2] = {{CRYPT_PARAM_ML_KEM_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.kemDk.data,
                key->key.kemDk.len, 0},
                BSL_PARAM_END};
            ret = pkey->method->setPrv(pkey->key, &paParam);
            break;
        }
        case CRYPT_PKEY_ML_DSA: {
            BSL_Param paParam[2] = {{CRYPT_PARAM_ML_DSA_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.mldsaPrv.data,
                key->key.mldsaPrv.len, 0},
                BSL_PARAM_END};
            ret = pkey->method->setPrv(pkey->key, &paParam);
            break;
        }
        case CRYPT_PKEY_HYBRID_KEM: {
            BSL_Param paParam[2] = {{CRYPT_PARAM_HYBRID_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.kemDk.data,
                key->key.kemDk.len, 0},
                BSL_PARAM_END};
            ret = pkey->method->setPrv(pkey->key, &paParam);
            break;
        }
        default:
            ret = CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    EAL_EventReport((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_SETSSP : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

static int32_t GetRSAPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_RsaPub *pub)
{
    BSL_Param param[3] = {{CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, pub->e, pub->eLen, 0},
        {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, pub->n, pub->nLen, 0}, BSL_PARAM_END};
    int32_t ret = pkey->method->getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pub->eLen = param[0].useLen;
    pub->nLen = param[1].useLen;
    return CRYPT_SUCCESS;
}

static int32_t GetCommonPub(const CRYPT_EAL_PkeyCtx *pkey, int32_t paramKey, CRYPT_Data *pub)
{
    BSL_Param param[2] = {{paramKey, BSL_PARAM_TYPE_OCTETS, pub->data, pub->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pub->len = param[0].useLen;
    return CRYPT_SUCCESS;
}

static int32_t GetPaillierPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_PaillierPub *pub)
{
     BSL_Param param[4] = {{CRYPT_PARAM_PAILLIER_N, BSL_PARAM_TYPE_OCTETS, pub->n, pub->nLen, 0},
        {CRYPT_PARAM_PAILLIER_G, BSL_PARAM_TYPE_OCTETS, pub->g, pub->gLen, 0},
        {CRYPT_PARAM_PAILLIER_N2, BSL_PARAM_TYPE_OCTETS, pub->n2, pub->n2Len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pub->nLen = param[0].useLen;
    pub->gLen = param[1].useLen;
    pub->n2Len = param[2].useLen;
    return CRYPT_SUCCESS;
}

static int32_t GetElGamalPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_ElGamalPub *pub)
{
     BSL_Param param[5] = {{CRYPT_PARAM_ELGAMAL_P, BSL_PARAM_TYPE_OCTETS, pub->p, pub->pLen, 0},
        {CRYPT_PARAM_ELGAMAL_G, BSL_PARAM_TYPE_OCTETS, pub->g, pub->gLen, 0},
        {CRYPT_PARAM_ELGAMAL_Y, BSL_PARAM_TYPE_OCTETS, pub->y, pub->yLen, 0},
        {CRYPT_PARAM_ELGAMAL_Q, BSL_PARAM_TYPE_OCTETS, pub->q, pub->qLen, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pub->pLen = param[0].useLen;
    pub->gLen = param[1].useLen;
    pub->yLen = param[2].useLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_PkeyGetPubEx(const CRYPT_EAL_PkeyCtx *pkey, BSL_Param *param)
{
    if (pkey == NULL || param == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pkey->method == NULL || pkey->method->getPub == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = pkey->method->getPub(pkey->key, param);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeySetPubEx(CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *param)
{
    if (pkey == NULL || param == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pkey->method == NULL || pkey->method->setPub == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = pkey->method->setPub(pkey->key, param);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeyGetPrvEx(const CRYPT_EAL_PkeyCtx *pkey, BSL_Param *param)
{
    if (pkey == NULL || param == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pkey->method == NULL || pkey->method->getPrv == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = pkey->method->getPrv(pkey->key, param);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeySetPrvEx(CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *param)
{
    if (pkey == NULL || param == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pkey->method == NULL || pkey->method->setPrv == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = pkey->method->setPrv(pkey->key, param);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

static int32_t GetMlkemPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_KemEncapsKey *kemEk)
{
    BSL_Param param[2] = {{CRYPT_PARAM_ML_KEM_PUBKEY, BSL_PARAM_TYPE_OCTETS, kemEk->data,
        kemEk->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    kemEk->len = param[0].useLen;
    return CRYPT_SUCCESS;
}

static int32_t GetMldsaPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MlDsaPub *dsaPub)
{
    BSL_Param param[2] = {{CRYPT_PARAM_ML_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, dsaPub->data,
        dsaPub->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    dsaPub->len = param[0].useLen;
    return CRYPT_SUCCESS;
}

static int32_t GetHybridkemPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_KemEncapsKey *kemEk)
{
    BSL_Param param[2] = {{CRYPT_PARAM_HYBRID_PUBKEY, BSL_PARAM_TYPE_OCTETS, kemEk->data,
        kemEk->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    kemEk->len = param[0].useLen;
    return CRYPT_SUCCESS;
}


static int32_t GetSlhDsaPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_SlhDsaPub *pub)
{
    BSL_Param param[3] = {{CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, pub->seed, pub->len, 0},
        {CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, pub->root, pub->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pub->len = param[0].useLen;
    return CRYPT_SUCCESS;
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

    switch (key->id) {
        case CRYPT_PKEY_RSA:
            ret = GetRSAPub(pkey, &key->key.rsaPub);
            break;
        case CRYPT_PKEY_DSA:
            ret = GetCommonPub(pkey, CRYPT_PARAM_DSA_PUBKEY, &key->key.dsaPub);
            break;
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519:
            ret = GetCommonPub(pkey, CRYPT_PARAM_CURVE25519_PUBKEY, &key->key.curve25519Pub);
            break;
        case CRYPT_PKEY_DH:
            ret = GetCommonPub(pkey, CRYPT_PARAM_DH_PUBKEY, &key->key.dhPub);
            break;
        case CRYPT_PKEY_ECDH:
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_SM2:
            ret = GetCommonPub(pkey, CRYPT_PARAM_EC_PUBKEY, &key->key.eccPub);
            break;
        case CRYPT_PKEY_PAILLIER:
            ret = GetPaillierPub(pkey, &key->key.paillierPub);
            break;
        case CRYPT_PKEY_ELGAMAL:
            ret = GetElGamalPub(pkey, &key->key.elgamalPub);
            break;
		case CRYPT_PKEY_ML_KEM:
            ret = GetMlkemPub(pkey, &key->key.kemEk);
            break;
        case CRYPT_PKEY_ML_DSA: 
            ret = GetMldsaPub(pkey, &key->key.mldsaPub);
            break;
        case CRYPT_PKEY_HYBRID_KEM:
            ret = GetHybridkemPub(pkey, &key->key.kemEk);
            break;
        case CRYPT_PKEY_SLH_DSA:
            ret = GetSlhDsaPub(pkey, &key->key.slhDsaPub);
            break;
        default:
            ret = CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    EAL_EventReport((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_GETSSP : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

static int32_t GetRSAPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_RsaPrv *prv)
{
    BSL_Param param[] = {{CRYPT_PARAM_RSA_D, BSL_PARAM_TYPE_OCTETS, prv->d, prv->dLen, 0},
        {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, prv->n, prv->nLen, 0},
        {CRYPT_PARAM_RSA_P, BSL_PARAM_TYPE_OCTETS, prv->p, prv->pLen, 0},
        {CRYPT_PARAM_RSA_Q, BSL_PARAM_TYPE_OCTETS, prv->q, prv->qLen, 0},
        {CRYPT_PARAM_RSA_DP, BSL_PARAM_TYPE_OCTETS, prv->dP, prv->dPLen, 0},
        {CRYPT_PARAM_RSA_DQ, BSL_PARAM_TYPE_OCTETS, prv->dQ, prv->dQLen, 0},
        {CRYPT_PARAM_RSA_QINV, BSL_PARAM_TYPE_OCTETS, prv->qInv, prv->qInvLen, 0},
        {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, prv->e, prv->eLen, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    prv->dLen = param[0].useLen;
    prv->nLen = param[1].useLen;
    prv->pLen = param[2].useLen;
    prv->qLen = param[3].useLen;
    prv->dPLen = param[4].useLen;
    prv->dQLen = param[5].useLen;
    prv->qInvLen = param[6].useLen;
    prv->eLen = param[7].useLen;
    return CRYPT_SUCCESS;
}

static int32_t GetCommonPrv(const CRYPT_EAL_PkeyCtx *pkey, int32_t paramKey, CRYPT_Data *prv)
{
    BSL_Param param[2] = {{paramKey, BSL_PARAM_TYPE_OCTETS, prv->data, prv->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    prv->len = param[0].useLen;
    return CRYPT_SUCCESS;
}

static int32_t GetPaillierPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_PaillierPrv *prv)
{
    BSL_Param param[5] = {{CRYPT_PARAM_PAILLIER_N, BSL_PARAM_TYPE_OCTETS, prv->n, prv->nLen, 0},
        {CRYPT_PARAM_PAILLIER_LAMBDA, BSL_PARAM_TYPE_OCTETS, prv->lambda, prv->lambdaLen, 0},
        {CRYPT_PARAM_PAILLIER_MU, BSL_PARAM_TYPE_OCTETS, prv->mu, prv->muLen, 0},
        {CRYPT_PARAM_PAILLIER_N2, BSL_PARAM_TYPE_OCTETS, prv->n2, prv->n2Len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    prv->nLen = param[0].useLen;
    prv->lambdaLen = param[1].useLen;
    prv->muLen = param[2].useLen;
    prv->n2Len = param[3].useLen;
    return CRYPT_SUCCESS;
}

static int32_t GetElGamalPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_ElGamalPrv *prv)
{
    BSL_Param param[5] = {{CRYPT_PARAM_ELGAMAL_P, BSL_PARAM_TYPE_OCTETS, prv->p, prv->pLen, 0},
        {CRYPT_PARAM_ELGAMAL_G, BSL_PARAM_TYPE_OCTETS, prv->g, prv->gLen, 0},
        {CRYPT_PARAM_ELGAMAL_X, BSL_PARAM_TYPE_OCTETS, prv->x, prv->xLen, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    prv->pLen = param[0].useLen;
    prv->gLen = param[1].useLen;
    prv->xLen = param[2].useLen;
    return CRYPT_SUCCESS;
}

static int32_t GetMlkemPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_KemDecapsKey *kemDk)
{
    BSL_Param param[2] = {{CRYPT_PARAM_ML_KEM_PRVKEY, BSL_PARAM_TYPE_OCTETS, kemDk->data,
        kemDk->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    kemDk->len = param[0].useLen;
    return CRYPT_SUCCESS;
}

static int32_t GetMldsaPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MlDsaPrv *dsaPrv)
{
    BSL_Param param[2] = {{CRYPT_PARAM_ML_DSA_PRVKEY, BSL_PARAM_TYPE_OCTETS, dsaPrv->data,
        dsaPrv->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    dsaPrv->len = param[0].useLen;
    return CRYPT_SUCCESS;
}

static int32_t GetHybridkemPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_KemDecapsKey *kemDk)
{
    BSL_Param param[2] = {{CRYPT_PARAM_HYBRID_PRVKEY, BSL_PARAM_TYPE_OCTETS, kemDk->data,
        kemDk->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    kemDk->len = param[0].useLen;
    return CRYPT_SUCCESS;
}

static int32_t GetSlhDsaPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_SlhDsaPrv *prv)
{
    BSL_Param param[5] = {{CRYPT_PARAM_SLH_DSA_PRV_SEED, BSL_PARAM_TYPE_OCTETS, prv->seed, prv->pub.len, 0},
        {CRYPT_PARAM_SLH_DSA_PRV_PRF, BSL_PARAM_TYPE_OCTETS, prv->prf, prv->pub.len, 0},
        {CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, prv->pub.seed, prv->pub.len, 0},
        {CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, prv->pub.root, prv->pub.len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method->getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    prv->pub.len = param[0].useLen;
    return CRYPT_SUCCESS;
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
    switch(key->id) {
        case CRYPT_PKEY_RSA:
            ret = GetRSAPrv(pkey, &key->key.rsaPrv);
            break;
        case CRYPT_PKEY_DSA:
            ret = GetCommonPrv(pkey, CRYPT_PARAM_DSA_PRVKEY, &key->key.dsaPrv);
            break;
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519:
            ret = GetCommonPrv(pkey, CRYPT_PARAM_CURVE25519_PRVKEY, &key->key.curve25519Prv);
            break;
        case CRYPT_PKEY_DH:
            ret = GetCommonPrv(pkey, CRYPT_PARAM_DH_PRVKEY, &key->key.dhPrv);
            break;
        case CRYPT_PKEY_ECDH:
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_SM2:
            ret = GetCommonPrv(pkey, CRYPT_PARAM_EC_PRVKEY, &key->key.eccPrv);
            break;
        case CRYPT_PKEY_PAILLIER:
            ret = GetPaillierPrv(pkey, &key->key.paillierPrv);
            break;
        case CRYPT_PKEY_ELGAMAL:
            ret = GetElGamalPrv(pkey, &key->key.elgamalPrv);
            break;
		case CRYPT_PKEY_ML_KEM:
            ret = GetMlkemPrv(pkey, &key->key.kemDk);
            break;
        case CRYPT_PKEY_ML_DSA:
            ret = GetMldsaPrv(pkey, &key->key.mldsaPrv);
            break;
        case CRYPT_PKEY_SLH_DSA:
            ret = GetSlhDsaPrv(pkey, &key->key.slhDsaPrv);
            break;
		case CRYPT_PKEY_HYBRID_KEM:
            ret = GetHybridkemPrv(pkey, &key->key.kemDk);
            break;
        default:
            ret = CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    EAL_EventReport((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_GETSSP : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
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
                default:
                    BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                    return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
            }
        index++;
        }
    }
    return CRYPT_SUCCESS;
}

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
                    method->encaps = funcKem[index].func;
                    break;
                case CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE:
                    method->decaps = funcKem[index].func;
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

int32_t CRYPT_EAL_SetPkeyMethod(EAL_PkeyUnitaryMethod **pkeyMethod, const CRYPT_EAL_Func *funcsKeyMgmt,
    const CRYPT_EAL_Func *funcsAsyCipher, const CRYPT_EAL_Func *funcsExch, const CRYPT_EAL_Func *funcSign,
    const CRYPT_EAL_Func *funcKem)
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
    ret = CRYPT_EAL_SetKemMethod(funcKem, method);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(method);
        return ret;
    }
    *pkeyMethod = method;
    return CRYPT_SUCCESS;
}

static int32_t ProviderGetTargetFuncs(CRYPT_EAL_LibCtx *libCtx, int32_t operaId, int32_t algId,
    const char *attrName, const CRYPT_EAL_Func **funcs, CRYPT_EAL_ProvMgrCtx **mgrCtx)
{
    int32_t ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, operaId, algId, attrName, funcs, mgrCtx);
    return ret == CRYPT_NOT_SUPPORT ? CRYPT_SUCCESS : ret;
}

int32_t CRYPT_EAL_ProviderGetAsyAlgFuncs(CRYPT_EAL_LibCtx *libCtx, int32_t algId, uint32_t pkeyOperType,
    const char *attrName, CRYPT_EAL_AsyAlgFuncsInfo *funcs)
{
    int32_t ret = CRYPT_PROVIDER_NOT_SUPPORT;
    if (pkeyOperType == CRYPT_EAL_PKEY_UNKNOWN_OPERATE) {
        RETURN_RET_IF_ERR(ProviderGetTargetFuncs(libCtx, CRYPT_EAL_OPERAID_ASYMCIPHER, algId,
            attrName, &funcs->funcsAsyCipher, &funcs->mgrCtx), ret);
        RETURN_RET_IF_ERR(ProviderGetTargetFuncs(libCtx, CRYPT_EAL_OPERAID_KEYEXCH, algId,
            attrName, &funcs->funcsExch, &funcs->mgrCtx), ret);
        RETURN_RET_IF_ERR(ProviderGetTargetFuncs(libCtx, CRYPT_EAL_OPERAID_SIGN, algId,
            attrName, &funcs->funcSign, &funcs->mgrCtx), ret);
        RETURN_RET_IF_ERR(ProviderGetTargetFuncs(libCtx, CRYPT_EAL_OPERAID_KEM, algId,
            attrName, &funcs->funcKem, &funcs->mgrCtx), ret);
    }
    if ((pkeyOperType & CRYPT_EAL_PKEY_CIPHER_OPERATE) == CRYPT_EAL_PKEY_CIPHER_OPERATE) {
        ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, CRYPT_EAL_OPERAID_ASYMCIPHER, algId, attrName,
            &funcs->funcsAsyCipher, &funcs->mgrCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if ((pkeyOperType & CRYPT_EAL_PKEY_EXCH_OPERATE) == CRYPT_EAL_PKEY_EXCH_OPERATE) {
        ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, CRYPT_EAL_OPERAID_KEYEXCH, algId, attrName,
            &funcs->funcsExch, &funcs->mgrCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if ((pkeyOperType & CRYPT_EAL_PKEY_SIGN_OPERATE) == CRYPT_EAL_PKEY_SIGN_OPERATE) {
        ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, CRYPT_EAL_OPERAID_SIGN, algId, attrName,
            &funcs->funcSign, &funcs->mgrCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if ((pkeyOperType & CRYPT_EAL_PKEY_KEM_OPERATE) == CRYPT_EAL_PKEY_KEM_OPERATE) {
        ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, CRYPT_EAL_OPERAID_KEM, algId, attrName,
            &funcs->funcKem, &funcs->mgrCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, CRYPT_EAL_OPERAID_KEYMGMT, algId, attrName,
        &funcs->funcsKeyMgmt, &funcs->mgrCtx);
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
    ret = CRYPT_EAL_SetPkeyMethod(&(ctx->method), funcInfo.funcsKeyMgmt, funcInfo.funcsAsyCipher, funcInfo.funcsExch,
        funcInfo.funcSign, funcInfo.funcKem);
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
