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

#include <stdint.h>
#include "bsl_params.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "eal_pkey_local.h"
#include "crypt_params_key.h"
#include "crypt_eal_pkey.h"

#ifdef HITLS_CRYPTO_DSA
static int32_t SetDsaParams(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_DsaPara *dsaPara)
{
    BSL_Param param[4] = {
        {CRYPT_PARAM_DSA_P, BSL_PARAM_TYPE_OCTETS, dsaPara->p, dsaPara->pLen, 0},
        {CRYPT_PARAM_DSA_Q, BSL_PARAM_TYPE_OCTETS, dsaPara->q, dsaPara->qLen, 0},
        {CRYPT_PARAM_DSA_G, BSL_PARAM_TYPE_OCTETS, dsaPara->g, dsaPara->gLen, 0},
        BSL_PARAM_END
    };
    return pkey->method.setPara(pkey->key, param);
}
#endif

#ifdef HITLS_CRYPTO_RSA
static int32_t SetRsaParams(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_RsaPara *rsaPara)
{
    uint32_t bits = rsaPara->bits;
    BSL_Param param[] = {
        {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, rsaPara->e, rsaPara->eLen, 0},
        {CRYPT_PARAM_RSA_BITS, BSL_PARAM_TYPE_UINT32, &bits, sizeof(bits), 0},
        BSL_PARAM_END
    };
    return pkey->method.setPara(pkey->key, param);
}
#endif

#ifdef HITLS_CRYPTO_DH
static int32_t SetDhParams(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_DhPara *dhPara)
{
    BSL_Param param[4] = {
        {CRYPT_PARAM_DH_P, BSL_PARAM_TYPE_OCTETS, dhPara->p, dhPara->pLen, 0},
        {CRYPT_PARAM_DH_Q, BSL_PARAM_TYPE_OCTETS, dhPara->q, dhPara->qLen, 0},
        {CRYPT_PARAM_DH_G, BSL_PARAM_TYPE_OCTETS, dhPara->g, dhPara->gLen, 0},
        BSL_PARAM_END
    };
    return pkey->method.setPara(pkey->key, param);
}
#endif

#if defined HITLS_CRYPTO_ECDSA || defined HITLS_CRYPTO_ECDH
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
    return pkey->method.setPara(pkey->key, param);
}
#endif

#ifdef HITLS_CRYPTO_PAILLIER
static int32_t SetPaillierParams(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_PaillierPara *paillierPara)
{
    uint32_t bits = paillierPara->bits;
    BSL_Param param[4] = {
        {CRYPT_PARAM_PAILLIER_P, BSL_PARAM_TYPE_OCTETS, paillierPara->p, paillierPara->pLen, 0},
        {CRYPT_PARAM_PAILLIER_Q, BSL_PARAM_TYPE_OCTETS, paillierPara->q, paillierPara->qLen, 0},
        {CRYPT_PARAM_PAILLIER_BITS, BSL_PARAM_TYPE_UINT32, &bits, sizeof(bits), 0},
        BSL_PARAM_END
    };
    return pkey->method.setPara(pkey->key, param);
}
#endif

#ifdef HITLS_CRYPTO_ELGAMAL
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
    return pkey->method.setPara(pkey->key, param);
}
#endif

#ifdef HITLS_CRYPTO_DSA
static int32_t GetDsaParams(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_DsaPara *dsaPara)
{
    BSL_Param param[4] = {
        {CRYPT_PARAM_DSA_P, BSL_PARAM_TYPE_OCTETS, dsaPara->p, dsaPara->pLen, 0},
        {CRYPT_PARAM_DSA_Q, BSL_PARAM_TYPE_OCTETS, dsaPara->q, dsaPara->qLen, 0},
        {CRYPT_PARAM_DSA_G, BSL_PARAM_TYPE_OCTETS, dsaPara->g, dsaPara->gLen, 0},
        BSL_PARAM_END
    };
    int32_t ret = pkey->method.getPara(pkey->key, param);
    if (ret == CRYPT_SUCCESS) {
        dsaPara->pLen = param[0].useLen;
        dsaPara->qLen = param[1].useLen;
        dsaPara->gLen = param[2].useLen;
    }
    return ret;
}
#endif

#ifdef HITLS_CRYPTO_DH
static int32_t GetDhParams(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_DhPara *dhPara)
{
    BSL_Param param[4] = {
        {CRYPT_PARAM_DH_P, BSL_PARAM_TYPE_OCTETS, dhPara->p, dhPara->pLen, 0},
        {CRYPT_PARAM_DH_Q, BSL_PARAM_TYPE_OCTETS, dhPara->q, dhPara->qLen, 0},
        {CRYPT_PARAM_DH_G, BSL_PARAM_TYPE_OCTETS, dhPara->g, dhPara->gLen, 0},
        BSL_PARAM_END
    };
    int32_t ret = pkey->method.getPara(pkey->key, param);
    if (ret == CRYPT_SUCCESS) {
        dhPara->pLen = param[0].useLen;
        dhPara->qLen = param[1].useLen;
        dhPara->gLen = param[2].useLen;
    }
    return ret;
}
#endif

#if defined HITLS_CRYPTO_ECDSA || defined HITLS_CRYPTO_ECDH
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
    int32_t ret = pkey->method.getPara(pkey->key, param);
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
#endif

int32_t PkeyProviderSetPara(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPara *para)
{
    switch (pkey->id) {
#ifdef HITLS_CRYPTO_DSA
        case CRYPT_PKEY_DSA:
            return SetDsaParams(pkey, &para->para.dsaPara);
#endif
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA:
            return SetRsaParams(pkey, &para->para.rsaPara);
#endif
#ifdef HITLS_CRYPTO_DH
        case CRYPT_PKEY_DH:
            return SetDhParams(pkey, &para->para.dhPara);
#endif
#if defined HITLS_CRYPTO_ECDSA || defined HITLS_CRYPTO_ECDH
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_ECDH:
            return SetEccParams(pkey, &para->para.eccPara);
#endif
#ifdef HITLS_CRYPTO_PAILLIER
        case CRYPT_PKEY_PAILLIER:
            return SetPaillierParams(pkey, &para->para.paillierPara);
#endif
#ifdef HITLS_CRYPTO_ELGAMAL
        case CRYPT_PKEY_ELGAMAL:
            return SetElGamalParams(pkey, &para->para.elgamalPara);
#endif
        default:
            (void)pkey;
            (void)para;
            return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
}

int32_t PkeyProviderGetPara(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPara *para)
{
    switch (pkey->id) {
#ifdef HITLS_CRYPTO_DSA
        case CRYPT_PKEY_DSA:
            return GetDsaParams(pkey, &para->para.dsaPara);
#endif
#ifdef HITLS_CRYPTO_DH
        case CRYPT_PKEY_DH:
            return GetDhParams(pkey, &para->para.dhPara);
#endif
#if defined HITLS_CRYPTO_ECDSA || defined HITLS_CRYPTO_ECDH
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_ECDH:
            return GetEccParams(pkey, &para->para.eccPara);
#endif
        default:
            (void)pkey;
            (void)para;
            return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
}

int32_t PkeyProviderSetPrv(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPrv *key)
{
    switch (pkey->id) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA: {
            BSL_Param rsaParam[] = {
                {CRYPT_PARAM_RSA_D, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.d, key->key.rsaPrv.dLen, 0},
                {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.n, key->key.rsaPrv.nLen, 0},
                {CRYPT_PARAM_RSA_P, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.p, key->key.rsaPrv.pLen, 0},
                {CRYPT_PARAM_RSA_Q, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.q, key->key.rsaPrv.qLen, 0},
                {CRYPT_PARAM_RSA_DP, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.dP, key->key.rsaPrv.dPLen, 0},
                {CRYPT_PARAM_RSA_DQ, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.dQ, key->key.rsaPrv.dQLen, 0},
                {CRYPT_PARAM_RSA_QINV, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.qInv, key->key.rsaPrv.qInvLen, 0},
                {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, key->key.rsaPrv.e, key->key.rsaPrv.eLen, 0},
                BSL_PARAM_END};
            return pkey->method.setPrv(pkey->key, &rsaParam);
        }
#endif
#ifdef HITLS_CRYPTO_DSA
        case CRYPT_PKEY_DSA: {
            BSL_Param dsaParam[2] = {
                {CRYPT_PARAM_DSA_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.dsaPrv.data, key->key.dsaPrv.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPrv(pkey->key, &dsaParam);
        }
#endif
#if defined HITLS_CRYPTO_ED25519 || defined HITLS_CRYPTO_X25519
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519: {
            BSL_Param para[2] = {
                {CRYPT_PARAM_CURVE25519_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.curve25519Prv.data,
                    key->key.curve25519Prv.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPrv(pkey->key, &para);
        }
#endif
#ifdef HITLS_CRYPTO_DH
        case CRYPT_PKEY_DH: {
            BSL_Param dhParam[2] = {
                {CRYPT_PARAM_DH_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.dhPrv.data, key->key.dhPrv.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPrv(pkey->key, &dhParam);
        }
#endif
#if defined HITLS_CRYPTO_ECDSA || defined HITLS_CRYPTO_ECDH || defined HITLS_CRYPTO_SM2
        case CRYPT_PKEY_ECDH:
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_SM2: {
            BSL_Param ecParam[2] = {
                {CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.eccPrv.data, key->key.eccPrv.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPrv(pkey->key, &ecParam);
        }
#endif
#ifdef HITLS_CRYPTO_PAILLIER
        case CRYPT_PKEY_PAILLIER: {
            BSL_Param paParam[5] = {
                {CRYPT_PARAM_PAILLIER_N, BSL_PARAM_TYPE_OCTETS, key->key.paillierPrv.n, key->key.paillierPrv.nLen, 0},
                {CRYPT_PARAM_PAILLIER_LAMBDA, BSL_PARAM_TYPE_OCTETS, key->key.paillierPrv.lambda,
                    key->key.paillierPrv.lambdaLen, 0},
                {CRYPT_PARAM_PAILLIER_MU, BSL_PARAM_TYPE_OCTETS, key->key.paillierPrv.mu, key->key.paillierPrv.muLen,
                    0},
                {CRYPT_PARAM_PAILLIER_N2, BSL_PARAM_TYPE_OCTETS, key->key.paillierPrv.n2, key->key.paillierPrv.n2Len,
                    0},
                BSL_PARAM_END};
            return pkey->method.setPrv(pkey->key, &paParam);
        }
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
        case CRYPT_PKEY_SLH_DSA: {
            BSL_Param slhDsaParam[5] = {
                {CRYPT_PARAM_SLH_DSA_PRV_SEED, BSL_PARAM_TYPE_OCTETS, key->key.slhDsaPrv.seed,
                    key->key.slhDsaPrv.pub.len, 0},
                {CRYPT_PARAM_SLH_DSA_PRV_PRF, BSL_PARAM_TYPE_OCTETS, key->key.slhDsaPrv.prf, key->key.slhDsaPrv.pub.len,
                    0},
                {CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, key->key.slhDsaPrv.pub.seed,
                    key->key.slhDsaPrv.pub.len, 0},
                {CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, key->key.slhDsaPrv.pub.root,
                    key->key.slhDsaPrv.pub.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPrv(pkey->key, &slhDsaParam);
        }
#endif
#ifdef HITLS_CRYPTO_XMSS
        case CRYPT_PKEY_XMSS: {
            uint64_t index = key->key.xmssPrv.index;
            BSL_Param xmssParam[6] = {
                {CRYPT_PARAM_XMSS_PRV_SEED, BSL_PARAM_TYPE_OCTETS, key->key.xmssPrv.seed, key->key.xmssPrv.pub.len, 0},
                {CRYPT_PARAM_XMSS_PRV_PRF, BSL_PARAM_TYPE_OCTETS, key->key.xmssPrv.prf, key->key.xmssPrv.pub.len, 0},
                {CRYPT_PARAM_XMSS_PRV_INDEX, BSL_PARAM_TYPE_UINT64, &index, sizeof(index), 0},
                {CRYPT_PARAM_XMSS_PUB_SEED, BSL_PARAM_TYPE_OCTETS, key->key.xmssPrv.pub.seed, key->key.xmssPrv.pub.len,
                    0},
                {CRYPT_PARAM_XMSS_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, key->key.xmssPrv.pub.root, key->key.xmssPrv.pub.len,
                    0},
                BSL_PARAM_END,
            };
            return pkey->method.setPrv(pkey->key, &xmssParam);
        }
#endif
#ifdef HITLS_CRYPTO_ELGAMAL
        case CRYPT_PKEY_ELGAMAL: {
            BSL_Param paParam[4] = {
                {CRYPT_PARAM_ELGAMAL_P, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPrv.p, key->key.elgamalPrv.pLen, 0},
                {CRYPT_PARAM_ELGAMAL_G, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPrv.g, key->key.elgamalPrv.gLen, 0},
                {CRYPT_PARAM_ELGAMAL_X, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPrv.x, key->key.elgamalPrv.xLen, 0},
                BSL_PARAM_END};
            return pkey->method.setPrv(pkey->key, &paParam);
        }
#endif
#ifdef HITLS_CRYPTO_MLKEM
		case CRYPT_PKEY_ML_KEM: {
            BSL_Param paParam[2] = {
                {CRYPT_PARAM_ML_KEM_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.kemDk.data, key->key.kemDk.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPrv(pkey->key, &paParam);
        }
#endif
#ifdef HITLS_CRYPTO_MLDSA
        case CRYPT_PKEY_ML_DSA: {
            BSL_Param paParam[2] = {
                {CRYPT_PARAM_ML_DSA_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.mldsaPrv.data, key->key.mldsaPrv.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPrv(pkey->key, &paParam);
        }
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
        case CRYPT_PKEY_HYBRID_KEM: {
            BSL_Param paParam[2] = {
                {CRYPT_PARAM_HYBRID_PRVKEY, BSL_PARAM_TYPE_OCTETS, key->key.kemDk.data, key->key.kemDk.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPrv(pkey->key, &paParam);
        }
#endif
        default:
            (void)key;
            (void)pkey;
            return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
}

#ifdef HITLS_CRYPTO_RSA
static int32_t GetRSAPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_RsaPrv *prv)
{
    BSL_Param param[] = {
        {CRYPT_PARAM_RSA_D, BSL_PARAM_TYPE_OCTETS, prv->d, prv->dLen, 0},
        {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, prv->n, prv->nLen, 0},
        {CRYPT_PARAM_RSA_P, BSL_PARAM_TYPE_OCTETS, prv->p, prv->pLen, 0},
        {CRYPT_PARAM_RSA_Q, BSL_PARAM_TYPE_OCTETS, prv->q, prv->qLen, 0},
        {CRYPT_PARAM_RSA_DP, BSL_PARAM_TYPE_OCTETS, prv->dP, prv->dPLen, 0},
        {CRYPT_PARAM_RSA_DQ, BSL_PARAM_TYPE_OCTETS, prv->dQ, prv->dQLen, 0},
        {CRYPT_PARAM_RSA_QINV, BSL_PARAM_TYPE_OCTETS, prv->qInv, prv->qInvLen, 0},
        {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, prv->e, prv->eLen, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
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
#endif

#if defined HITLS_CRYPTO_DSA || defined HITLS_CRYPTO_ED25519 || defined HITLS_CRYPTO_X25519 || \
    defined HITLS_CRYPTO_DH || defined HITLS_CRYPTO_ECDSA || defined HITLS_CRYPTO_ECDH || \
    defined HITLS_CRYPTO_SM2
static int32_t GetCommonPrv(const CRYPT_EAL_PkeyCtx *pkey, int32_t paramKey, CRYPT_Data *prv)
{
    BSL_Param param[2] = {
        {paramKey, BSL_PARAM_TYPE_OCTETS, prv->data, prv->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    prv->len = param[0].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_PAILLIER
static int32_t GetPaillierPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_PaillierPrv *prv)
{
    BSL_Param param[5] = {
        {CRYPT_PARAM_PAILLIER_N, BSL_PARAM_TYPE_OCTETS, prv->n, prv->nLen, 0},
        {CRYPT_PARAM_PAILLIER_LAMBDA, BSL_PARAM_TYPE_OCTETS, prv->lambda, prv->lambdaLen, 0},
        {CRYPT_PARAM_PAILLIER_MU, BSL_PARAM_TYPE_OCTETS, prv->mu, prv->muLen, 0},
        {CRYPT_PARAM_PAILLIER_N2, BSL_PARAM_TYPE_OCTETS, prv->n2, prv->n2Len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    prv->nLen = param[0].useLen;
    prv->lambdaLen = param[1].useLen;
    prv->muLen = param[2].useLen;
    prv->n2Len = param[3].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_ELGAMAL
static int32_t GetElGamalPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_ElGamalPrv *prv)
{
    BSL_Param param[5] = {
        {CRYPT_PARAM_ELGAMAL_P, BSL_PARAM_TYPE_OCTETS, prv->p, prv->pLen, 0},
        {CRYPT_PARAM_ELGAMAL_G, BSL_PARAM_TYPE_OCTETS, prv->g, prv->gLen, 0},
        {CRYPT_PARAM_ELGAMAL_X, BSL_PARAM_TYPE_OCTETS, prv->x, prv->xLen, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    prv->pLen = param[0].useLen;
    prv->gLen = param[1].useLen;
    prv->xLen = param[2].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_MLKEM
static int32_t GetMlkemPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_KemDecapsKey *kemDk)
{
    BSL_Param param[2] = {
        {CRYPT_PARAM_ML_KEM_PRVKEY, BSL_PARAM_TYPE_OCTETS, kemDk->data, kemDk->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    kemDk->len = param[0].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_MLDSA
static int32_t GetMldsaPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MlDsaPrv *dsaPrv)
{
    BSL_Param param[2] = {
        {CRYPT_PARAM_ML_DSA_PRVKEY, BSL_PARAM_TYPE_OCTETS, dsaPrv->data, dsaPrv->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    dsaPrv->len = param[0].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_HYBRIDKEM
static int32_t GetHybridkemPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_KemDecapsKey *kemDk)
{
    BSL_Param param[2] = {
        {CRYPT_PARAM_HYBRID_PRVKEY, BSL_PARAM_TYPE_OCTETS, kemDk->data, kemDk->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    kemDk->len = param[0].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_SLH_DSA
static int32_t GetSlhDsaPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_SlhDsaPrv *prv)
{
    BSL_Param param[5] = {
        {CRYPT_PARAM_SLH_DSA_PRV_SEED, BSL_PARAM_TYPE_OCTETS, prv->seed, prv->pub.len, 0},
        {CRYPT_PARAM_SLH_DSA_PRV_PRF, BSL_PARAM_TYPE_OCTETS, prv->prf, prv->pub.len, 0},
        {CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, prv->pub.seed, prv->pub.len, 0},
        {CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, prv->pub.root, prv->pub.len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    prv->pub.len = param[0].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_XMSS
static int32_t GetXmssPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_XmssPrv *prv)
{
    BSL_Param param[6] = {
        {CRYPT_PARAM_XMSS_PRV_SEED, BSL_PARAM_TYPE_OCTETS, prv->seed, prv->pub.len, 0},
        {CRYPT_PARAM_XMSS_PRV_PRF, BSL_PARAM_TYPE_OCTETS, prv->prf, prv->pub.len, 0},
        {CRYPT_PARAM_XMSS_PRV_INDEX, BSL_PARAM_TYPE_UINT64, &prv->index, sizeof(prv->index), 0},
        {CRYPT_PARAM_XMSS_PUB_SEED, BSL_PARAM_TYPE_OCTETS, prv->pub.seed, prv->pub.len, 0},
        {CRYPT_PARAM_XMSS_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, prv->pub.root, prv->pub.len, 0},
        BSL_PARAM_END,
    };
    int32_t ret = pkey->method.getPrv(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    prv->pub.len = param[0].useLen;
    return CRYPT_SUCCESS;
}
#endif

int32_t PkeyProviderGetPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPrv *key)
{
    switch (pkey->id) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA:
            return GetRSAPrv(pkey, &key->key.rsaPrv);
#endif
#ifdef HITLS_CRYPTO_DSA
        case CRYPT_PKEY_DSA:
            return GetCommonPrv(pkey, CRYPT_PARAM_DSA_PRVKEY, &key->key.dsaPrv);
#endif
#if defined HITLS_CRYPTO_ED25519 || defined HITLS_CRYPTO_X25519
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519:
            return GetCommonPrv(pkey, CRYPT_PARAM_CURVE25519_PRVKEY, &key->key.curve25519Prv);
#endif
#ifdef HITLS_CRYPTO_DH
        case CRYPT_PKEY_DH:
            return GetCommonPrv(pkey, CRYPT_PARAM_DH_PRVKEY, &key->key.dhPrv);
#endif
#if defined HITLS_CRYPTO_ECDSA || defined HITLS_CRYPTO_ECDH || defined HITLS_CRYPTO_SM2
        case CRYPT_PKEY_ECDH:
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_SM2:
            return GetCommonPrv(pkey, CRYPT_PARAM_EC_PRVKEY, &key->key.eccPrv);
#endif
#ifdef HITLS_CRYPTO_PAILLIER
        case CRYPT_PKEY_PAILLIER:
            return GetPaillierPrv(pkey, &key->key.paillierPrv);
#endif
#ifdef HITLS_CRYPTO_ELGAMAL
        case CRYPT_PKEY_ELGAMAL:
            return GetElGamalPrv(pkey, &key->key.elgamalPrv);
#endif
#ifdef HITLS_CRYPTO_MLKEM
        case CRYPT_PKEY_ML_KEM:
            return GetMlkemPrv(pkey, &key->key.kemDk);
#endif
#ifdef HITLS_CRYPTO_MLDSA
        case CRYPT_PKEY_ML_DSA:
            return GetMldsaPrv(pkey, &key->key.mldsaPrv);
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
        case CRYPT_PKEY_SLH_DSA:
            return GetSlhDsaPrv(pkey, &key->key.slhDsaPrv);
#endif
#ifdef HITLS_CRYPTO_XMSS
        case CRYPT_PKEY_XMSS:
            return GetXmssPrv(pkey, &key->key.xmssPrv);
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
        case CRYPT_PKEY_HYBRID_KEM:
            return GetHybridkemPrv(pkey, &key->key.kemDk);
#endif
        default:
            (void)key;
            (void)pkey;
            return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
}

int32_t PkeyProviderSetPub(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPub *key)
{
    switch (pkey->id) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA: {
            BSL_Param rsa[3] = {
                {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, key->key.rsaPub.e, key->key.rsaPub.eLen, 0},
                {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, key->key.rsaPub.n, key->key.rsaPub.nLen, 0},
                BSL_PARAM_END};
            return pkey->method.setPub(pkey->key, &rsa);
        }
#endif
#ifdef HITLS_CRYPTO_DSA
        case CRYPT_PKEY_DSA: {
            BSL_Param dsa[2] = {
                {CRYPT_PARAM_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.dsaPub.data, key->key.dsaPub.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPub(pkey->key, &dsa);
        }
#endif
#if defined HITLS_CRYPTO_ED25519 || defined HITLS_CRYPTO_X25519
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519: {
            BSL_Param para[2] = {
                {CRYPT_PARAM_CURVE25519_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.curve25519Pub.data,
                    key->key.curve25519Pub.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPub(pkey->key, &para);
        }
#endif
#ifdef HITLS_CRYPTO_DH
        case CRYPT_PKEY_DH: {
            BSL_Param dhParam[2] = {
                {CRYPT_PARAM_DH_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.dhPub.data, key->key.dhPub.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPub(pkey->key, &dhParam);
        }
#endif
#if defined HITLS_CRYPTO_ECDSA || defined HITLS_CRYPTO_ECDH || defined HITLS_CRYPTO_SM2
        case CRYPT_PKEY_ECDH:
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_SM2: {
            BSL_Param ecParam[2] = {
                {CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.eccPub.data, key->key.eccPub.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPub(pkey->key, &ecParam);
        }
#endif
#ifdef HITLS_CRYPTO_PAILLIER
        case CRYPT_PKEY_PAILLIER: {
            BSL_Param paParam[4] = {
                {CRYPT_PARAM_PAILLIER_N, BSL_PARAM_TYPE_OCTETS, key->key.paillierPub.n, key->key.paillierPub.nLen, 0},
                {CRYPT_PARAM_PAILLIER_G, BSL_PARAM_TYPE_OCTETS, key->key.paillierPub.g, key->key.paillierPub.gLen, 0},
                {CRYPT_PARAM_PAILLIER_N2, BSL_PARAM_TYPE_OCTETS, key->key.paillierPub.n2, key->key.paillierPub.n2Len,
                    0},
                BSL_PARAM_END};
            return pkey->method.setPub(pkey->key, &paParam);
        }
#endif
#ifdef HITLS_CRYPTO_MLKEM
        case CRYPT_PKEY_ML_KEM: {
            BSL_Param paParam[2] = {
                {CRYPT_PARAM_ML_KEM_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.kemEk.data, key->key.kemEk.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPub(pkey->key, &paParam);
        }
#endif
#ifdef HITLS_CRYPTO_MLDSA
        case CRYPT_PKEY_ML_DSA: {
            BSL_Param paParam[2] = {
                {CRYPT_PARAM_ML_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.mldsaPub.data, key->key.mldsaPub.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPub(pkey->key, &paParam);
        }
#endif
#ifdef HITLS_CRYPTO_ELGAMAL
        case CRYPT_PKEY_ELGAMAL: {
            BSL_Param paParam[5] = {
                {CRYPT_PARAM_ELGAMAL_P, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPub.p, key->key.elgamalPub.pLen, 0},
                {CRYPT_PARAM_ELGAMAL_G, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPub.g, key->key.elgamalPub.gLen, 0},
                {CRYPT_PARAM_ELGAMAL_Y, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPub.y, key->key.elgamalPub.pLen, 0},
                {CRYPT_PARAM_ELGAMAL_Q, BSL_PARAM_TYPE_OCTETS, key->key.elgamalPub.q, key->key.elgamalPub.qLen, 0},
                BSL_PARAM_END};
            return pkey->method.setPub(pkey->key, &paParam);
        }
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
        case CRYPT_PKEY_SLH_DSA: {
            BSL_Param slhDsaPub[3] = {
                {CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, key->key.slhDsaPub.seed,
                    key->key.slhDsaPub.len, 0},
                {CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, key->key.slhDsaPub.root,
                    key->key.slhDsaPub.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPub(pkey->key, &slhDsaPub);
        }
#endif
#ifdef HITLS_CRYPTO_XMSS
        case CRYPT_PKEY_XMSS: {
            BSL_Param xmssPub[3] = {
                {CRYPT_PARAM_XMSS_PUB_SEED, BSL_PARAM_TYPE_OCTETS, key->key.xmssPub.seed, key->key.xmssPub.len, 0},
                {CRYPT_PARAM_XMSS_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, key->key.xmssPub.root, key->key.xmssPub.len, 0},
                BSL_PARAM_END,
            };
            return pkey->method.setPub(pkey->key, &xmssPub);
        }
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
        case CRYPT_PKEY_HYBRID_KEM: {
            BSL_Param paParam[2] = {
                {CRYPT_PARAM_HYBRID_PUBKEY, BSL_PARAM_TYPE_OCTETS, key->key.kemEk.data, key->key.kemEk.len, 0},
                BSL_PARAM_END};
            return pkey->method.setPub(pkey->key, &paParam);
        }
#endif
        default:
            (void)key;
            (void)pkey;
            return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
}

#ifdef HITLS_CRYPTO_RSA
static int32_t GetRSAPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_RsaPub *pub)
{
    BSL_Param param[3] = {
        {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, pub->e, pub->eLen, 0},
        {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, pub->n, pub->nLen, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    pub->eLen = param[0].useLen;
    pub->nLen = param[1].useLen;
    return CRYPT_SUCCESS;
}
#endif

#if defined HITLS_CRYPTO_DSA || defined HITLS_CRYPTO_ED25519 || defined HITLS_CRYPTO_X25519 || \
    defined HITLS_CRYPTO_DH || defined HITLS_CRYPTO_ECDSA || defined HITLS_CRYPTO_ECDH || \
    defined HITLS_CRYPTO_SM2
static int32_t GetCommonPub(const CRYPT_EAL_PkeyCtx *pkey, int32_t paramKey, CRYPT_Data *pub)
{
    BSL_Param param[2] = {
        {paramKey, BSL_PARAM_TYPE_OCTETS, pub->data, pub->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    pub->len = param[0].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_PAILLIER
static int32_t GetPaillierPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_PaillierPub *pub)
{
     BSL_Param param[4] = {
        {CRYPT_PARAM_PAILLIER_N, BSL_PARAM_TYPE_OCTETS, pub->n, pub->nLen, 0},
        {CRYPT_PARAM_PAILLIER_G, BSL_PARAM_TYPE_OCTETS, pub->g, pub->gLen, 0},
        {CRYPT_PARAM_PAILLIER_N2, BSL_PARAM_TYPE_OCTETS, pub->n2, pub->n2Len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    pub->nLen = param[0].useLen;
    pub->gLen = param[1].useLen;
    pub->n2Len = param[2].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_ELGAMAL
static int32_t GetElGamalPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_ElGamalPub *pub)
{
    BSL_Param param[5] = {
        {CRYPT_PARAM_ELGAMAL_P, BSL_PARAM_TYPE_OCTETS, pub->p, pub->pLen, 0},
        {CRYPT_PARAM_ELGAMAL_G, BSL_PARAM_TYPE_OCTETS, pub->g, pub->gLen, 0},
        {CRYPT_PARAM_ELGAMAL_Y, BSL_PARAM_TYPE_OCTETS, pub->y, pub->yLen, 0},
        {CRYPT_PARAM_ELGAMAL_Q, BSL_PARAM_TYPE_OCTETS, pub->q, pub->qLen, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    pub->pLen = param[0].useLen;
    pub->gLen = param[1].useLen;
    pub->yLen = param[2].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_MLKEM
static int32_t GetMlkemPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_KemEncapsKey *kemEk)
{
    BSL_Param param[2] = {
        {CRYPT_PARAM_ML_KEM_PUBKEY, BSL_PARAM_TYPE_OCTETS, kemEk->data, kemEk->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    kemEk->len = param[0].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_MLDSA
static int32_t GetMldsaPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MlDsaPub *dsaPub)
{
    BSL_Param param[2] = {
        {CRYPT_PARAM_ML_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, dsaPub->data, dsaPub->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    dsaPub->len = param[0].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_HYBRIDKEM
static int32_t GetHybridkemPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_KemEncapsKey *kemEk)
{
    BSL_Param param[2] = {
        {CRYPT_PARAM_HYBRID_PUBKEY, BSL_PARAM_TYPE_OCTETS, kemEk->data, kemEk->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    kemEk->len = param[0].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_SLH_DSA
static int32_t GetSlhDsaPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_SlhDsaPub *pub)
{
    BSL_Param param[3] = {
        {CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, pub->seed, pub->len, 0},
        {CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, pub->root, pub->len, 0},
        BSL_PARAM_END};
    int32_t ret = pkey->method.getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    pub->len = param[0].useLen;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_XMSS
static int32_t GetXmssPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_XmssPub *pub)
{
    BSL_Param param[3] = {
        {CRYPT_PARAM_XMSS_PUB_SEED, BSL_PARAM_TYPE_OCTETS, pub->seed, pub->len, 0},
        {CRYPT_PARAM_XMSS_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, pub->root, pub->len, 0},
        BSL_PARAM_END,
    };
    int32_t ret = pkey->method.getPub(pkey->key, &param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    pub->len = param[0].useLen;
    return CRYPT_SUCCESS;
}
#endif

int32_t PkeyProviderGetPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPub *key)
{
    switch (pkey->id) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA:
            return GetRSAPub(pkey, &key->key.rsaPub);
#endif
#ifdef HITLS_CRYPTO_DSA
        case CRYPT_PKEY_DSA:
            return GetCommonPub(pkey, CRYPT_PARAM_DSA_PUBKEY, &key->key.dsaPub);
#endif
#if defined HITLS_CRYPTO_ED25519 || defined HITLS_CRYPTO_X25519
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519:
            return GetCommonPub(pkey, CRYPT_PARAM_CURVE25519_PUBKEY, &key->key.curve25519Pub);
#endif
#ifdef HITLS_CRYPTO_DH
        case CRYPT_PKEY_DH:
            return GetCommonPub(pkey, CRYPT_PARAM_DH_PUBKEY, &key->key.dhPub);
#endif
#if defined HITLS_CRYPTO_ECDSA || defined HITLS_CRYPTO_ECDH || defined HITLS_CRYPTO_SM2
        case CRYPT_PKEY_ECDH:
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_SM2:
            return GetCommonPub(pkey, CRYPT_PARAM_EC_PUBKEY, &key->key.eccPub);
#endif
#ifdef HITLS_CRYPTO_PAILLIER
        case CRYPT_PKEY_PAILLIER:
            return GetPaillierPub(pkey, &key->key.paillierPub);
#endif
#ifdef HITLS_CRYPTO_ELGAMAL
        case CRYPT_PKEY_ELGAMAL:
            return GetElGamalPub(pkey, &key->key.elgamalPub);
#endif
#ifdef HITLS_CRYPTO_MLKEM
        case CRYPT_PKEY_ML_KEM:
            return GetMlkemPub(pkey, &key->key.kemEk);
#endif
#ifdef HITLS_CRYPTO_MLDSA
        case CRYPT_PKEY_ML_DSA:
            return GetMldsaPub(pkey, &key->key.mldsaPub);
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
        case CRYPT_PKEY_HYBRID_KEM:
            return GetHybridkemPub(pkey, &key->key.kemEk);
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
        case CRYPT_PKEY_SLH_DSA:
            return GetSlhDsaPub(pkey, &key->key.slhDsaPub);
#endif
#ifdef HITLS_CRYPTO_XMSS
        case CRYPT_PKEY_XMSS:
            return GetXmssPub(pkey, &key->key.xmssPub);
#endif
        default:
            (void)key;
            (void)pkey;
            return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
}

#endif