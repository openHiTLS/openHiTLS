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
#ifdef HITLS_CRYPTO_PROVIDER

#include "crypt_eal_implprovider.h"
#include "crypt_dsa.h"
#include "crypt_curve25519.h"
#include "crypt_rsa.h"
#include "crypt_dh.h"
#include "crypt_ecdsa.h"
#include "crypt_ecdh.h"
#include "crypt_sm2.h"
#include "crypt_paillier.h"
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_params.h"
#include "crypt_params_type.h"

void *CRYPT_EAL_DefPkeyMgmtNewCtx(void *provCtx, int32_t algId)
{
    (void) provCtx;
    void *pkeyCtx = NULL;
    switch (algId) {
        case CRYPT_PKEY_DSA:
            pkeyCtx = CRYPT_DSA_NewCtx();
            break;
        case CRYPT_PKEY_ED25519:
            pkeyCtx = CRYPT_ED25519_NewCtx();
            break;
        case CRYPT_PKEY_X25519:
            pkeyCtx = CRYPT_X25519_NewCtx();
            break;
        case CRYPT_PKEY_RSA:
            pkeyCtx = CRYPT_RSA_NewCtx();
            break;
        case CRYPT_PKEY_DH:
            pkeyCtx = CRYPT_DH_NewCtx();
            break;
        case CRYPT_PKEY_ECDSA:
            pkeyCtx = CRYPT_ECDSA_NewCtx();
            break;
        case CRYPT_PKEY_ECDH:
            pkeyCtx = CRYPT_ECDH_NewCtx();
            break;
        case CRYPT_PKEY_SM2:
            pkeyCtx = CRYPT_SM2_NewCtx();
            break;
        case CRYPT_PKEY_PAILLIER:
            pkeyCtx = CRYPT_PAILLIER_NewCtx();
            break;
    }
    if (pkeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
    return pkeyCtx;
};

static int32_t CvtBslParamAndSetParams(BSL_Param *param, void *ctx, int32_t algId)
{
    switch (algId)
    {
        case CRYPT_PKEY_DSA: {
            CRYPT_DsaPara Para = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_DSA_KEY_P, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&Para.p, &Para.pLen);
            BSL_Param_GetPtrValue(&param[1], CRYPT_DSA_KEY_Q, BSL_PARAM_TYPE_UINT32_PTR,
                (void **)&Para.q, &Para.qLen);
            BSL_Param_GetPtrValue(&param[2], CRYPT_DSA_KEY_G, BSL_PARAM_TYPE_UINT32_PTR,
                (void **)&Para.g, &Para.gLen);
            return CRYPT_DSA_SetPara((CRYPT_DSA_Ctx *)ctx, &Para);
        }
        case CRYPT_PKEY_RSA: {
            CRYPT_RsaPara Para = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_RSA_KEY_E, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&Para.e, &Para.eLen);
            uint32_t len = sizeof(Para.bits);
            BSL_Param_GetValue(&param[1], CRYPT_RSA_KEY_BITS, BSL_PARAM_TYPE_UINT32,
                &Para.bits, &len);;
            return CRYPT_RSA_SetPara((CRYPT_RSA_Ctx *)ctx, &Para);
        }
        case CRYPT_PKEY_DH: {
            CRYPT_DhPara Para = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_DH_KEY_P, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&Para.p, &Para.pLen);
            BSL_Param_GetPtrValue(&param[1], CRYPT_DH_KEY_Q, BSL_PARAM_TYPE_UINT32_PTR,
                (void **)&Para.q, &Para.qLen);
            BSL_Param_GetPtrValue(&param[2], CRYPT_DH_KEY_G, BSL_PARAM_TYPE_UINT32_PTR,
                (void **)&Para.g, &Para.gLen);
            return CRYPT_DH_SetPara((CRYPT_DH_Ctx *)ctx, &Para);
        }
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_ECDH: {
            CRYPT_EccPara Para = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_ECC_KEY_P, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&Para.p, &Para.pLen);
            BSL_Param_GetPtrValue(&param[1], CRYPT_ECC_KEY_A, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&Para.a, &Para.aLen);
            BSL_Param_GetPtrValue(&param[2], CRYPT_ECC_KEY_B, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&Para.b, &Para.bLen);
            BSL_Param_GetPtrValue(&param[3], CRYPT_ECC_KEY_N, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&Para.n, &Para.nLen);
            BSL_Param_GetPtrValue(&param[4], CRYPT_ECC_KEY_H, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&Para.h, &Para.hLen);
            BSL_Param_GetPtrValue(&param[5], CRYPT_ECC_KEY_X, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&Para.x, &Para.xLen);
            BSL_Param_GetPtrValue(&param[6], CRYPT_ECC_KEY_Y, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&Para.y, &Para.yLen);
            return algId == CRYPT_PKEY_ECDSA ? CRYPT_ECDSA_SetPara((CRYPT_ECDSA_Ctx *)ctx, &Para) :
                CRYPT_ECDH_SetPara((CRYPT_ECDH_Ctx *)ctx, &Para);
        }
        case CRYPT_PKEY_PAILLIER: {
            CRYPT_PaillierPara Para = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PAILLER_KEY_N, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&Para.p, &Para.pLen);
            BSL_Param_GetPtrValue(&param[1], CRYPT_PAILLER_KEY_Q, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&Para.q, &Para.qLen);
            uint32_t len = sizeof(Para.bits);
            BSL_Param_GetValue(&param[2], CRYPT_PAILLER_KEY_BITS, BSL_PARAM_TYPE_UINT32,
                &Para.bits, &len);
            return CRYPT_PAILLIER_SetPara((CRYPT_PAILLIER_Ctx *)ctx, &Para);
        }
        default:
            return CRYPT_EAL_ERR_ALGID;
    }
}

static int32_t CvtBslParamAndGetParams(BSL_Param *param, void *ctx, int32_t algId)
{
    int32_t ret;
    switch (algId)
    {
        case CRYPT_PKEY_DSA: {
            CRYPT_DsaPara Para = {param[0].value, param[1].value, param[2].value, param[0].valueLen, param[1].valueLen, param[2].valueLen};
            ret = CRYPT_DSA_GetPara((CRYPT_DSA_Ctx *)ctx, &Para);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = Para.pLen;
            param[1].useLen = Para.qLen;
            param[2].useLen = Para.gLen;
            break;
        }
        case CRYPT_PKEY_DH: {
            CRYPT_DhPara Para = {param[0].value, param[1].value, param[2].value, param[0].valueLen, param[1].valueLen, param[2].valueLen};
            ret = CRYPT_DH_GetPara((CRYPT_DH_Ctx *)ctx, &Para);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = Para.pLen;
            param[1].useLen = Para.qLen;
            param[2].useLen = Para.gLen;
            break;
        }
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_ECDH: {
            CRYPT_EccPara Para = {param[0].value, param[1].value, param[2].value, param[3].value, param[4].value, param[5].value, param[6].value,
                param[0].valueLen, param[1].valueLen, param[2].valueLen, param[3].valueLen, param[4].valueLen, param[5].valueLen, param[6].valueLen};
            ret = (algId == CRYPT_PKEY_ECDSA) ? CRYPT_ECDSA_GetPara((CRYPT_ECDSA_Ctx *)ctx, &Para)
                : CRYPT_ECDH_GetPara((CRYPT_ECDH_Ctx *)ctx, &Para);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = Para.pLen;
            param[1].useLen = Para.aLen;
            param[2].useLen = Para.bLen;
            param[3].useLen = Para.nLen;
            param[4].useLen = Para.hLen;
            param[5].useLen = Para.xLen;
            param[6].useLen = Para.yLen;
            break;
        }
        default:
            return CRYPT_EAL_ERR_ALGID;
    }
    return CRYPT_SUCCESS;
}

static int32_t CvtBslParamAndSetPub(BSL_Param *param, void *ctx, int32_t algId)
{
    switch (algId)
    {
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519:
            CRYPT_Data k1 = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PUBLIC_KEY, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&k1.data, &k1.len);
            return CRYPT_CURVE25519_SetPubKey((CRYPT_CURVE25519_Ctx *)ctx, &k1);
        case CRYPT_PKEY_DH: {
            CRYPT_Data k2 = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PUBLIC_KEY, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&k2.data, &k2.len);
            return CRYPT_DH_SetPubKey((CRYPT_DH_Ctx *)ctx, &k2);
        }
        case CRYPT_PKEY_ECDSA: {
            CRYPT_Data k3 = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PUBLIC_KEY, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&k3.data, &k3.len);
            return CRYPT_ECDSA_SetPubKey((CRYPT_ECDSA_Ctx *)ctx, &k3);
        }
        case CRYPT_PKEY_ECDH: {
            CRYPT_Data k4 = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PUBLIC_KEY, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&k4.data, &k4.len);
            return CRYPT_ECDH_SetPubKey((CRYPT_ECDH_Ctx *)ctx, &k4);
        }
        case CRYPT_PKEY_SM2: {
            CRYPT_Data k5 = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PUBLIC_KEY, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&k5.data, &k5.len);
            return CRYPT_SM2_SetPubKey((CRYPT_SM2_Ctx *)ctx, &k5);
        }
        case CRYPT_PKEY_DSA: {
            CRYPT_Data k6 = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PUBLIC_KEY, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&k6.data, &k6.len);
            return CRYPT_DSA_SetPubKey((CRYPT_DSA_Ctx *)ctx, &k6);
        }
        case CRYPT_PKEY_RSA: {
            CRYPT_RsaPub k7 = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_RSA_KEY_E, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&k7.e, &k7.eLen);
            BSL_Param_GetPtrValue(&param[1], CRYPT_RSA_KEY_N, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&k7.n, &k7.nLen);
            return CRYPT_RSA_SetPubKey((CRYPT_RSA_Ctx *)ctx, &k7);
        }
        case CRYPT_PKEY_PAILLIER: {
            CRYPT_PaillierPub k8 = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PAILLER_KEY_N, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&k8.n, &k8.nLen);
            BSL_Param_GetPtrValue(&param[1], CRYPT_PAILLER_KEY_G, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&k8.g, &k8.gLen);
            BSL_Param_GetPtrValue(&param[2], CRYPT_PAILLER_KEY_N2, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&k8.n2, &k8.n2Len);
            return CRYPT_PAILLIER_SetPubKey((CRYPT_PAILLIER_Ctx *)ctx, &k8);
        }
        default:
            return CRYPT_EAL_ERR_ALGID;
    }
}

static int32_t CvtBslParamAndSetPrv(BSL_Param *param, void *ctx, int32_t algId)
{
    switch (algId)
    {
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519:
            CRYPT_Data kCurve25519 = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PRIVATE_KEY, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kCurve25519.data, &kCurve25519.len);
            return CRYPT_CURVE25519_SetPrvKey((CRYPT_CURVE25519_Ctx *)ctx, &kCurve25519);
        case CRYPT_PKEY_DH: {
            CRYPT_Data kDh = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PRIVATE_KEY, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kDh.data, &kDh.len);
            return CRYPT_DH_SetPrvKey((CRYPT_DH_Ctx *)ctx, &kDh);
        }
        case CRYPT_PKEY_ECDSA: {
            CRYPT_Data kEcdsa = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PRIVATE_KEY, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kEcdsa.data, &kEcdsa.len);
            return CRYPT_ECDSA_SetPrvKey((CRYPT_ECDSA_Ctx *)ctx, &kEcdsa);
        }
        case CRYPT_PKEY_ECDH: {
            CRYPT_Data kEcdh = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PRIVATE_KEY, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kEcdh.data, &kEcdh.len);
            return CRYPT_ECDH_SetPrvKey((CRYPT_ECDH_Ctx *)ctx, &kEcdh);
        }
        case CRYPT_PKEY_SM2: {
            CRYPT_Data kSm2 = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PRIVATE_KEY, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kSm2.data, &kSm2.len);
            return CRYPT_SM2_SetPrvKey((CRYPT_SM2_Ctx *)ctx, &kSm2);
        }
        case CRYPT_PKEY_DSA: {
            CRYPT_Data kDsa = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PRIVATE_KEY, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kDsa.data, &kDsa.len);
            return CRYPT_DSA_SetPrvKey((CRYPT_DSA_Ctx *)ctx, &kDsa);
        }
        case CRYPT_PKEY_RSA: {
            CRYPT_RsaPrv kRsa = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_RSA_KEY_D, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kRsa.d, &kRsa.dLen);
            BSL_Param_GetPtrValue(&param[1], CRYPT_RSA_KEY_N, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kRsa.n, &kRsa.nLen);
            BSL_Param_GetPtrValue(&param[2], CRYPT_RSA_KEY_P, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kRsa.p, &kRsa.pLen);
            BSL_Param_GetPtrValue(&param[3], CRYPT_RSA_KEY_Q, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kRsa.q, &kRsa.qLen);
            BSL_Param_GetPtrValue(&param[4], CRYPT_RSA_KEY_DP, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kRsa.dP, &kRsa.dPLen);
            BSL_Param_GetPtrValue(&param[5], CRYPT_RSA_KEY_DQ, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kRsa.dQ, &kRsa.dQLen);
            BSL_Param_GetPtrValue(&param[6], CRYPT_RSA_KEY_QINV, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kRsa.qInv, &kRsa.qInvLen);
            BSL_Param_GetPtrValue(&param[7], CRYPT_RSA_KEY_E, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kRsa.e, &kRsa.eLen);
            return CRYPT_RSA_SetPrvKey((CRYPT_RSA_Ctx *)ctx, &kRsa);
        }
        case CRYPT_PKEY_PAILLIER: {
            CRYPT_PaillierPrv kPaillier = {0};
            BSL_Param_GetPtrValue(&param[0], CRYPT_PAILLER_KEY_N, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kPaillier.n, &kPaillier.nLen);
            BSL_Param_GetPtrValue(&param[1], CRYPT_PAILLER_KEY_LAMBDA, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kPaillier.lambda, &kPaillier.lambdaLen);
            BSL_Param_GetPtrValue(&param[2], CRYPT_PAILLER_KEY_MU, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kPaillier.mu, &kPaillier.muLen);
            BSL_Param_GetPtrValue(&param[3], CRYPT_PAILLER_KEY_N2, BSL_PARAM_TYPE_OCTETS_PTR,
                (void **)&kPaillier.n2, &kPaillier.n2Len);
            return CRYPT_PAILLIER_SetPrvKey((CRYPT_PAILLIER_Ctx *)ctx, &kPaillier);
        }
        default:
            return CRYPT_EAL_ERR_ALGID;
    }
}

static int32_t CvtBslParamAndGetPub(BSL_Param *param, const void *ctx, int32_t algId)
{
    int32_t ret;
    switch (algId)
    {
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519:
            CRYPT_Data kCurve = {param[0].value, param[0].valueLen};
            ret = CRYPT_CURVE25519_GetPubKey((const CRYPT_CURVE25519_Ctx *)ctx, &kCurve);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kCurve.len;
            break;
        case CRYPT_PKEY_DH: {
            CRYPT_Data kDh = {param[0].value, param[0].valueLen};
            ret = CRYPT_DH_GetPubKey((const CRYPT_DH_Ctx *)ctx, &kDh);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kDh.len;
            break;
        }
        case CRYPT_PKEY_ECDSA: {
            CRYPT_Data kEcdsa = {param[0].value, param[0].valueLen};
            ret = CRYPT_ECDSA_GetPubKey((const CRYPT_ECDSA_Ctx *)ctx, &kEcdsa);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kEcdsa.len;
            break;
        }
        case CRYPT_PKEY_ECDH: {
            CRYPT_Data kEcdh = {param[0].value, param[0].valueLen};
            ret = CRYPT_ECDH_GetPubKey((const CRYPT_ECDH_Ctx *)ctx, &kEcdh);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kEcdh.len;
            break;
        }
        case CRYPT_PKEY_SM2: {
            CRYPT_Data kSm2 = {param[0].value, param[0].valueLen};
            ret = CRYPT_SM2_GetPubKey((const CRYPT_SM2_Ctx *)ctx, &kSm2);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kSm2.len;
            break;
        }
        case CRYPT_PKEY_DSA: {
            CRYPT_Data kDsa = {param[0].value, param[0].valueLen};
            ret = CRYPT_DSA_GetPubKey((const CRYPT_DSA_Ctx *)ctx, &kDsa);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kDsa.len;
            break;
        }
        case CRYPT_PKEY_RSA: {
            CRYPT_RsaPub kRsa = {param[0].value, param[1].value, param[0].valueLen, param[1].valueLen};
            ret = CRYPT_RSA_GetPubKey((CRYPT_RSA_Ctx *)ctx, &kRsa);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kRsa.eLen;
            param[1].useLen = kRsa.nLen;
            break;
        }
        case CRYPT_PKEY_PAILLIER: {
            CRYPT_PaillierPub kPaillier = {param[0].value, param[1].value, param[2].value, param[0].valueLen, param[1].valueLen, param[2].valueLen};
            ret = CRYPT_PAILLIER_GetPubKey((CRYPT_PAILLIER_Ctx *)ctx, &kPaillier);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kPaillier.nLen;
            param[1].useLen = kPaillier.gLen;
            param[2].useLen = kPaillier.n2Len;
            break;
        }
        default:
            return CRYPT_EAL_ERR_ALGID;
    }
    return CRYPT_SUCCESS;
}

static int32_t CvtBslParamAndGetPrv(BSL_Param *param, const void *ctx, int32_t algId)
{
    int32_t ret;
    switch (algId)
    {
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_X25519:
            CRYPT_Data kCurve25519 = {param[0].value, param[0].valueLen};
            ret = CRYPT_CURVE25519_GetPrvKey((const CRYPT_CURVE25519_Ctx *)ctx, &kCurve25519);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kCurve25519.len;
            break;
        case CRYPT_PKEY_DH: {
            CRYPT_Data kDh = {param[0].value, param[0].valueLen};
            ret = CRYPT_DH_GetPrvKey((const CRYPT_DH_Ctx *)ctx, &kDh);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kDh.len;
            break;
        }
        case CRYPT_PKEY_ECDSA: {
            CRYPT_Data kEcdsa = {param[0].value, param[0].valueLen};
            ret = CRYPT_ECDSA_GetPrvKey((const CRYPT_ECDSA_Ctx *)ctx, &kEcdsa);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kEcdsa.len;
            break;
        }
        case CRYPT_PKEY_ECDH: {
            CRYPT_Data kEcdh = {param[0].value, param[0].valueLen};
            ret = CRYPT_ECDH_GetPrvKey((const CRYPT_ECDH_Ctx *)ctx, &kEcdh);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kEcdh.len;
            break;
        }
        case CRYPT_PKEY_SM2: {
            CRYPT_Data kSm2 = {param[0].value, param[0].valueLen};
            ret = CRYPT_SM2_GetPrvKey((const CRYPT_SM2_Ctx *)ctx, &kSm2);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kSm2.len;
            break;
        }
        case CRYPT_PKEY_DSA: {
            CRYPT_Data kDsa = {param[0].value, param[0].valueLen};
            ret = CRYPT_DSA_GetPrvKey((const CRYPT_DSA_Ctx *)ctx, &kDsa);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kDsa.len;
            break;
        }
        case CRYPT_PKEY_RSA: {
            CRYPT_RsaPrv kRsaPrv = {param[0].value, param[1].value, param[2].value, param[3].value, param[4].value, param[5].value, param[6].value, param[7].value,
                param[0].valueLen, param[1].valueLen, param[2].valueLen, param[3].valueLen, param[4].valueLen, param[5].valueLen, param[6].valueLen, param[7].valueLen};
            ret = CRYPT_RSA_GetPrvKey((const CRYPT_RSA_Ctx *)ctx, &kRsaPrv);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kRsaPrv.dLen;
            param[1].useLen = kRsaPrv.nLen;
            param[2].useLen = kRsaPrv.pLen;
            param[3].useLen = kRsaPrv.qLen;
            param[4].useLen = kRsaPrv.dPLen;
            param[5].useLen = kRsaPrv.dQLen;
            param[6].useLen = kRsaPrv.qInvLen;
            param[7].useLen = kRsaPrv.eLen;
            break;
        }
        case CRYPT_PKEY_PAILLIER: {
            CRYPT_PaillierPrv kPaillierPrv = {param[0].value, param[1].value, param[2].value, param[3].value,
                param[0].valueLen, param[1].valueLen, param[2].valueLen, param[3].valueLen};
            ret = CRYPT_PAILLIER_GetPrvKey((const CRYPT_PAILLIER_Ctx *)ctx, &kPaillierPrv);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            param[0].useLen = kPaillierPrv.nLen;
            param[1].useLen = kPaillierPrv.lambdaLen;
            param[2].useLen = kPaillierPrv.muLen;
            param[3].useLen = kPaillierPrv.n2Len;
            break;
        }
        default:
            return CRYPT_EAL_ERR_ALGID;
    }
    return CRYPT_SUCCESS;
}

// set para
int32_t CRYPT_DSA_DefPkeyMgmtSetPara(CRYPT_DSA_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndSetParams(param, ctx, CRYPT_PKEY_DSA);
};

int32_t CRYPT_RSA_DefPkeyMgmtSetPara(CRYPT_RSA_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndSetParams(param, ctx, CRYPT_PKEY_RSA);
};

int32_t CRYPT_DH_DefPkeyMgmtSetPara(CRYPT_DH_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndSetParams(param, ctx, CRYPT_PKEY_DH);
};

int32_t CRYPT_ECDSA_DefPkeyMgmtSetPara(CRYPT_ECDSA_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndSetParams(param, ctx, CRYPT_PKEY_ECDSA);
};

int32_t CRYPT_ECDH_DefPkeyMgmtSetPara(CRYPT_ECDH_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndSetParams(param, ctx, CRYPT_PKEY_ECDH);
};

int32_t CRYPT_PAILLIER_DefPkeyMgmtSetPara(CRYPT_PAILLIER_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndSetParams(param, ctx, CRYPT_PKEY_PAILLIER);
};

// get para
int32_t CRYPT_DSA_DefPkeyMgmtGetPara(CRYPT_DSA_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetParams(param, ctx, CRYPT_PKEY_DSA);
};

int32_t CRYPT_DH_DefPkeyMgmtGetPara(CRYPT_DH_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetParams(param, ctx, CRYPT_PKEY_DH);
};

int32_t CRYPT_ECDSA_DefPkeyMgmtGetPara(CRYPT_ECDSA_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetParams(param, ctx, CRYPT_PKEY_ECDSA);
};

int32_t CRYPT_ECDH_DefPkeyMgmtGetPara(CRYPT_ECDH_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetParams(param, ctx, CRYPT_PKEY_ECDH);
};

// set pub
int32_t CRYPT_DSA_DefPkeyMgmtSetPub(CRYPT_DSA_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPub((BSL_Param *)param, ctx, CRYPT_PKEY_DSA);
};

int32_t CRYPT_ED25519_DefPkeyMgmtSetPub(CRYPT_CURVE25519_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPub((BSL_Param *)param, ctx, CRYPT_PKEY_ED25519);
};

int32_t CRYPT_X25519_DefPkeyMgmtSetPub(CRYPT_CURVE25519_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPub((BSL_Param *)param, ctx, CRYPT_PKEY_X25519);
};

int32_t CRYPT_RSA_DefPkeyMgmtSetPub(CRYPT_RSA_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPub((BSL_Param *)param, ctx, CRYPT_PKEY_RSA);
};

int32_t CRYPT_DH_DefPkeyMgmtSetPub(CRYPT_DH_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPub((BSL_Param *)param, ctx, CRYPT_PKEY_DH);
};

int32_t CRYPT_ECDSA_DefPkeyMgmtSetPub(CRYPT_ECDSA_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPub((BSL_Param *)param, ctx, CRYPT_PKEY_ECDSA);
};

int32_t CRYPT_ECDH_DefPkeyMgmtSetPub(CRYPT_ECDH_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPub((BSL_Param *)param, ctx, CRYPT_PKEY_ECDH);
};

int32_t CRYPT_SM2_DefPkeyMgmtSetPub(CRYPT_SM2_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPub((BSL_Param *)param, ctx, CRYPT_PKEY_SM2);
};

int32_t CRYPT_PAILLIER_DefPkeyMgmtSetPub(CRYPT_PAILLIER_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPub((BSL_Param *)param, ctx, CRYPT_PKEY_PAILLIER);
};

// set prv
int32_t CRYPT_DSA_DefPkeyMgmtSetPrv(CRYPT_DSA_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPrv((BSL_Param *)param, ctx, CRYPT_PKEY_DSA);
}

int32_t CRYPT_ED25519_DefPkeyMgmtSetPrv(CRYPT_CURVE25519_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPrv((BSL_Param *)param, ctx, CRYPT_PKEY_ED25519);
}

int32_t CRYPT_X25519_DefPkeyMgmtSetPrv(CRYPT_CURVE25519_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPrv((BSL_Param *)param, ctx, CRYPT_PKEY_X25519);
}

int32_t CRYPT_RSA_DefPkeyMgmtSetPrv(CRYPT_RSA_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPrv((BSL_Param *)param, ctx, CRYPT_PKEY_RSA);
}

int32_t CRYPT_DH_DefPkeyMgmtSetPrv(CRYPT_DH_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPrv((BSL_Param *)param, ctx, CRYPT_PKEY_DH);
}

int32_t CRYPT_ECDSA_DefPkeyMgmtSetPrv(CRYPT_ECDSA_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPrv((BSL_Param *)param, ctx, CRYPT_PKEY_ECDSA);
}

int32_t CRYPT_ECDH_DefPkeyMgmtSetPrv(CRYPT_ECDH_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPrv((BSL_Param *)param, ctx, CRYPT_PKEY_ECDH);
}

int32_t CRYPT_SM2_DefPkeyMgmtSetPrv(CRYPT_SM2_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPrv((BSL_Param *)param, ctx, CRYPT_PKEY_SM2);
}

int32_t CRYPT_PAILLIER_DefPkeyMgmtSetPrv(CRYPT_PAILLIER_Ctx *ctx, const BSL_Param *param)
{
    return CvtBslParamAndSetPrv((BSL_Param *)param, ctx, CRYPT_PKEY_PAILLIER);
}

// get pub
int32_t CRYPT_DSA_DefPkeyMgmtGetPub(const CRYPT_DSA_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPub(param, ctx, CRYPT_PKEY_DSA);
}

int32_t CRYPT_ED25519_DefPkeyMgmtGetPub(const CRYPT_CURVE25519_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPub(param, ctx, CRYPT_PKEY_ED25519);
}

int32_t CRYPT_X25519_DefPkeyMgmtGetPub(const CRYPT_CURVE25519_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPub(param, ctx, CRYPT_PKEY_X25519);
}

int32_t CRYPT_RSA_DefPkeyMgmtGetPub(const CRYPT_RSA_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPub(param, ctx, CRYPT_PKEY_RSA);
}

int32_t CRYPT_DH_DefPkeyMgmtGetPub(const CRYPT_DH_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPub(param, ctx, CRYPT_PKEY_DH);
}

int32_t CRYPT_ECDSA_DefPkeyMgmtGetPub(const CRYPT_ECDSA_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPub(param, ctx, CRYPT_PKEY_ECDSA);
}

int32_t CRYPT_ECDH_DefPkeyMgmtGetPub(const CRYPT_ECDH_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPub(param, ctx, CRYPT_PKEY_ECDH);
}

int32_t CRYPT_SM2_DefPkeyMgmtGetPub(const CRYPT_SM2_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPub(param, ctx, CRYPT_PKEY_SM2);
}

int32_t CRYPT_PAILLIER_DefPkeyMgmtGetPub(const CRYPT_PAILLIER_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPub(param, ctx, CRYPT_PKEY_PAILLIER);
}

// get prv
int32_t CRYPT_DSA_DefPkeyMgmtGetPrv(const CRYPT_DSA_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPrv(param, ctx, CRYPT_PKEY_DSA);
}

int32_t CRYPT_ED25519_DefPkeyMgmtGetPrv(const CRYPT_CURVE25519_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPrv(param, ctx, CRYPT_PKEY_ED25519);
}

int32_t CRYPT_X25519_DefPkeyMgmtGetPrv(const CRYPT_CURVE25519_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPrv(param, ctx, CRYPT_PKEY_X25519);
}

int32_t CRYPT_RSA_DefPkeyMgmtGetPrv(const CRYPT_RSA_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPrv(param, ctx, CRYPT_PKEY_RSA);
}

int32_t CRYPT_DH_DefPkeyMgmtGetPrv(const CRYPT_DH_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPrv(param, ctx, CRYPT_PKEY_DH);
}

int32_t CRYPT_ECDSA_DefPkeyMgmtGetPrv(const CRYPT_ECDSA_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPrv(param, ctx, CRYPT_PKEY_ECDSA);
}

int32_t CRYPT_ECDH_DefPkeyMgmtGetPrv(const CRYPT_ECDH_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPrv(param, ctx, CRYPT_PKEY_ECDH);
}

int32_t CRYPT_SM2_DefPkeyMgmtGetPrv(const CRYPT_SM2_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPrv(param, ctx, CRYPT_PKEY_SM2);
}

int32_t CRYPT_PAILLIER_DefPkeyMgmtGetPrv(const CRYPT_PAILLIER_Ctx *ctx, BSL_Param *param)
{
    return CvtBslParamAndGetPrv(param, ctx, CRYPT_PKEY_PAILLIER);
}


const CRYPT_EAL_Func g_defKeyMgmtDsa[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, CRYPT_EAL_DefPkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, CRYPT_DSA_DefPkeyMgmtSetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, CRYPT_DSA_DefPkeyMgmtGetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, CRYPT_DSA_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, CRYPT_DSA_DefPkeyMgmtSetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, CRYPT_DSA_DefPkeyMgmtSetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, CRYPT_DSA_DefPkeyMgmtGetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, CRYPT_DSA_DefPkeyMgmtGetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, CRYPT_DSA_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, CRYPT_DSA_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_COPYPARAM, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, CRYPT_DSA_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, CRYPT_DSA_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defKeyMgmtEd25519[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, CRYPT_EAL_DefPkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, CRYPT_ED25519_GenKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, CRYPT_ED25519_DefPkeyMgmtSetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, CRYPT_ED25519_DefPkeyMgmtSetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, CRYPT_ED25519_DefPkeyMgmtGetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, CRYPT_ED25519_DefPkeyMgmtGetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, CRYPT_CURVE25519_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, CRYPT_CURVE25519_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_COPYPARAM, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, CRYPT_CURVE25519_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, CRYPT_CURVE25519_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defKeyMgmtX25519[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, CRYPT_EAL_DefPkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, CRYPT_X25519_GenKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, CRYPT_X25519_DefPkeyMgmtSetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, CRYPT_X25519_DefPkeyMgmtSetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, CRYPT_X25519_DefPkeyMgmtGetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, CRYPT_X25519_DefPkeyMgmtGetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, CRYPT_CURVE25519_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, CRYPT_CURVE25519_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_COPYPARAM, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, CRYPT_CURVE25519_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, CRYPT_CURVE25519_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defKeyMgmtRsa[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, CRYPT_EAL_DefPkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, CRYPT_RSA_DefPkeyMgmtSetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, CRYPT_RSA_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, CRYPT_RSA_DefPkeyMgmtSetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, CRYPT_RSA_DefPkeyMgmtSetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, CRYPT_RSA_DefPkeyMgmtGetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, CRYPT_RSA_DefPkeyMgmtGetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, CRYPT_RSA_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, CRYPT_RSA_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_COPYPARAM, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, CRYPT_RSA_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, CRYPT_RSA_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defKeyMgmtDh[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, CRYPT_EAL_DefPkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, CRYPT_DH_DefPkeyMgmtSetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, CRYPT_DH_DefPkeyMgmtGetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, CRYPT_DH_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, CRYPT_DH_DefPkeyMgmtSetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, CRYPT_DH_DefPkeyMgmtSetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, CRYPT_DH_DefPkeyMgmtGetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, CRYPT_DH_DefPkeyMgmtGetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, CRYPT_DH_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, CRYPT_DH_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_COPYPARAM, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, CRYPT_DH_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, CRYPT_DH_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defKeyMgmtEcdsa[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, CRYPT_EAL_DefPkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, CRYPT_ECDSA_DefPkeyMgmtSetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, CRYPT_ECDSA_DefPkeyMgmtGetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, CRYPT_ECDSA_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, CRYPT_ECDSA_DefPkeyMgmtSetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, CRYPT_ECDSA_DefPkeyMgmtSetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, CRYPT_ECDSA_DefPkeyMgmtGetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, CRYPT_ECDSA_DefPkeyMgmtGetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, CRYPT_ECDSA_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, CRYPT_ECDSA_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_COPYPARAM, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, CRYPT_ECDSA_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, CRYPT_ECDSA_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defKeyMgmtEcdh[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, CRYPT_EAL_DefPkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, CRYPT_ECDH_DefPkeyMgmtSetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, CRYPT_ECDH_DefPkeyMgmtGetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, CRYPT_ECDH_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, CRYPT_ECDH_DefPkeyMgmtSetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, CRYPT_ECDH_DefPkeyMgmtSetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, CRYPT_ECDH_DefPkeyMgmtGetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, CRYPT_ECDH_DefPkeyMgmtGetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, CRYPT_ECDH_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, CRYPT_ECDH_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_COPYPARAM, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, CRYPT_ECDH_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, CRYPT_ECDH_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defKeyMgmtSm2[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, CRYPT_EAL_DefPkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, CRYPT_SM2_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, CRYPT_SM2_DefPkeyMgmtSetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, CRYPT_SM2_DefPkeyMgmtSetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, CRYPT_SM2_DefPkeyMgmtGetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, CRYPT_SM2_DefPkeyMgmtGetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, CRYPT_SM2_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, CRYPT_SM2_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_COPYPARAM, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, CRYPT_SM2_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, CRYPT_SM2_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defKeyMgmtPaillier[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, CRYPT_EAL_DefPkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, CRYPT_PAILLIER_DefPkeyMgmtSetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, CRYPT_PAILLIER_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, CRYPT_PAILLIER_DefPkeyMgmtSetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, CRYPT_PAILLIER_DefPkeyMgmtSetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, CRYPT_PAILLIER_DefPkeyMgmtGetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, CRYPT_PAILLIER_DefPkeyMgmtGetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, CRYPT_PAILLIER_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_COPYPARAM, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, CRYPT_PAILLIER_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, CRYPT_PAILLIER_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_PROVIDER */