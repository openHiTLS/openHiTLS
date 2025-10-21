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
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "eal_common.h"

#ifdef HITLS_CRYPTO_RSA
#define MAX_RSA_KEY_LEN 1024
#define MAX_RSA_PUB_KEY_PARA_CNT 2
#define MAX_RSA_PRV_KEY_PARA_CNT 8
#endif
#ifdef HITLS_CRYPTO_DSA
#define MAX_DSA_KEY_LEN 1024
#define MAX_DSA_PARA_SIZE 3
#endif
#ifdef HITLS_CRYPTO_DH
#define MAX_DH_KEY_LEN 1024
#endif
#ifdef HITLS_CRYPTO_ED25519
#define MAX_ED25519_KEY_LEN 32
#endif
#ifdef HITLS_CRYPTO_X25519
#define MAX_X25519_KEY_LEN 32
#endif
#ifdef HITLS_CRYPTO_ED448
#define MAX_ED448_KEY_LEN 57
#endif
#ifdef HITLS_CRYPTO_X448
#define MAX_X448_KEY_LEN 56
#endif
#ifdef HITLS_CRYPTO_SM2
#define MAX_SM2_PUB_KEY_LEN 65
#define MAX_SM2_PRV_KEY_LEN 32
#endif
#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_ECDH)
#define MAX_ECC_PUB_KEY_LEN 140
#define MAX_ECC_PRV_KEY_LEN 66
#define MAX_ECC_PARA_LEN 66
#define MAX_ECC_PARA_CNT 7
#endif

#ifdef HITLS_CRYPTO_RSA
static int32_t CryptRsaPkeyNewPub(CRYPT_EAL_PkeyPub *pkeyPub)
{
    uint8_t *buff = BSL_SAL_Calloc(MAX_RSA_KEY_LEN * MAX_RSA_PUB_KEY_PARA_CNT, sizeof(uint8_t));
    if (buff == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    pkeyPub->key.rsaPub.e = buff;
    pkeyPub->key.rsaPub.eLen = MAX_RSA_KEY_LEN;
    pkeyPub->key.rsaPub.n = buff + MAX_RSA_KEY_LEN;
    pkeyPub->key.rsaPub.nLen = MAX_RSA_KEY_LEN;
    return CRYPT_SUCCESS;
}

static int32_t CryptRsaPkeyNewPrv(CRYPT_EAL_PkeyPrv *pkeyPrv)
{
    uint8_t *buff = BSL_SAL_Calloc(MAX_RSA_KEY_LEN * MAX_RSA_PRV_KEY_PARA_CNT, sizeof(uint8_t));
    if (buff == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    pkeyPrv->key.rsaPrv.d = buff;
    pkeyPrv->key.rsaPrv.dLen = MAX_RSA_KEY_LEN;
    pkeyPrv->key.rsaPrv.n = buff + MAX_RSA_KEY_LEN;
    pkeyPrv->key.rsaPrv.nLen = MAX_RSA_KEY_LEN;
    pkeyPrv->key.rsaPrv.p = buff + 2 * MAX_RSA_KEY_LEN; // 2 denote the third para
    pkeyPrv->key.rsaPrv.pLen = MAX_RSA_KEY_LEN;
    pkeyPrv->key.rsaPrv.q = buff + 3 * MAX_RSA_KEY_LEN; // 3 denote the fourth para
    pkeyPrv->key.rsaPrv.qLen = MAX_RSA_KEY_LEN;
    pkeyPrv->key.rsaPrv.dP = buff + 4 * MAX_RSA_KEY_LEN; // 4 denote the fifth para
    pkeyPrv->key.rsaPrv.dPLen = MAX_RSA_KEY_LEN;
    pkeyPrv->key.rsaPrv.dQ = buff + 5 * MAX_RSA_KEY_LEN; // 5 denote the sixth para
    pkeyPrv->key.rsaPrv.dQLen = MAX_RSA_KEY_LEN;
    pkeyPrv->key.rsaPrv.qInv = buff + 6 * MAX_RSA_KEY_LEN; // 6 denote the seventh para
    pkeyPrv->key.rsaPrv.qInvLen = MAX_RSA_KEY_LEN;
    pkeyPrv->key.rsaPrv.e = buff + 7 * MAX_RSA_KEY_LEN; // 7 denote the eighth para
    pkeyPrv->key.rsaPrv.eLen = MAX_RSA_KEY_LEN;
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_RSA

#if defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_DH) ||                \
    defined(HITLS_CRYPTO_CURVE25519) || defined(HITLS_CRYPTO_CURVE448) || defined(HITLS_CRYPTO_ECDSA) || \
    defined(HITLS_CRYPTO_ECDH) || defined(HITLS_CRYPTO_SM2)
static int32_t CryptMallocOnePara(uint8_t **para, uint32_t *paraLen, uint32_t buffLen)
{
    uint8_t *buff = BSL_SAL_Calloc(buffLen, sizeof(uint8_t));
    if (buff == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    *para = buff;
    *paraLen = buffLen;
    return CRYPT_SUCCESS;
}
#endif

static int32_t CryptPkeyNewPub(CRYPT_EAL_PkeyPub *pkeyPub)
{
    switch (pkeyPub->id) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA:
            return CryptRsaPkeyNewPub(pkeyPub);
#endif
#ifdef HITLS_CRYPTO_DSA
        case CRYPT_PKEY_DSA:
            return CryptMallocOnePara(&pkeyPub->key.dsaPub.data, &pkeyPub->key.dsaPub.len, MAX_DSA_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_DH
        case CRYPT_PKEY_DH:
            return CryptMallocOnePara(&pkeyPub->key.dhPub.data, &pkeyPub->key.dhPub.len, MAX_DH_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_ED25519
        case CRYPT_PKEY_ED25519:
            return CryptMallocOnePara(&pkeyPub->key.curve25519Pub.data, &pkeyPub->key.curve25519Pub.len,
                MAX_ED25519_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_X25519
        case CRYPT_PKEY_X25519:
            return CryptMallocOnePara(&pkeyPub->key.curve25519Pub.data, &pkeyPub->key.curve25519Pub.len,
                MAX_X25519_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_ED448
        case CRYPT_PKEY_ED448:
            return CryptMallocOnePara(&pkeyPub->key.curve448Pub.data, &pkeyPub->key.curve448Pub.len, MAX_ED448_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_X448
        case CRYPT_PKEY_X448:
            return CryptMallocOnePara(&pkeyPub->key.curve448Pub.data, &pkeyPub->key.curve448Pub.len, MAX_X448_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_ECDSA
        case CRYPT_PKEY_ECDSA:
            return CryptMallocOnePara(&pkeyPub->key.eccPub.data, &pkeyPub->key.eccPub.len, MAX_ECC_PUB_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_ECDH
        case CRYPT_PKEY_ECDH:
            return CryptMallocOnePara(&pkeyPub->key.eccPub.data, &pkeyPub->key.eccPub.len, MAX_ECC_PUB_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_SM2
        case CRYPT_PKEY_SM2:
            return CryptMallocOnePara(&pkeyPub->key.eccPub.data, &pkeyPub->key.eccPub.len, MAX_SM2_PUB_KEY_LEN);
#endif
        default:
            return CRYPT_NOT_SUPPORT;
    }
}

CRYPT_EAL_PkeyPub *CRYPT_EAL_PkeyNewPub(CRYPT_PKEY_AlgId id)
{
    CRYPT_EAL_PkeyPub *pkeyPub = BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_PkeyPub));
    if (pkeyPub == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    pkeyPub->id = id;
    int32_t ret = CryptPkeyNewPub(pkeyPub);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, ret);
        BSL_SAL_Free(pkeyPub);
        return NULL;
    }
    return pkeyPub;
}

void CRYPT_EAL_PkeyFreePub(CRYPT_EAL_PkeyPub *pubKey)
{
    if (pubKey == NULL) {
        return;
    }
    BSL_SAL_FREE(pubKey->key.dsaPub.data);
    BSL_SAL_Free(pubKey);
}

static int32_t CryptPkeyNewPrv(CRYPT_EAL_PkeyPrv *pkeyPrv)
{
    switch (pkeyPrv->id) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA:
            return CryptRsaPkeyNewPrv(pkeyPrv);
#endif
#ifdef HITLS_CRYPTO_DSA
        case CRYPT_PKEY_DSA:
            return CryptMallocOnePara(&pkeyPrv->key.dsaPrv.data, &pkeyPrv->key.dsaPrv.len, MAX_DSA_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_DH
        case CRYPT_PKEY_DH:
            return CryptMallocOnePara(&pkeyPrv->key.dhPrv.data, &pkeyPrv->key.dhPrv.len, MAX_DH_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_ED25519
        case CRYPT_PKEY_ED25519:
            return CryptMallocOnePara(&pkeyPrv->key.curve25519Prv.data, &pkeyPrv->key.curve25519Prv.len,
                MAX_ED25519_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_X25519
        case CRYPT_PKEY_X25519:
            return CryptMallocOnePara(&pkeyPrv->key.curve25519Prv.data, &pkeyPrv->key.curve25519Prv.len,
                MAX_X25519_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_ED448
        case CRYPT_PKEY_ED448:
            return CryptMallocOnePara(&pkeyPrv->key.curve448Prv.data, &pkeyPrv->key.curve448Prv.len, MAX_ED448_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_X448
        case CRYPT_PKEY_X448:
            return CryptMallocOnePara(&pkeyPrv->key.curve448Prv.data, &pkeyPrv->key.curve448Prv.len, MAX_X448_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_ECDSA
        case CRYPT_PKEY_ECDSA:
            return CryptMallocOnePara(&pkeyPrv->key.eccPrv.data, &pkeyPrv->key.eccPrv.len, MAX_ECC_PRV_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_ECDH
        case CRYPT_PKEY_ECDH:
            return CryptMallocOnePara(&pkeyPrv->key.eccPrv.data, &pkeyPrv->key.eccPrv.len, MAX_ECC_PRV_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_SM2
        case CRYPT_PKEY_SM2:
            return CryptMallocOnePara(&pkeyPrv->key.eccPrv.data, &pkeyPrv->key.eccPrv.len, MAX_SM2_PRV_KEY_LEN);
#endif
        default:
            return CRYPT_NOT_SUPPORT;
    }
}

CRYPT_EAL_PkeyPrv *CRYPT_EAL_PkeyNewPrv(CRYPT_PKEY_AlgId id)
{
    CRYPT_EAL_PkeyPrv *pkeyPrv = BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_PkeyPrv));
    if (pkeyPrv == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    pkeyPrv->id = id;
    int32_t ret = CryptPkeyNewPrv(pkeyPrv);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, ret);
        BSL_SAL_Free(pkeyPrv);
        return NULL;
    }
    return pkeyPrv;
}

void CRYPT_EAL_PkeyFreePrv(CRYPT_EAL_PkeyPrv *prvKey)
{
    if (prvKey == NULL) {
        return;
    }
    BSL_SAL_FREE(prvKey->key.dsaPrv.data);
    BSL_SAL_Free(prvKey);
}

#ifdef HITLS_CRYPTO_DSA
static int32_t CryptDsaPkeyNewPara(CRYPT_EAL_PkeyPara *pkeyPara, uint32_t keyLen)
{
    uint8_t *buff = BSL_SAL_Calloc(keyLen * MAX_DSA_PARA_SIZE, sizeof(uint8_t));
    if (buff == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    pkeyPara->para.dsaPara.p = buff;
    pkeyPara->para.dsaPara.pLen = keyLen;
    pkeyPara->para.dsaPara.q = buff + keyLen;
    pkeyPara->para.dsaPara.qLen = keyLen;
    pkeyPara->para.dsaPara.g = buff + 2 * keyLen;  // 2 denote the third para
    pkeyPara->para.dsaPara.gLen = keyLen;
    return CRYPT_SUCCESS;
}
#endif

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_ECDH)
static int32_t CryptEccPkeyNewPara(CRYPT_EAL_PkeyPara *pkeyPara)
{
    uint8_t *buff = BSL_SAL_Calloc(MAX_ECC_PARA_LEN * MAX_ECC_PARA_CNT, sizeof(uint8_t));
    if (buff == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    pkeyPara->para.eccPara.p = buff;
    pkeyPara->para.eccPara.pLen = MAX_ECC_PARA_LEN;
    pkeyPara->para.eccPara.a = buff + MAX_ECC_PARA_LEN;
    pkeyPara->para.eccPara.aLen = MAX_ECC_PARA_LEN;
    pkeyPara->para.eccPara.b = buff + 2 * MAX_ECC_PARA_LEN;  // 2 denote the third para
    pkeyPara->para.eccPara.bLen = MAX_ECC_PARA_LEN;
    pkeyPara->para.eccPara.n = buff + 3 * MAX_ECC_PARA_LEN;  // 3 denote the fourth para
    pkeyPara->para.eccPara.nLen = MAX_ECC_PARA_LEN;
    pkeyPara->para.eccPara.h = buff + 4 * MAX_ECC_PARA_LEN;  // 4 denote the fifth para
    pkeyPara->para.eccPara.hLen = MAX_ECC_PARA_LEN;
    pkeyPara->para.eccPara.x = buff + 5 * MAX_ECC_PARA_LEN;  // 5 denote the sixth para
    pkeyPara->para.eccPara.xLen = MAX_ECC_PARA_LEN;
    pkeyPara->para.eccPara.y = buff + 6 * MAX_ECC_PARA_LEN;  // 6 denote the seventh para
    pkeyPara->para.eccPara.yLen = MAX_ECC_PARA_LEN;
    return CRYPT_SUCCESS;
}
#endif

static int32_t CryptPkeyNewPara(CRYPT_EAL_PkeyPara *pkeyPara)
{
    switch (pkeyPara->id) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA:
            return CryptMallocOnePara(&pkeyPara->para.rsaPara.e, &pkeyPara->para.rsaPara.eLen, MAX_RSA_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_DSA
        case CRYPT_PKEY_DSA:
            return CryptDsaPkeyNewPara(pkeyPara, MAX_DSA_KEY_LEN);
#endif
#ifdef HITLS_CRYPTO_ECDSA
        case CRYPT_PKEY_ECDSA:
            return CryptEccPkeyNewPara(pkeyPara);
#endif
#ifdef HITLS_CRYPTO_ECDH
        case CRYPT_PKEY_ECDH:
            return CryptEccPkeyNewPara(pkeyPara);
#endif
        default:
            return CRYPT_NOT_SUPPORT;
    }
}

CRYPT_EAL_PkeyPara *CRYPT_EAL_PkeyNewPara(CRYPT_PKEY_AlgId id)
{
    CRYPT_EAL_PkeyPara *pkeyPara = BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_PkeyPara));
    if (pkeyPara == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    pkeyPara->id = id;
    int32_t ret = CryptPkeyNewPara(pkeyPara);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, id, ret);
        BSL_SAL_Free(pkeyPara);
        return NULL;
    }
    return pkeyPara;
}

void CRYPT_EAL_PkeyFreePara(CRYPT_EAL_PkeyPara *para)
{
    if (para == NULL) {
        return;
    }
    BSL_SAL_FREE(para->para.rsaPara.e);
    BSL_SAL_Free(para);
}
#endif
