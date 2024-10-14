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

#include "bsl_sal.h"
#include "sal_file.h"
#include "securec.h"
#include "hitls_pkcs12_local.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_x509_errno.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_md.h"
#include "hitls_cert_local.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"

HTILS_PKCS12_SafeBag *HTILS_PKCS12_SafeBagNew()
{
    return BSL_SAL_Malloc(sizeof(HTILS_PKCS12_SafeBag));
}

static void AttributesFree(HTILS_PKCS12_SafeBagAttr *attribute)
{
    if (attribute == NULL) {
        return;
    }

    BSL_SAL_FREE(attribute->attrValue->data);
    BSL_SAL_FREE(attribute->attrValue);
    BSL_SAL_FREE(attribute);
}

void HTILS_PKCS12_AttributesFree(void *attribute)
{
    AttributesFree((HTILS_PKCS12_SafeBagAttr *)attribute);
    return;
}

void HTILS_PKCS12_SafeBagFree(HTILS_PKCS12_SafeBag *safeBag)
{
    if (safeBag == NULL) {
        return;
    }
    BSL_LIST_DeleteAll(safeBag->attributes, HTILS_PKCS12_AttributesFree);
    BSL_SAL_FREE(safeBag->attributes);
    BSL_SAL_CleanseData(safeBag->bag->data, safeBag->bag->dataLen);
    BSL_SAL_FREE(safeBag->bag->data);
    BSL_SAL_FREE(safeBag->bag);
    BSL_SAL_Free(safeBag);
    return;
}

HTILS_PKCS12_MacData *HTILS_PKCS12_P12_MacDataNew(void)
{
    HTILS_PKCS12_MacData *macData = BSL_SAL_Calloc(1u, sizeof(HTILS_PKCS12_MacData));
    if (macData == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    BSL_Buffer *macSalt = BSL_SAL_Calloc(1u, sizeof(BSL_Buffer));
    if (macSalt == NULL) {
        BSL_SAL_Free(macData);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    BSL_Buffer *mac = BSL_SAL_Calloc(1u, sizeof(BSL_Buffer));
    if (mac == NULL) {
        BSL_SAL_Free(macSalt);
        BSL_SAL_Free(mac);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    macData->mac = mac;
    macData->macSalt = macSalt;
    return macData;
}

void HTILS_PKCS12_p12_MacDataFree(HTILS_PKCS12_MacData *macData)
{
    if (macData == NULL) {
        return;
    }

    if (macData->mac != NULL) {
        BSL_SAL_FREE(macData->mac->data);
        BSL_SAL_Free(macData->mac);
    }

    if (macData->macSalt != NULL) {
        BSL_SAL_CleanseData(macData->macSalt->data, macData->macSalt->dataLen);
        BSL_SAL_FREE(macData->macSalt->data);
        BSL_SAL_Free(macData->macSalt);
    }
    BSL_SAL_Free(macData);
}

HTILS_PKCS12_P12Info *HTILS_PKCS12_P12_InfoNew(void)
{
    HTILS_PKCS12_P12Info *p12 = BSL_SAL_Calloc(1u, sizeof(HTILS_PKCS12_P12Info));
    if (p12 == NULL) {
        return NULL;
    }
    HTILS_PKCS12_MacData *macData = HTILS_PKCS12_P12_MacDataNew();
    if (macData == NULL) {
        BSL_SAL_Free(p12);
        return NULL;
    }
    HTILS_PKCS12_Bag *key = BSL_SAL_Calloc(1u, sizeof(HTILS_PKCS12_Bag));
    if (key == NULL) {
        HTILS_PKCS12_p12_MacDataFree(macData);
        BSL_SAL_Free(p12);
        return NULL;
    }
    HTILS_PKCS12_Bag *entityCert = BSL_SAL_Calloc(1u, sizeof(HTILS_PKCS12_Bag));
    if (key == NULL) {
        BSL_SAL_Free(entityCert);
        HTILS_PKCS12_p12_MacDataFree(macData);
        BSL_SAL_Free(p12);
        return NULL;
    }
    BSL_ASN1_List *certList = BSL_LIST_New(sizeof(HTILS_PKCS12_Bag));
    if (certList == NULL) {
        BSL_SAL_Free(entityCert);
        BSL_SAL_Free(key);
        BSL_SAL_Free(p12);
        HTILS_PKCS12_p12_MacDataFree(macData);
        return NULL;
    }
    p12->version = 3; // RFC7292 required the version = 3;
    p12->key = key;
    p12->entityCert = entityCert;
    p12->certList = certList;
    p12->macData = macData;
    return p12;
}

static void CertBagFree(void *value)
{
    if (value == NULL) {
        return;
    }
    HTILS_PKCS12_Bag *bag = (HTILS_PKCS12_Bag *)value;
    HITLS_X509_CertFree(bag->value.cert);
    BSL_LIST_DeleteAll(bag->attributes, HTILS_PKCS12_AttributesFree);
    BSL_SAL_FREE(bag->attributes);
    BSL_SAL_FREE(bag);
}

void HTILS_PKCS12_P12_InfoFree(HTILS_PKCS12_P12Info *p12)
{
    if (p12 == NULL) {
        return;
    }

    HITLS_X509_CertFree(p12->entityCert->value.cert);
    BSL_LIST_DeleteAll(p12->entityCert->attributes, HTILS_PKCS12_AttributesFree);
    BSL_SAL_FREE(p12->entityCert->attributes);
    BSL_SAL_Free(p12->entityCert);

    CRYPT_EAL_PkeyFreeCtx(p12->key->value.key);
    BSL_LIST_DeleteAll(p12->key->attributes, HTILS_PKCS12_AttributesFree);
    BSL_SAL_FREE(p12->key->attributes);
    BSL_SAL_Free(p12->key);

    BSL_LIST_DeleteAll(p12->certList, CertBagFree);
    BSL_SAL_Free(p12->certList);
    HTILS_PKCS12_p12_MacDataFree(p12->macData);
    BSL_SAL_Free(p12);
}

typedef struct {
    CRYPT_MD_AlgId alg;
    uint32_t u;
    uint32_t v;
} Pkcs12KdfParam;

/*
 * The data comes from RFC7292.
 * https://datatracker.ietf.org/doc/html/rfc7292#appendix-B.2
 */
const Pkcs12KdfParam PKCS12KDF_PARAM[] = {
    {.alg = CRYPT_MD_SHA224, .u = 28, .v = 64},
    {.alg = CRYPT_MD_SHA256, .u = 32, .v = 64},
    {.alg = CRYPT_MD_SHA384, .u = 48, .v = 128},
    {.alg = CRYPT_MD_SHA512, .u = 64, .v = 128},
};

const Pkcs12KdfParam *FindKdfParam(CRYPT_MD_AlgId id)
{
    const Pkcs12KdfParam *param = NULL;
    uint32_t num = sizeof(PKCS12KDF_PARAM) / sizeof(PKCS12KDF_PARAM[0]);
    for (uint32_t i = 0; i < num; i++) {
        if (PKCS12KDF_PARAM[i].alg == id) {
            param = &PKCS12KDF_PARAM[i];
            return param;
        }
    }
    return NULL;
}

static int32_t InitKdfParam(const Pkcs12KdfParam *param, uint8_t **D, uint8_t **I, uint8_t **A, uint8_t **B)
{
    *D = BSL_SAL_Malloc(param->v);
    *I = BSL_SAL_Malloc(param->v * 2); // len(I) = 2 * v.
    *A = BSL_SAL_Malloc(param->u);
    *B = BSL_SAL_Malloc(param->v);
    if (*D == NULL || *I == NULL || *A == NULL || *B == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_FREE(*D);
        BSL_SAL_FREE(*I);
        BSL_SAL_FREE(*B);
        BSL_SAL_FREE(*A);
        return BSL_MALLOC_FAIL;
    }
    return HITLS_X509_SUCCESS;
}

static int32_t MacLoop(uint32_t LoopTimes, CRYPT_EAL_MdCTX *ctx, const Pkcs12KdfParam *param, uint8_t *D,
    uint8_t *I, uint8_t *A, uint32_t dataLen)
{
    int32_t ret;
    uint32_t tempLen = param->u;
    /* A = H(H(H(... H(D || I)))) */
    ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_MdUpdate(ctx, D, param->v);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_MdUpdate(ctx, I, param->v * 2); // len(I) = 2 * v.
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_MdFinal(ctx, A, &tempLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_EAL_MdDeinit(ctx);

    for (uint32_t j = 0; j < LoopTimes - 1; j++) {
        ret = CRYPT_EAL_MdInit(ctx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ret = CRYPT_EAL_MdUpdate(ctx, A, dataLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ret = CRYPT_EAL_MdFinal(ctx, A, &dataLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        CRYPT_EAL_MdDeinit(ctx);
    }
    return ret;
}

int32_t HTILS_PKCS12_KDF(BSL_Buffer *output, const uint8_t *pwd, uint32_t pwdLen, HITLS_PKCS12_KDF_IDX id,
    HTILS_PKCS12_MacData *macData)
{
    if (output == NULL || output->data == NULL || macData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }

    if (pwd == NULL && pwdLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }

    uint8_t *salt = macData->macSalt->data;
    uint32_t saltLen = macData->macSalt->dataLen;
    uint32_t n = output->dataLen;
    uint32_t iter = macData->interation;
    uint8_t *key = output->data;

    const Pkcs12KdfParam *param = FindKdfParam((CRYPT_MD_AlgId)macData->alg);
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_ALGO);
        return HITLS_PKCS12_ERR_INVALID_ALGO;
    }
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx((CRYPT_MD_AlgId)macData->alg);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    uint8_t *D = NULL;
    uint8_t *A = NULL;
    uint8_t *B = NULL;
    uint8_t *I = NULL;
    int32_t ret = InitKdfParam(param, &D, &I, &A, &B);
    if (ret != HITLS_X509_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        return ret;
    }

    (void)memset_s(D, param->v, id, param->v);
    (void)memset_s(I, 2 * param->v, 0, 2 * param->v); // we need 2 * v

    /* K = ceiling(s/v) + ceiling(p/v)
     *   = (pwdLen + param->v - 1) / param->v + (saltLen + param->v - 1) / param->v
    */
    uint32_t k = ((pwdLen + saltLen - 2) / param->v) + 2;

    /* I = S||P */
    if (salt != NULL) {
        for (uint32_t i = 0; i < param->v; i++) {
            I[i] = salt[i % saltLen];
        }
    }

    if (pwd != NULL) {
        for (uint32_t i = 0; i < param->v; i++) {
            I[i + param->v] = pwd[i % pwdLen];
        }
    }

    /* C = ceiling(n/u) */
    uint32_t c = (n + param->u - 1) / param->u;
    for (uint32_t i = 0; i < c; i++) {
        ret = MacLoop(iter, ctx, param, D, I, A, param->u);
        if (ret != HITLS_X509_SUCCESS) {
            goto ERR; // has pushed err code.
        }

        uint32_t copyLen = n > param->u ? param->u : n;
        if (memcpy_s(key, n, A, copyLen) != EOK) {
            ret = BSL_MEMCPY_FAIL;
            BSL_ERR_PUSH_ERROR(BSL_MEMCPY_FAIL);
            goto ERR;
        }

        n -= copyLen;
        if (n == 0) {
            goto ERR;
        }
        key = key + copyLen;
        /* Concatenate copies of Ai to create a string B */
        for (uint32_t l = 0; l < param->v; l++) {
            B[l] = A[l % param->u];
        }
        /* I_j = (I_j + B + 1) mod 2^v */
        for (uint32_t m = 0; m < k; m++) {
            uint8_t *tempI = I + m * param->v;
            uint8_t carry = 1;
            for (int32_t r = (uint32_t)param->v - 1; r >= 0; r--) {
                uint8_t temp = tempI[r] + carry;
                carry = temp < tempI[r] ? 1 : 0;
                temp += B[r];
                carry = temp < B[r] ? 1 : 0;
                tempI[r] = temp;
            }
        }
    }

ERR:
    CRYPT_EAL_MdFreeCtx(ctx);
    BSL_SAL_Free(D);
    BSL_SAL_Free(I);
    BSL_SAL_Free(B);
    BSL_SAL_Free(A);
    return ret;
}

static uint32_t GetMacId(BslCid id)
{
    switch (id) {
        case CRYPT_MD_SHA224:
            return CRYPT_MAC_HMAC_SHA224;
        case CRYPT_MD_SHA256:
            return CRYPT_MAC_HMAC_SHA256;
        case CRYPT_MD_SHA384:
            return CRYPT_MAC_HMAC_SHA384;
        case CRYPT_MD_SHA512:
            return CRYPT_MAC_HMAC_SHA512;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_ALGO);
            return HITLS_PKCS12_ERR_INVALID_ALGO;
    }
}

static int32_t Untf8ToUtf16(const uint8_t *src, uint8_t *target, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        if (src[i] > 127) { // the Max ascii < 127.
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PASSWORD);
            return HITLS_PKCS12_ERR_INVALID_PASSWORD;
        }
        target[2 * i + 1] = src[i]; // we need 2 space, [0,0] -> after encode = [0, data];
    }
    return HITLS_X509_SUCCESS;
}

static int32_t TransCodePwd(BSL_Buffer *pwd, uint8_t **transcoded, uint32_t *transcodedLen)
{
    if (pwd == NULL || pwd->data == NULL) {
        *transcodedLen = 0;
        return HITLS_X509_SUCCESS;
    }

    uint32_t outputLen = 2 * pwd->dataLen + 2; // encodeLen = 2 * len, and two zeros at the end.
    uint8_t *output = BSL_SAL_Calloc(1u, outputLen);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = Untf8ToUtf16(pwd->data, output, pwd->dataLen);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_SAL_CleanseData(output, outputLen);
        BSL_SAL_FREE(output);
        return ret; // has pushed err code.
    }
    *transcodedLen = outputLen;
    *transcoded = output;
    return HITLS_X509_SUCCESS;
}

static int32_t GetHmacKey(BSL_Buffer *pwd, uint32_t macSize, HTILS_PKCS12_MacData *macData, uint8_t **keyData)
{
    uint32_t temPwdLen = 0;
    uint8_t *temPwd = NULL;
    int32_t ret = TransCodePwd(pwd, &temPwd, &temPwdLen);
    if (ret != HITLS_X509_SUCCESS) {
        return ret; // has pushed err code.
    }

    uint8_t *key = BSL_SAL_Malloc(macSize);
    if (key == NULL) {
        BSL_SAL_CleanseData(temPwd, temPwdLen);
        BSL_SAL_FREE(temPwd);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    BSL_Buffer keyBuffer = {key, macSize};
    ret = HTILS_PKCS12_KDF(&keyBuffer, temPwd, temPwdLen, HITLS_PKCS12_KDF_MACKEY_ID, macData);
    BSL_SAL_CleanseData(temPwd, temPwdLen);
    BSL_SAL_FREE(temPwd);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_SAL_CleanseData(key, macSize);
        BSL_SAL_FREE(key);
        return ret;
    }
    *keyData = key;
    return ret;
}

static int32_t ParamCheckAndInit(HTILS_PKCS12_MacData *macData, BSL_Buffer *pwd)
{
    if (macData == NULL || macData->macSalt == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }

    if (pwd != NULL && pwd->data == NULL && pwd->dataLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (macData->interation < 1000) { // The nist sp800-132 required the minimum iteration count = 1000.
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_INTERATION);
        return HITLS_PKCS12_ERR_INVALID_INTERATION;
    }

    if (macData->macSalt->data == NULL) {
        if (macData->macSalt->dataLen == 0) {
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SALTLEN);
            return HITLS_PKCS12_ERR_INVALID_SALTLEN;
        }
        uint8_t *salt = BSL_SAL_Malloc(macData->macSalt->dataLen);
        if (salt == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        int32_t ret = CRYPT_EAL_Randbytes(salt, macData->macSalt->dataLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(salt);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        macData->macSalt->data = salt;
    }
    return HITLS_X509_SUCCESS;
}

int32_t HTILS_PKCS12_CalMac(BSL_Buffer *output, BSL_Buffer *pwd, BSL_Buffer *initData, HTILS_PKCS12_MacData *macData)
{
    int32_t ret = ParamCheckAndInit(macData, pwd);
    if (ret != HITLS_X509_SUCCESS) {
        return ret;
    }
    uint32_t macId = GetMacId(macData->alg);
    uint32_t macSize = CRYPT_EAL_MdGetDigestSize((CRYPT_MD_AlgId)macData->alg);
    if (macId == BSL_CID_UNKNOWN || macSize == 0) {
        return HITLS_PKCS12_ERR_INVALID_ALGO; // has pushed errcode.
    }
    uint8_t *keyData = NULL;
    ret = GetHmacKey(pwd, macSize, macData, &keyData);
    if (ret != HITLS_X509_SUCCESS) {
        return ret; // has pushed err code.
    }

    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(macId);
    if (ctx == NULL) {
        BSL_SAL_CleanseData(keyData, macSize);
        BSL_SAL_FREE(keyData);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return ret;
    }
    ret = CRYPT_EAL_MacInit(ctx, keyData, macSize);
    BSL_SAL_CleanseData(keyData, macSize);
    BSL_SAL_FREE(keyData);
    if (ret != HITLS_X509_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_MacUpdate(ctx, initData->data, initData->dataLen);
    if (ret != HITLS_X509_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *temp = BSL_SAL_Malloc(macSize);
    if (temp == NULL) {
        CRYPT_EAL_MacFreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t tempLen = macSize;
    ret = CRYPT_EAL_MacFinal(ctx, temp, &tempLen);
    CRYPT_EAL_MacFreeCtx(ctx);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_SAL_FREE(temp);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    output->data = temp;
    output->dataLen = tempLen;
    return ret;
}
