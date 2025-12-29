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
#ifdef HITLS_CRYPTO_ECC

#include <stdbool.h>
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "crypt_util_ctrl.h"
#include "securec.h"
#include "sal_atomic.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_bn.h"
#include "crypt_ecc.h"
#include "ecc_local.h"
#include "crypt_ecc_pkey.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

typedef struct {
    const char *name;           /* elliptic curve NIST name */
    CRYPT_PKEY_ParaId id;       /* elliptic curve ID */
} EC_NAME;

void ECC_FreeCtx(ECC_Pkey *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int ret = 0;
    BSL_SAL_AtomicDownReferences(&(ctx->references), &ret);
    if (ret > 0) {
        return;
    }
    BSL_SAL_ReferencesFree(&(ctx->references));
    BN_Destroy(ctx->prvkey);
    ECC_FreePoint(ctx->pubkey);
    ctx->pubkey = NULL;
    ECC_FreePara(ctx->para);
    ctx->para = NULL;
    BSL_SAL_Free(ctx->mdAttr);
    BSL_SAL_Free(ctx);
}

ECC_Pkey *ECC_DupCtx(ECC_Pkey *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    ECC_Pkey *newCtx = BSL_SAL_Calloc(1u, sizeof(ECC_Pkey));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    newCtx->useCofactorMode = ctx->useCofactorMode;
    newCtx->pointFormat = ctx->pointFormat;
    BSL_SAL_ReferencesInit(&(newCtx->references));
    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->prvkey, ctx->prvkey, BN_Dup(ctx->prvkey), CRYPT_MEM_ALLOC_FAIL);

    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->pubkey, ctx->pubkey, ECC_DupPoint(ctx->pubkey), CRYPT_MEM_ALLOC_FAIL);

    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->para, ctx->para, ECC_DupPara(ctx->para), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->mdAttr, ctx->mdAttr, BSL_SAL_Dump(ctx->mdAttr, strlen(ctx->mdAttr) + 1),
        CRYPT_MEM_ALLOC_FAIL);
    newCtx->libCtx = ctx->libCtx;
    newCtx->flag = ctx->flag;
    return newCtx;

ERR:
    ECC_FreeCtx(newCtx);
    return NULL;
}

// GetBits applies to both public and private keys.
// The public key requires the largest space. Therefore, the public key space prevails.
uint32_t ECC_PkeyGetBits(const ECC_Pkey *ctx)
{
    if ((ctx == NULL) || (ctx->para == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }

    // The length of ECC_ParaBits is internally specified and can ensure that the length is not 0. 1 byte = 8 bits.
    uint32_t bytes = ((ECC_ParaBits(ctx->para) - 1) / 8) + 1;

    // The public key contains 2 coordinates. The public key flag occupies is 1 byte. 1 byte = 8 bits.
    return (bytes * 2 + 1) * 8;
}

int32_t ECC_PkeySetPrvKey(ECC_Pkey *ctx, const CRYPT_EccPrv *prv)
{
    if ((ctx == NULL) || (ctx->para == NULL) || (prv == NULL) || (prv->data == NULL) || (prv->len == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret;
    BN_BigNum *paraN = ECC_GetParaN(ctx->para);
    BN_BigNum *newPrvKey = BN_Create(ECC_ParaBits(ctx->para));
    if ((paraN == NULL) || (newPrvKey == NULL)) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = BN_Bin2Bn(newPrvKey, prv->data, prv->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (ctx->para->id == CRYPT_ECC_SM2) {
        (void)BN_SubLimb(paraN, paraN, 1);
    }
    if (BN_IsZero(newPrvKey) || (BN_Cmp(newPrvKey, paraN)) >= 0) {
        ret = CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    BN_Destroy(ctx->prvkey);
    ctx->prvkey = newPrvKey;
    BN_Destroy(paraN);
    return CRYPT_SUCCESS;

ERR:
    BN_Destroy(newPrvKey);
    BN_Destroy(paraN);
    return ret;
}

/**
 * In NIST.SP.800-56 Ar3, the FFC Full Public-Key Validation Routine needs to check nQ = Ø.
 * For performance considerations, we perform Partial public-key Validation (Section 5.6.2.3.4) when
 * setting the Public Key.
*/
int32_t ECC_PkeySetPubKey(ECC_Pkey *ctx, const CRYPT_EccPub *pub)
{
    if ((ctx == NULL) || (ctx->para == NULL) || (pub == NULL) || (pub->data == NULL) || (pub->len == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ECC_Point *newPubKey = ECC_NewPoint(ctx->para);
    if (newPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = ECC_DecodePoint(ctx->para, newPubKey, pub->data, pub->len);
    if (ret == CRYPT_SUCCESS) {
        ECC_FreePoint(ctx->pubkey);
        ctx->pubkey = newPubKey;
        return ret;
    }
    ECC_FreePoint(newPubKey);
    return ret;
}

int32_t ECC_PkeyGetPrvKey(const ECC_Pkey *ctx, CRYPT_EccPrv *prv)
{
    if ((ctx == NULL) || (prv == NULL) || (prv->data == NULL) || (prv->len == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->prvkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_EMPTY_KEY);
        return CRYPT_ECC_PKEY_ERR_EMPTY_KEY;
    }

    return BN_Bn2Bin(ctx->prvkey, prv->data, &prv->len);
}

int32_t ECC_PkeyGetPubKey(const ECC_Pkey *ctx, CRYPT_EccPub *pub)
{
    if ((ctx == NULL) || (ctx->para == NULL) || (pub == NULL) || (pub->data == NULL) || (pub->len == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->pubkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_EMPTY_KEY);
        return CRYPT_ECC_PKEY_ERR_EMPTY_KEY;
    }

    return ECC_EncodePoint(ctx->para, ctx->pubkey, pub->data, &pub->len, ctx->pointFormat);
}

#ifdef HITLS_BSL_PARAMS
int32_t ECC_PkeySetPrvKeyEx(ECC_Pkey *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_EccPrv prv = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_EC_PRVKEY, &prv.data, &prv.len);
    return ECC_PkeySetPrvKey(ctx, &prv);
}

int32_t ECC_PkeySetPubKeyEx(ECC_Pkey *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_EccPub pub = {0};
    if (GetConstParamValue(para, CRYPT_PARAM_EC_PUBKEY, &pub.data, &pub.len) == NULL) {
        (void)GetConstParamValue(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY, (uint8_t **)&pub.data, &pub.len);
    }
    return ECC_PkeySetPubKey(ctx, &pub);
}

int32_t ECC_PkeyGetPrvKeyEx(const ECC_Pkey *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_EccPrv prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_EC_PRVKEY, &prv.data, &(prv.len));
    int32_t ret = ECC_PkeyGetPrvKey(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPrv->useLen = prv.len;
    return CRYPT_SUCCESS;
}

int32_t ECC_PkeyGetPubKeyEx(const ECC_Pkey *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_EccPub pub = {0};
    BSL_Param *paramPub = GetParamValue(para, CRYPT_PARAM_EC_PUBKEY, &pub.data, &(pub.len));
    if (paramPub == NULL) {
        paramPub = GetParamValue(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY, &pub.data, &(pub.len));
    }
    int32_t ret = ECC_PkeyGetPubKey(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPub->useLen = pub.len;
    return CRYPT_SUCCESS;
}
#endif

static int32_t GenPrivateKey(ECC_Pkey *ctx)
{
    int32_t ret = CRYPT_SUCCESS;
    uint32_t tryCount = 0;
    uint32_t paraBits = ECC_ParaBits(ctx->para);
    BN_BigNum *paraN = NULL;
    if (ctx->para->id == CRYPT_ECC_SM2) {
        paraN = BN_Create(paraBits);
        if (paraN == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        (void)BN_SubLimb(paraN, ctx->para->n, 1);
    } else {
        paraN = ctx->para->n;
    }
    if (ctx->prvkey == NULL) {
        ctx->prvkey = BN_Create(paraBits);
        if (ctx->prvkey == NULL) {
            ret = CRYPT_MEM_ALLOC_FAIL;
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            goto EXIT;
        }
    }
    do {
        ret = BN_RandRangeEx(ctx->libCtx, ctx->prvkey, paraN);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        tryCount += 1;
    } while ((BN_IsZero(ctx->prvkey) == true) && (tryCount < CRYPT_ECC_TRY_MAX_CNT));

    if (tryCount == CRYPT_ECC_TRY_MAX_CNT) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_TRY_CNT);
        ret = CRYPT_ECC_PKEY_ERR_TRY_CNT;
    }
EXIT:
    if (paraN != ctx->para->n) {
        BN_Destroy(paraN);
    }
    return ret;
}

int32_t ECC_GenPublicKey(ECC_Pkey *ctx)
{
    if (ctx->pubkey != NULL) {
        return CRYPT_SUCCESS;
    }
    ctx->pubkey = ECC_NewPoint(ctx->para);
    if (ctx->pubkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = ECC_PointMul(ctx->para, ctx->pubkey, ctx->prvkey, NULL);
    if (ret != CRYPT_SUCCESS) {
        ECC_FreePoint(ctx->pubkey);
        ctx->pubkey = NULL;
    }
    return ret;
}

static int32_t GenPublicKey(ECC_Pkey *ctx)
{
    if (ctx->prvkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->pubkey == NULL) {
        ctx->pubkey = ECC_NewPoint(ctx->para);
        if (ctx->pubkey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }

    return ECC_PointMul(ctx->para, ctx->pubkey, ctx->prvkey, NULL);
}

int32_t ECC_PkeyGen(ECC_Pkey *ctx)
{
    if ((ctx == NULL) || (ctx->para == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = GenPrivateKey(ctx);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }

    ret = GenPublicKey(ctx);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }

    return CRYPT_SUCCESS;
ERR:
    BN_Zeroize(ctx->prvkey);
    BN_Destroy(ctx->prvkey);
    ctx->prvkey = NULL;
    ECC_FreePoint(ctx->pubkey);
    ctx->pubkey = NULL;
    return ret;
}

#ifdef HITLS_CRYPTO_ECC_CHECK

static int32_t EccKeyPairCheck(const ECC_Pkey *pub, const ECC_Pkey *prv)
{
    int32_t ret;
    if (prv == NULL || pub == NULL || pub->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->pubkey == NULL || prv->prvkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_EMPTY_KEY);
        return CRYPT_ECC_PKEY_ERR_EMPTY_KEY;
    }
    ECC_Point *point = ECC_NewPoint(pub->para);
    if (point == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = ECC_PointMul(pub->para, point, prv->prvkey, NULL);
    if (ret != CRYPT_SUCCESS) {
        ECC_FreePoint(point);
        return ret;
    }
    if (ECC_PointCmp(pub->para, point, pub->pubkey) != 0) {
        ret = CRYPT_ECC_PAIRWISE_CHECK_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
    }
    ECC_FreePoint(point);
    return ret;
}

static int32_t EccPrvKeyCheck(const ECC_Pkey *pkey)
{
    if (pkey == NULL || pkey->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->prvkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_EMPTY_KEY);
        return CRYPT_ECC_PKEY_ERR_EMPTY_KEY;
    }
    int32_t ret = CRYPT_SUCCESS;
    BN_BigNum *paraN = ECC_GetParaN(pkey->para);
    if (pkey->para->id == CRYPT_ECC_SM2) {
        (void)BN_SubLimb(paraN, paraN, 1);
        /* GB/T 32918.2-2016 for check sm2 prv key, 0 < key < n - 1 is valid */
        if (BN_IsZero(pkey->prvkey) == true || BN_IsNegative(pkey->prvkey) == true ||
            (BN_Cmp(pkey->prvkey, paraN) >= 0)) {
            ret = CRYPT_ECC_INVALID_PRVKEY;
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_INVALID_PRVKEY);
        }
    } else {
        /* SP800-56a 5.6.2.1.2 for check an ecc private key. 0 < key <= n - 1 is valid. */
        if (BN_IsZero(pkey->prvkey) == true || BN_IsNegative(pkey->prvkey) == true ||
            (BN_Cmp(pkey->prvkey, paraN) >= 0)) {
            ret = CRYPT_ECC_INVALID_PRVKEY;
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_INVALID_PRVKEY);
        }
    }
    BN_Destroy(paraN);
    return ret;
}

int32_t ECC_PkeyCheck(const ECC_Pkey *pkey1, const ECC_Pkey *pkey2, uint32_t checkType)
{
    switch (checkType) {
        case CRYPT_PKEY_CHECK_KEYPAIR:
            return EccKeyPairCheck(pkey1, pkey2);
        case CRYPT_PKEY_CHECK_PRVKEY:
            return EccPrvKeyCheck(pkey1);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
}

#endif // HITLS_CRYPTO_ECC_CHECK

static const char *EcCurveId2nist(CRYPT_PKEY_ParaId id)
{
    static EC_NAME nistCurves[] = {
        {"P-192", CRYPT_ECC_NISTP192},
        {"P-224", CRYPT_ECC_NISTP224},
        {"P-256", CRYPT_ECC_NISTP256},
        {"P-384", CRYPT_ECC_NISTP384},
        {"P-521", CRYPT_ECC_NISTP521}
    };

    for (uint32_t i = 0; i < sizeof(nistCurves) / sizeof(nistCurves[0]); i++) {
        if (nistCurves[i].id == id) {
            return nistCurves[i].name;
        }
    }
    return NULL;
}

static int32_t ECC_GetPubXYBnBin(ECC_Pkey *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx->para == NULL || len != sizeof(CRYPT_Data) || val == NULL || ((CRYPT_Data *)val)->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    int32_t ret;
    uint32_t bits = BN_Bits(ctx->para->p);
    BN_BigNum *x = BN_Create(bits);
    BN_BigNum *y = BN_Create(bits);
    do {
        if (x == NULL || y == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            ret = CRYPT_MEM_ALLOC_FAIL;
            break;
        }
        ret = ECC_GetPoint2Bn(ctx->para, ctx->pubkey, x, y);
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        if (opt == CRYPT_CTRL_GET_ECC_PUB_X_BIN) {
            ret = BN_Bn2Bin(x, ((CRYPT_Data *)val)->data, &((CRYPT_Data *)val)->len);
        } else {
            ret = BN_Bn2Bin(y, ((CRYPT_Data *)val)->data, &((CRYPT_Data *)val)->len);
        }
    } while (0);

    BN_Destroy(x);
    BN_Destroy(y);
    return ret;
}
static uint32_t ECC_GetKeyLen(const ECC_Pkey *ctx)
{
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return BN_Bytes(ctx->para->p);
}

static uint32_t ECC_GetPubKeyLen(const ECC_Pkey *ctx)
{
    uint32_t keylen = ECC_GetKeyLen(ctx);
    if (keylen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return 0;
    }
    if (ctx->pointFormat == CRYPT_POINT_COMPRESSED) {
        return (keylen + 1);
    }
    return (keylen * 2 + 1);
}

static int32_t GetEccName(ECC_Pkey *ctx, void *val, uint32_t len)
{
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const char *name = EcCurveId2nist(ctx->para->id);
    if (name == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (memcpy_s(val, len, name, strlen(name) + 1) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t SetEccPointFormat(ECC_Pkey *ctx, void *val, uint32_t len)
{
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_CTRL_LEN);
        return CRYPT_ECC_PKEY_ERR_CTRL_LEN;
    }
    uint32_t pointFormat = *(uint32_t *)val;
    if (pointFormat >= CRYPT_POINT_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_INVALID_POINT_FORMAT);
        return CRYPT_ECC_PKEY_ERR_INVALID_POINT_FORMAT;
    }
    ctx->pointFormat = pointFormat;
    return CRYPT_SUCCESS;
}

static int32_t GetEccPointFormat(ECC_Pkey *ctx, void *val, uint32_t len)
{
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_CTRL_LEN);
        return CRYPT_ECC_PKEY_ERR_CTRL_LEN;
    }
    *(uint32_t *)val = ctx->pointFormat;
    return CRYPT_SUCCESS;
}

static int32_t SetEccUseCofactorMode(ECC_Pkey *ctx, void *val, uint32_t len)
{
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_CTRL_LEN);
        return CRYPT_ECC_PKEY_ERR_CTRL_LEN;
    }
    ctx->useCofactorMode = *(uint32_t *)val;
    return CRYPT_SUCCESS;
}

static int32_t SetFlag(ECC_Pkey *ctx, const void *val, uint32_t len)
{
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_CTRL_LEN);
        return CRYPT_ECC_PKEY_ERR_CTRL_LEN;
    }
    ctx->flag |= *(const uint32_t *)val;
    return CRYPT_SUCCESS;
}

static int32_t GetFlag(const ECC_Pkey *ctx, void *val, uint32_t len)
{
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_CTRL_LEN);
        return CRYPT_ECC_PKEY_ERR_CTRL_LEN;
    }
    *(uint32_t *)val = ctx->flag;
    return CRYPT_SUCCESS;
}

static int32_t ClearFlag(ECC_Pkey *ctx)
{
    ctx->flag = 0;
    return CRYPT_SUCCESS;
}

int32_t ECC_PkeyCtrl(ECC_Pkey *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL || (val == NULL && opt != CRYPT_CTRL_GEN_ECC_PUBLICKEY)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_GET_ECC_NAME:
            return GetEccName(ctx, val, len);
        case CRYPT_CTRL_GET_ECC_PUB_X_BIN:
        case CRYPT_CTRL_GET_ECC_PUB_Y_BIN:
            return ECC_GetPubXYBnBin(ctx, opt, val, len);
        case CRYPT_CTRL_SET_ECC_POINT_FORMAT:
            return SetEccPointFormat(ctx, val, len);
        case CRYPT_CTRL_GET_ECC_POINT_FORMAT:
            return GetEccPointFormat(ctx, val, len);
        case CRYPT_CTRL_SET_ECC_USE_COFACTOR_MODE:
            return SetEccUseCofactorMode(ctx, val, len);
        case CRYPT_CTRL_GEN_ECC_PUBLICKEY:
            return GenPublicKey(ctx);
        case CRYPT_CTRL_GET_ECC_ORDER_BITS:
        case CRYPT_CTRL_GET_PUB_KEY_BITS:
            return CRYPT_CTRL_GetNum32(ctx->para == NULL ? 0 : BN_Bits(ctx->para->n), val, len);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            return CRYPT_CTRL_GET_NUM32_EX(ECC_GetPubKeyLen, ctx, val, len);
        case CRYPT_CTRL_GET_PRVKEY_LEN:
        case CRYPT_CTRL_GET_SHARED_KEY_LEN:
            return CRYPT_CTRL_GET_NUM32_EX(ECC_GetKeyLen, ctx, val, len);
        case CRYPT_CTRL_UP_REFERENCES:
            return BSL_SAL_AtomicRefUpCtrl(&(ctx->references), val, len);
        case CRYPT_CTRL_SET_FLAG:
            return SetFlag(ctx, val, len);
        case CRYPT_CTRL_GET_FLAG:
            return GetFlag(ctx, val, len);
        case CRYPT_CTRL_CLR_FLAG:
            return ClearFlag(ctx);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION);
            return CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION;
    }
}

ECC_Pkey *ECC_PkeyNewCtx(CRYPT_PKEY_ParaId id)
{
    ECC_Para *para = ECC_NewPara(id);
    if (para == NULL) {
        return NULL;
    }
    ECC_Pkey *key = BSL_SAL_Calloc(1u, sizeof(ECC_Pkey));
    if (key == NULL) {
        ECC_FreePara(para);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    key->para = para;
    key->pointFormat = CRYPT_POINT_UNCOMPRESSED;
    BSL_SAL_ReferencesInit(&(key->references));
    return key;
}

#ifdef HITLS_CRYPTO_ECC_CMP
int32_t ECC_PkeyCmp(const ECC_Pkey *a, const ECC_Pkey *b)
{
    RETURN_RET_IF(a == NULL || b == NULL, CRYPT_NULL_INPUT);

    // Compare public keys.
    RETURN_RET_IF(ECC_PointCmp(a->para, a->pubkey, b->pubkey), CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL);

    // Compare parameters.
    RETURN_RET_IF(b->para == NULL || a->para->id != b->para->id, CRYPT_ECC_POINT_ERR_CURVE_ID);

    return CRYPT_SUCCESS;
}
#endif
#endif /* HITLS_CRYPTO_ECC */
