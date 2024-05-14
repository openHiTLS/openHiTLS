/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CURVE448

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "curve448_local.h"
#include "crypt_util_rand.h"
#include "crypt_utils.h"
#include "crypt_types.h"
#include "crypt_local_types.h"
#include "sal_atomic.h"

CRYPT_CURVE448_Ctx *CRYPT_CURVE448_NewCtx(void)
{
    CRYPT_CURVE448_Ctx *ctx = NULL;
    ctx = (CRYPT_CURVE448_Ctx *)BSL_SAL_Malloc(sizeof(CRYPT_CURVE448_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(CRYPT_CURVE448_Ctx), 0, sizeof(CRYPT_CURVE448_Ctx));

    ctx->keyType = CURVE448_NOKEY;
    ctx->hashMethod = NULL;
    ctx->ctxLen = CURVE448_NO_SET_CTX;
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

CRYPT_CURVE448_Ctx *CRYPT_CURVE448_DupCtx(CRYPT_CURVE448_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_CURVE448_Ctx *newCtx = (CRYPT_CURVE448_Ctx *)BSL_SAL_Calloc(1u, sizeof(CRYPT_CURVE448_Ctx));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memcpy_s(newCtx, sizeof(CRYPT_CURVE448_Ctx), ctx, sizeof(CRYPT_CURVE448_Ctx));
    BSL_SAL_ReferencesInit(&(newCtx->references));
    return newCtx;
}

void CRYPT_CURVE448_FreeCtx(CRYPT_CURVE448_Ctx *pkey)
{
    int ref = 0;
    if (pkey == NULL) {
        return;
    }
    BSL_SAL_AtomicDownReferences(&(pkey->references), &ref);
    if (ref > 0) {
        return;
    }
    BSL_SAL_ReferencesFree(&(pkey->references));
    BSL_SAL_CleanseData((void *)(pkey), sizeof(CRYPT_CURVE448_Ctx));
    BSL_SAL_FREE(pkey);
}

int32_t CRYPT_CURVE448_Ctrl(CRYPT_CURVE448_Ctx *pkey, CRYPT_PkeyCtrl opt, const void *val, uint32_t len)
{
    if (pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (opt == CRYPT_CTRL_SET_ED448_HASH_METHOD) {
        if (len != sizeof(EAL_MdMethod)) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        pkey->hashMethod = (const EAL_MdMethod *)val;

        return CRYPT_SUCCESS;
    }

    if (opt == CRYPT_CTRL_SET_ED448_CONTEXT) {
        if (val == NULL && len != 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
            return CRYPT_NULL_INPUT;
        }
        if (len > ED448_CONTEXT_MAX_LEN) {
            BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_CONTEXT_TOO_LONG);
            return CRYPT_CURVE448_CONTEXT_TOO_LONG;
        }
        if (val != NULL) {
            (void)memcpy_s(pkey->context, sizeof(pkey->context), val, len);
        }
        pkey->ctxLen = len;

        return CRYPT_SUCCESS;
    }

    if (opt == CRYPT_CTRL_SET_ED448_PREHASH) {
        pkey->preHash = true;
        return CRYPT_SUCCESS;
    }

    if (opt == CRYPT_CTRL_UP_REFERENCES) {
        if (val == NULL || len != (uint32_t)sizeof(int)) {
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
            return CRYPT_NULL_INPUT;
        }
        return BSL_SAL_AtomicUpReferences(&(pkey->references), (int *)val);
    }
    BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_UNSUPPORTED_CTRL_OPTION);
    return CRYPT_CURVE448_UNSUPPORTED_CTRL_OPTION;
}

#ifdef HITLS_CRYPTO_ED448
static void ED448GenPubKeyCore(const uint8_t prvKey[ED448_KEY_LEN], uint8_t pubKey[ED448_KEY_LEN])
{
    uint8_t prvKeyLocal[ED448_KEY_LEN];
    (void)memcpy_s(prvKeyLocal, ED448_KEY_LEN, prvKey, ED448_KEY_LEN);
    Scalar s;
    Curve448Point mulBase;

    // setting bits base on rfc8032
    prvKeyLocal[0] &= 0xfc;
    prvKeyLocal[56] = 0; // 56 is last byte
    prvKeyLocal[55] |= 0x80; // 55 is second last byte

    ScalarDecode(&s, prvKeyLocal, ED448_KEY_LEN);

    ScalarDivideBy2(&s, &s);
    ScalarDivideBy2(&s, &s);
    Curve448PrecomputedMulBase(&mulBase, &s);

    Ed448EncodePoint(pubKey, &mulBase);
    BSL_SAL_CleanseData(prvKeyLocal, sizeof(prvKeyLocal));
    BSL_SAL_CleanseData(&s, sizeof(s));
}

static int32_t HashPrvKey(const uint8_t prvKey[ED448_KEY_LEN], uint8_t hash[ED448_SIGN_LEN],
    const EAL_MdMethod *hashMethod)
{
    void *mdCtx = NULL;
    uint32_t hashLen = ED448_SIGN_LEN;
    mdCtx = BSL_SAL_Malloc(hashMethod->ctxSize);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = hashMethod->init(mdCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto end;
    }
    ret = hashMethod->update(mdCtx, prvKey, ED448_KEY_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto end;
    }
    ret = hashMethod->final(mdCtx, hash, &hashLen);

end:
    hashMethod->deinit(mdCtx);
    BSL_SAL_FREE(mdCtx);
    return ret;
}

int32_t CRYPT_ED448_GenKey(CRYPT_CURVE448_Ctx *pkey)
{
    if (pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_NO_HASH_METHOD);
        return CRYPT_CURVE448_NO_HASH_METHOD;
    }

    int32_t ret;
    uint8_t prvKeyHash[ED448_SIGN_LEN];
    ret = CRYPT_Rand(pkey->prvKey, ED448_KEY_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HashPrvKey(pkey->prvKey, prvKeyHash, pkey->hashMethod);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ED448GenPubKeyCore(prvKeyHash, pkey->pubKey);
    pkey->keyType = CURVE448_PRVKEY | CURVE448_PUBKEY;
    BSL_SAL_CleanseData(prvKeyHash, sizeof(prvKeyHash));
    return CRYPT_SUCCESS;
}

static int32_t HashR(const uint8_t *context, uint32_t contextLen, const uint8_t prefix[ED448_KEY_LEN],
    const uint8_t *msg, uint32_t msgLen, bool prehash, uint8_t hash[ED448_SIGN_LEN], const EAL_MdMethod *hashMethod)
{
    void *mdCtx = NULL;
    uint32_t hashLen;
    uint8_t prehashMsg[ED448_PREHASH_MSG_LEN];
    uint8_t dom[2]; // dom has len of 2
    dom[0] = 0;
    dom[1] = (uint8_t)contextLen;
    const char *string = "SigEd448";

    int32_t ret;
    mdCtx = BSL_SAL_Malloc(hashMethod->ctxSize);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (prehash) {
        dom[0] = 1;
        hashLen = ED448_PREHASH_MSG_LEN;
        GOTO_END_IF_FAIL(hashMethod->init(mdCtx));
        GOTO_END_IF_FAIL(hashMethod->update(mdCtx, msg, msgLen));
        GOTO_END_IF_FAIL(hashMethod->final(mdCtx, prehashMsg, &hashLen));
    }
    hashLen = ED448_SIGN_LEN;
    GOTO_END_IF_FAIL(hashMethod->init(mdCtx));

    GOTO_END_IF_FAIL(hashMethod->update(mdCtx, (const uint8_t *)string, 8)); // len of SigEd448 = 8
    GOTO_END_IF_FAIL(hashMethod->update(mdCtx, dom, 2)); // dom has len of 2
    GOTO_END_IF_FAIL(hashMethod->update(mdCtx, context, contextLen));
    GOTO_END_IF_FAIL(hashMethod->update(mdCtx, prefix, ED448_KEY_LEN));
    if (prehash) {
        GOTO_END_IF_FAIL(hashMethod->update(mdCtx, prehashMsg, ED448_PREHASH_MSG_LEN));
    } else {
        GOTO_END_IF_FAIL(hashMethod->update(mdCtx, msg, msgLen));
    }
    GOTO_END_IF_FAIL(hashMethod->final(mdCtx, hash, &hashLen));

end:
    hashMethod->deinit(mdCtx);
    BSL_SAL_FREE(mdCtx);
    return ret;
}

static int32_t HashK(const uint8_t *context, uint32_t contextLen, const uint8_t rB[ED448_KEY_LEN],
    const uint8_t pubKey[ED448_KEY_LEN], const uint8_t *msg, uint32_t msgLen, bool prehash,
    uint8_t hash[ED448_SIGN_LEN], const EAL_MdMethod *hashMethod)
{
    void *mdCtx = NULL;
    uint32_t hashLen;
    uint8_t prehashMsg[ED448_PREHASH_MSG_LEN];
    uint8_t dom[2];
    dom[0] = 0;
    dom[1] = (uint8_t)contextLen;
    const char *string = "SigEd448";

    int32_t ret;
    mdCtx = BSL_SAL_Malloc(hashMethod->ctxSize);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (prehash) {
        dom[0] = 1;
        hashLen = ED448_PREHASH_MSG_LEN;
        GOTO_END_IF_FAIL(hashMethod->init(mdCtx));
        GOTO_END_IF_FAIL(hashMethod->update(mdCtx, msg, msgLen));
        GOTO_END_IF_FAIL(hashMethod->final(mdCtx, prehashMsg, &hashLen));
    }
    hashLen = ED448_SIGN_LEN;
    GOTO_END_IF_FAIL(hashMethod->init(mdCtx));

    GOTO_END_IF_FAIL(hashMethod->update(mdCtx, (const uint8_t *)string, 8)); // len of SigEd448 = 8
    GOTO_END_IF_FAIL(hashMethod->update(mdCtx, dom, 2)); // dom has len of 2
    GOTO_END_IF_FAIL(hashMethod->update(mdCtx, context, contextLen));
    GOTO_END_IF_FAIL(hashMethod->update(mdCtx, rB, ED448_KEY_LEN));
    GOTO_END_IF_FAIL(hashMethod->update(mdCtx, pubKey, ED448_KEY_LEN));
    if (prehash) {
        GOTO_END_IF_FAIL(hashMethod->update(mdCtx, prehashMsg, ED448_PREHASH_MSG_LEN));
    } else {
        GOTO_END_IF_FAIL(hashMethod->update(mdCtx, msg, msgLen));
    }
    GOTO_END_IF_FAIL(hashMethod->final(mdCtx, hash, &hashLen));

end:
    hashMethod->deinit(mdCtx);
    BSL_SAL_FREE(mdCtx);
    return ret;
}

static int32_t SignInputCheck(const CRYPT_CURVE448_Ctx *pkey, const uint8_t *msg,
    uint32_t msgLen, const uint8_t *sign, const uint32_t *signLen)
{
    if (pkey == NULL || (msg == NULL && msgLen != 0) || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((pkey->keyType & CURVE448_PRVKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_NO_PRVKEY);
        return CRYPT_CURVE448_NO_PRVKEY;
    }
    if (*signLen < ED448_SIGN_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_SIGNLEN_ERROR);
        return CRYPT_CURVE448_SIGNLEN_ERROR;
    }
    if (pkey->hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_NO_HASH_METHOD);
        return CRYPT_CURVE448_NO_HASH_METHOD;
    }
    if (pkey->ctxLen == CURVE448_NO_SET_CTX) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_NO_CONTEXT);
        return CRYPT_CURVE448_NO_CONTEXT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CURVE448_Sign(CRYPT_CURVE448_Ctx *pkey, const uint8_t *msg,
    uint32_t msgLen, uint8_t *sign, uint32_t *signLen)
{
    uint8_t prvKeyHash[ED448_SIGN_LEN];
    int32_t ret;
    Scalar s, sCopy, rScalar, rScalarCopy, kScalar;
    Curve448Point mulBase;
    uint8_t r[ED448_SIGN_LEN];
    uint8_t *prefix = NULL;
    uint8_t rB[ED448_KEY_LEN];
    uint8_t k[ED448_SIGN_LEN];

    ret = SignInputCheck(pkey, msg, msgLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = HashPrvKey(pkey->prvKey, prvKeyHash, pkey->hashMethod);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    prvKeyHash[0] &= 0xfc;
    prvKeyHash[ED448_KEY_LEN - 1] = 0;
    prvKeyHash[ED448_KEY_LEN - 2] |= 0x80; // 2nd last byte highest bit set 1

    prefix = prvKeyHash + ED448_KEY_LEN;

    ScalarDecode(&s, prvKeyHash, ED448_KEY_LEN);
    ScalarDivideBy2(&sCopy, &s);
    ScalarDivideBy2(&sCopy, &sCopy);

    // no pubkey, generate pubkey
    if ((pkey->keyType & CURVE448_PUBKEY) == 0) {
        Curve448PrecomputedMulBase(&mulBase, &sCopy);
        Ed448EncodePoint(pkey->pubKey, &mulBase);
        pkey->keyType |= CURVE448_PUBKEY;
    }

    ret = HashR(pkey->context, pkey->ctxLen, prefix, msg, msgLen, pkey->preHash, r, pkey->hashMethod);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ScalarDecode(&rScalar, r, ED448_SIGN_LEN);
    ScalarDivideBy2(&rScalarCopy, &rScalar);
    ScalarDivideBy2(&rScalarCopy, &rScalarCopy);

    Curve448PrecomputedMulBase(&mulBase, &rScalarCopy);
    Ed448EncodePoint(rB, &mulBase);

    ret = HashK(pkey->context, pkey->ctxLen, rB, pkey->pubKey, msg, msgLen, pkey->preHash, k, pkey->hashMethod);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }
    ScalarDecode(&kScalar, k, ED448_SIGN_LEN);
    ScalarMul(&s, &kScalar, &s);
    ScalarAdd(&s, &s, &rScalar);

    (void)memcpy_s(sign, ED448_SIGN_LEN, rB, ED448_KEY_LEN);
    ScalarEncode(sign + ED448_KEY_LEN, &s);
    sign[ED448_SIGN_LEN - 1] = 0;
    *signLen = ED448_SIGN_LEN;

end:
    BSL_SAL_CleanseData(prvKeyHash, sizeof(prvKeyHash));
    BSL_SAL_CleanseData(&s, sizeof(s));
    BSL_SAL_CleanseData(&sCopy, sizeof(sCopy));
    return ret;
}

static bool VerifyCheckSValid(const uint8_t s[ED448_KEY_LEN])
{
    // order L
    const uint8_t l[ED448_KEY_LEN] = {
        0xF3, 0x44, 0x58, 0xAB, 0x92, 0xC2, 0x78, 0x23, 0x55, 0x8F, 0xC5, 0x8D,
        0x72, 0xC2, 0x6C, 0x21, 0x90, 0x36, 0xD6, 0xAE, 0x49, 0xDB, 0x4E, 0xC4,
        0xE9, 0x23, 0xCA, 0x7C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F, 0x00
    };

    int32_t i;
    // start from highest block
    for (i = ED448_KEY_LEN - 1; i >= 0; i--) {
        if (s[i] > l[i]) {
            return false;
        } else if (s[i] < l[i]) {
            return true;
        }
    }
    // s = L is invalid
    return false;
}

static int32_t VerifyInputCheck(const CRYPT_CURVE448_Ctx *pkey, const uint8_t *msg,
    uint32_t msgLen, const uint8_t *sign, uint32_t signLen)
{
    if (pkey == NULL || (msg == NULL && msgLen != 0) || sign == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((pkey->keyType & CURVE448_PUBKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_NO_PUBKEY);
        return CRYPT_CURVE448_NO_PUBKEY;
    }
    if (signLen != ED448_SIGN_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_SIGNLEN_ERROR);
        return CRYPT_CURVE448_SIGNLEN_ERROR;
    }
    if (pkey->hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_NO_HASH_METHOD);
        return CRYPT_CURVE448_NO_HASH_METHOD;
    }
    if (pkey->ctxLen == CURVE448_NO_SET_CTX) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_NO_CONTEXT);
        return CRYPT_CURVE448_NO_CONTEXT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CURVE448_Verify(const CRYPT_CURVE448_Ctx *pkey, const uint8_t *msg,
    uint32_t msgLen, const uint8_t *sign, uint32_t signLen)
{
    int32_t ret;
    ret = VerifyInputCheck(pkey, msg, msgLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (!VerifyCheckSValid(sign + ED448_KEY_LEN)) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_VERIFY_FAIL);
        return CRYPT_CURVE448_VERIFY_FAIL;
    }

    Curve448Point pointA, pointR;
    if (ED448DecodePoint(&pointA, pkey->pubKey) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_INVALID_PUBKEY);
        return CRYPT_CURVE448_INVALID_PUBKEY;
    }

    if (ED448DecodePoint(&pointR, sign) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_VERIFY_FAIL);
        return CRYPT_CURVE448_VERIFY_FAIL;
    }

    Scalar sScalar, kScalar;
    uint8_t k[ED448_SIGN_LEN];
    ret = HashK(pkey->context, pkey->ctxLen, sign, pkey->pubKey, msg, msgLen, pkey->preHash, k, pkey->hashMethod);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ScalarDecode(&sScalar, sign + ED448_KEY_LEN, ED448_KEY_LEN);
    ScalarDecode(&kScalar, k, ED448_SIGN_LEN);

    // k = -k
    ScalarNeg(&kScalar);

    // sB = R + kA
    Curve448Point myR;
    PointSetZero(&myR);
    ret = Curve448KAMulPlusMulBase(&myR, &sScalar, &kScalar, &pointA);
    if ((ret == CRYPT_SUCCESS) && (PointEqual(&myR, &pointR) == CRYPT_SUCCESS)) {
        return CRYPT_SUCCESS;
    } else {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_VERIFY_FAIL);
        return CRYPT_CURVE448_VERIFY_FAIL;
    }
}
#endif

#ifdef HITLS_CRYPTO_X448
int32_t CRYPT_X448_GenKey(CRYPT_CURVE448_Ctx *pkey)
{
    if (pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CRYPT_Rand(pkey->prvKey, sizeof(pkey->prvKey));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t prvKeyLocal[X448_KEY_LEN];
    (void)memcpy_s(prvKeyLocal, X448_KEY_LEN, pkey->prvKey, X448_KEY_LEN);
    prvKeyLocal[0] &= 252; // and 252 to clear last 2 bits
    prvKeyLocal[X448_KEY_LEN - 1] |= 128; // or 128 to set highest bit

    Scalar s;
    Curve448Point point;
    ScalarDecodeX448(&s, prvKeyLocal);
    ScalarDivideBy2(&s, &s);

    Curve448PrecomputedMulBase(&point, &s);
    X448EncodePoint(pkey->pubKey, &point);

    pkey->keyType = CURVE448_PRVKEY | CURVE448_PUBKEY;

    BSL_SAL_CleanseData(prvKeyLocal, sizeof(prvKeyLocal));
    BSL_SAL_CleanseData(&s, sizeof(s));

    return 0;
}

int32_t CRYPT_X448_ComputeSharedKey(CRYPT_CURVE448_Ctx *prvKey, CRYPT_CURVE448_Ctx *pubKey,
    uint8_t *sharedKey, uint32_t *shareKeyLen)
{
    if (prvKey == NULL || pubKey == NULL || sharedKey == NULL || shareKeyLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (*shareKeyLen < X448_KEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_KEYLEN_ERROR);
        return CRYPT_CURVE448_KEYLEN_ERROR;
    }
    if ((prvKey->keyType & CURVE448_PRVKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_NO_PRVKEY);
        return CRYPT_CURVE448_NO_PRVKEY;
    }
    if ((pubKey->keyType & CURVE448_PUBKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_NO_PUBKEY);
        return CRYPT_CURVE448_NO_PUBKEY;
    }

    uint32_t tmpLen = *shareKeyLen;
    if (CRYPT_X448_ComputeSharedKeyValid(prvKey->prvKey, pubKey->pubKey, sharedKey)) {
        *shareKeyLen = X448_KEY_LEN;
        return CRYPT_SUCCESS;
    } else {
        *shareKeyLen = tmpLen;
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_KEY_COMPUTE_FAILED);
        return CRYPT_CURVE448_KEY_COMPUTE_FAILED;
    }
}
#endif

int32_t CRYPT_CURVE448_SetPubKey(CRYPT_CURVE448_Ctx *pkey, const CRYPT_Curve448Pub *pub, uint32_t keyLen)
{
    if (pkey == NULL || pub == NULL || pub->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->len != keyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_KEYLEN_ERROR);
        return CRYPT_CURVE448_KEYLEN_ERROR;
    }

    /* The keyLen has been checked and does not have the overlong problem.
       The pkey memory is dynamically allocated and does not overlap with the pubkey memory. */
    /* There is no failure case for memcpy_s. */
    (void)memcpy_s(pkey->pubKey, keyLen, pub->data, pub->len);
    pkey->keyType |= CURVE448_PUBKEY;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_CURVE448_SetPrvKey(CRYPT_CURVE448_Ctx *pkey, const CRYPT_Curve448Prv *prv, uint32_t keyLen)
{
    if (pkey == NULL || prv == NULL || prv->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (prv->len != keyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_KEYLEN_ERROR);
        return CRYPT_CURVE448_KEYLEN_ERROR;
    }

    /* The keyLen has been checked and does not have the overlong problem.
       The pkey memory is dynamically allocated and does not overlap with the pubkey memory. */
    /* There is no failure case for memcpy_s. */
    (void)memcpy_s(pkey->prvKey, keyLen, prv->data, prv->len);
    pkey->keyType |= CURVE448_PRVKEY;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_CURVE448_GetPubKey(const CRYPT_CURVE448_Ctx *pkey, CRYPT_Curve448Pub *pub, uint32_t keyLen)
{
    if (pkey == NULL || pub == NULL || pub->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pub->len < keyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_KEYLEN_ERROR);
        return CRYPT_CURVE448_KEYLEN_ERROR;
    }

    if ((pkey->keyType & CURVE448_PUBKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_NO_PUBKEY);
        return CRYPT_CURVE448_NO_PUBKEY;
    }

    /* The keyLen has been checked and does not have the overlong problem.
       The pkey memory is dynamically allocated and does not overlap with the pubkey memory. */
    /* There is no failure case for memcpy_s. */
    (void)memcpy_s(pub->data, pub->len, pkey->pubKey, keyLen);

    pub->len = keyLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CURVE448_GetPrvKey(const CRYPT_CURVE448_Ctx *pkey, CRYPT_Curve448Prv *prv, uint32_t keyLen)
{
    if (pkey == NULL || prv == NULL || prv->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (prv->len < keyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_KEYLEN_ERROR);
        return CRYPT_CURVE448_KEYLEN_ERROR;
    }

    if ((pkey->keyType & CURVE448_PRVKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_NO_PRVKEY);
        return CRYPT_CURVE448_NO_PRVKEY;
    }

    /* The keyLen has been checked and does not have the overlong problem.
       The pkey memory is dynamically allocated and does not overlap with the pubkey memory. */
    /* There is no failure case for memcpy_s. */
    (void)memcpy_s(prv->data, prv->len, pkey->prvKey, keyLen);

    prv->len = keyLen;
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_ED448
int32_t CRYPT_ED448_GetPrvKey(const CRYPT_CURVE448_Ctx *pkey, CRYPT_Curve448Prv *prv)
{
    return CRYPT_CURVE448_GetPrvKey(pkey, prv, ED448_KEY_LEN);
}

int32_t CRYPT_ED448_GetPubKey(const CRYPT_CURVE448_Ctx *pkey, CRYPT_Curve448Pub *pub)
{
    return CRYPT_CURVE448_GetPubKey(pkey, pub, ED448_KEY_LEN);
}

int32_t CRYPT_ED448_SetPrvKey(CRYPT_CURVE448_Ctx *pkey, const CRYPT_Curve448Prv *prv)
{
    return CRYPT_CURVE448_SetPrvKey(pkey, prv, ED448_KEY_LEN);
}

int32_t CRYPT_ED448_SetPubKey(CRYPT_CURVE448_Ctx *pkey, const CRYPT_Curve448Pub *pub)
{
    return CRYPT_CURVE448_SetPubKey(pkey, pub, ED448_KEY_LEN);
}

int32_t CRYPT_ED448_GetSignLen(const CRYPT_CURVE448_Ctx *pkey)
{
    (void)pkey;
    return ED448_SIGN_LEN;
}

int32_t CRYPT_ED448_GetBits(const CRYPT_CURVE448_Ctx *pkey)
{
    (void)pkey;
    return ED448_KEY_LEN * 8; // bits = 8 * bytes
}
#endif

#ifdef HITLS_CRYPTO_X448
int32_t CRYPT_X448_GetPrvKey(const CRYPT_CURVE448_Ctx *pkey, CRYPT_Curve448Prv *prv)
{
    return CRYPT_CURVE448_GetPrvKey(pkey, prv, X448_KEY_LEN);
}

int32_t CRYPT_X448_GetPubKey(const CRYPT_CURVE448_Ctx *pkey, CRYPT_Curve448Pub *pub)
{
    return CRYPT_CURVE448_GetPubKey(pkey, pub, X448_KEY_LEN);
}

int32_t CRYPT_X448_SetPrvKey(CRYPT_CURVE448_Ctx *pkey, const CRYPT_Curve448Prv *prv)
{
    return CRYPT_CURVE448_SetPrvKey(pkey, prv, X448_KEY_LEN);
}

int32_t CRYPT_X448_SetPubKey(CRYPT_CURVE448_Ctx *pkey, const CRYPT_Curve448Pub *pub)
{
    return CRYPT_CURVE448_SetPubKey(pkey, pub, X448_KEY_LEN);
}

int32_t CRYPT_X448_GetBits(const CRYPT_CURVE448_Ctx *pkey)
{
    (void)pkey;
    return X448_KEY_LEN * 8; // bits = 8 * bytes
}
#endif

int32_t CRYPT_CURVE448_Cmp(const CRYPT_CURVE448_Ctx *a, const CRYPT_CURVE448_Ctx *b)
{
    RETURN_RET_IF(a == NULL || b == NULL, CRYPT_NULL_INPUT);

    RETURN_RET_IF((a->keyType & CURVE448_PUBKEY) == 0 || (b->keyType & CURVE448_PUBKEY) == 0,
                  CRYPT_CURVE448_NO_PUBKEY);

    RETURN_RET_IF(memcmp(a->pubKey, b->pubKey, ED448_KEY_LEN) != 0, CRYPT_CURVE448_PUBKEY_NOT_EQUAL);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_CURVE448_GetSecBits(const CRYPT_CURVE448_Ctx *ctx)
{
    (void) ctx;
    return 224;
}
#endif /* HITLS_CRYPTO_CURVE448 */
