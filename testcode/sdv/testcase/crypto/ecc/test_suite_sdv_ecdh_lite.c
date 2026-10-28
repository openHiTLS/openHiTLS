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

/* BEGIN_HEADER */

#include <string.h>
#include <stdlib.h>
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_ecdh.h"
#include "ecc_local.h"
#include "crypt_errno.h"
#include "crypt_util_rand.h"
#include "crypt_eal_pkey.h"
#include "crypt_params_key.h"
#include "eal_pkey_local.h"
/* END_HEADER */

#ifdef HITLS_CRYPTO_ECC_LITE
static bool LiteErrorStackEquals(int32_t expected)
{
#ifdef HITLS_BSL_ERR
    return BSL_ERR_GetError() == expected && BSL_ERR_GetError() == 0;
#else
    (void)expected;
    return true;
#endif
}

static bool LiteCurveEnabled(int id)
{
    switch (id) {
#ifdef HITLS_CRYPTO_CURVE_NISTP192
        case CRYPT_ECC_NISTP192:
            return true;
#endif
#ifdef HITLS_CRYPTO_CURVE_NISTP256
        case CRYPT_ECC_NISTP256:
            return true;
#endif
        default:
            return false;
    }
}

/* Inspect generated state without adding key-export code to the library. */
static void LiteTestReadBn(const ECC_LiteBn *bn, uint8_t *out, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        uint32_t offset = len - 1 - i;
        out[i] = (uint8_t)(bn->data[offset / sizeof(BN_UINT)] >> (8 * (offset % sizeof(BN_UINT))));
    }
}

static int32_t LiteTestReadPub(const CRYPT_ECDH_Ctx *ctx, CRYPT_EccPub *pub)
{
    if (ctx->pubkey == NULL) {
        return CRYPT_ECC_PKEY_ERR_EMPTY_KEY;
    }
    uint32_t bytes = ctx->para->bytes;
    if (pub->len < 1 + 2 * bytes) {
        return CRYPT_ECC_BUFF_LEN_NOT_ENOUGH;
    }
    pub->data[0] = 4;
    CRYPT_Data x = {pub->data + 1, bytes};
    CRYPT_Data y = {pub->data + 1 + bytes, bytes};
    int32_t ret = ECC_GetPoint(ctx->para, ctx->pubkey, &x, &y);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    pub->len = 1 + 2 * bytes;
    return CRYPT_SUCCESS;
}

static int32_t LiteTestReadPrv(const CRYPT_ECDH_Ctx *ctx, CRYPT_EccPrv *prv)
{
    if (ctx->prvkey == NULL) {
        return CRYPT_ECC_PKEY_ERR_EMPTY_KEY;
    }
    if (prv->len < ctx->para->bytes) {
        return CRYPT_ECC_BUFF_LEN_NOT_ENOUGH;
    }
    LiteTestReadBn(ctx->prvkey, prv->data, ctx->para->bytes);
    prv->len = ctx->para->bytes;
    return CRYPT_SUCCESS;
}

static Hex *g_litePrv;
static uint32_t g_liteCalls;
static int g_liteRandMode;

static int32_t LiteTestRand(uint8_t *out, uint32_t len)
{
    g_liteCalls++;
    if (g_liteRandMode == 3) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (g_liteRandMode == 4 && g_liteCalls == 1) {
        memset(out, 0xff, len);
        return CRYPT_SUCCESS;
    }
    if (g_liteRandMode == 2 || (g_liteRandMode == 1 && g_liteCalls == 1)) {
        memset(out, 0, len);
        return CRYPT_SUCCESS;
    }
    if (len != g_litePrv->len) {
        return CRYPT_INVALID_ARG;
    }
    memcpy(out, g_litePrv->x, len);
    return CRYPT_SUCCESS;
}

static int32_t LiteSetCurve(CRYPT_ECDH_Ctx *ctx, int id)
{
    return CRYPT_ECDH_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &id, sizeof(id));
}

static uint32_t g_liteAllocCount;
static uint32_t g_liteFailAlloc;

static void *LiteTestMalloc(uint32_t len)
{
    if (++g_liteAllocCount == g_liteFailAlloc) {
        return NULL;
    }
    return malloc(len);
}

static int32_t LiteBlindRand(uint8_t *out, uint32_t len)
{
    memset(out, 1, len);
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_ECC_LITE */

/**
 * @test SDV_ECDH_LITE_SCALAR_WIDTH_TC001
 * @brief Check scalar bounds and point vectors.
 * @precon ECC lite and the selected curve are enabled.
 * @expect Results match vectors; input is preserved; failures preserve output.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_SCALAR_WIDTH_TC001(int id, Hex *scalar, Hex *peer, int expected, int expectedExport,
    Hex *expectedPoint)
{
#ifndef HITLS_CRYPTO_ECC_LITE
    (void)id;
    (void)scalar;
    (void)peer;
    (void)expected;
    (void)expectedExport;
    (void)expectedPoint;
    SKIP_TEST();
#else
    if (!LiteCurveEnabled(id)) {
        SKIP_TEST();
    }
    ECC_Para *para = ECC_NewPara(id);
    ECC_Point *point = NULL;
    ECC_Point *result = NULL;
    ECC_LiteBn k = {0};
    ASSERT_TRUE(para != NULL);
    point = ECC_NewPoint(para);
    result = ECC_NewPoint(para);
    ASSERT_TRUE(point != NULL && result != NULL);
    if (peer->len != 0) {
        ASSERT_EQ(ECC_DecodePoint(para, point, peer->x, peer->len), CRYPT_SUCCESS);
    } else {
        EccLiteBnSetLimb(&k, 1);
        ASSERT_EQ(ECC_PointMul(para, point, &k, NULL), CRYPT_SUCCESS);
    }
    ECC_Point input = *point;
    *result = input;
    ASSERT_EQ(EccLiteBnBin2Bn(&k, scalar->x, scalar->len, ECC_LITE_MAX_BYTES), CRYPT_SUCCESS);
#ifdef HITLS_BSL_ERR
    BSL_ERR_ClearError();
#endif
    ASSERT_EQ(ECC_PointMul(para, result, &k, peer->len != 0 ? point : NULL), expected);
    ASSERT_TRUE(LiteErrorStackEquals(expected));
    if (expected != CRYPT_SUCCESS) {
        ASSERT_EQ(memcmp(result, &input, sizeof(input)), 0);
    } else {
        uint8_t out[2 * ECC_LITE_MAX_BYTES] = {0};
        CRYPT_Data x = {out, para->bytes};
        CRYPT_Data y = {out + para->bytes, para->bytes};
        ASSERT_EQ(ECC_GetPoint(para, result, &x, &y), expectedExport);
        ASSERT_EQ(x.len, para->bytes);
        ASSERT_EQ(y.len, para->bytes);
        ASSERT_COMPARE("point", out, sizeof(out), expectedPoint->x, expectedPoint->len);
    }
    ASSERT_EQ(memcmp(point, &input, sizeof(input)), 0);
EXIT:
    ECC_FreePoint(result);
    ECC_FreePoint(point);
    ECC_FreePara(para);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_IMPORT_BOUNDARY_TC001
 * @brief Reject invalid EAL key imports without replacing existing keys.
 * @precon EAL, ECDH and the selected curve are enabled.
 * @expect Import fails and the previous key still computes the expected shared secret.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_IMPORT_BOUNDARY_TC001(int id, int privateKey, Hex *invalid, Hex *base)
{
#if !defined(HITLS_CRYPTO_ECC_LITE) || !defined(HITLS_CRYPTO_EAL)
    (void)id;
    (void)privateKey;
    (void)invalid;
    (void)base;
    SKIP_TEST();
#else
    if (!LiteCurveEnabled(id)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    uint8_t one = 1;
    uint8_t out[32];
    uint32_t len = sizeof(out);
    uint32_t bytes = (base->len - 1) / 2;
    CRYPT_EAL_PkeyPrv prv = {.id = CRYPT_PKEY_ECDH, .key.eccPrv = {&one, 1}};
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_ECDH, .key.eccPub = {base->x, base->len}};
    CRYPT_RandRegist(LiteBlindRand);
    memset(out, 0xa5, sizeof(out));
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, id), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub), CRYPT_SUCCESS);
    prv.key.eccPrv.data = invalid->x;
    prv.key.eccPrv.len = invalid->len;
    pub.key.eccPub.data = invalid->x;
    pub.key.eccPub.len = invalid->len;
    ASSERT_NE(privateKey ? CRYPT_EAL_PkeySetPrv(ctx, &prv) : CRYPT_EAL_PkeySetPub(ctx, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx, ctx, out, &len), CRYPT_SUCCESS);
    ASSERT_EQ(len, bytes);
    ASSERT_COMPARE("preserved keys", out, len, base->x + 1, bytes);
    for (uint32_t i = bytes; i < sizeof(out); i++) {
        ASSERT_EQ(out[i], 0xa5);
    }
EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_EAL_PkeyFreeCtx(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_VECTOR_TC001
 * @brief Check public keys and shared secrets against independent vectors.
 * @precon ECDH and the selected curve are enabled.
 * @expect Exact uncompressed public key and fixed-width shared secret.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_VECTOR_TC001(int id, Hex *prv, Hex *pub, Hex *peer, Hex *secret)
{
#ifndef HITLS_CRYPTO_ECC_LITE
    (void)id;
    (void)prv;
    (void)pub;
    (void)peer;
    (void)secret;
    SKIP_TEST();
#else
    if (!LiteCurveEnabled(id)) {
        SKIP_TEST();
    }
    CRYPT_ECDH_Ctx *a = CRYPT_ECDH_NewCtx();
    CRYPT_ECDH_Ctx *b = CRYPT_ECDH_NewCtx();
    uint8_t out[65] = {0};
    CRYPT_EccPrv key = {prv->x, prv->len};
    CRYPT_EccPub publicKey = {out, sizeof(out)};
    CRYPT_EccPub peerKey = {peer->x, peer->len};
    uint32_t len = sizeof(out);
    CRYPT_RandRegist(LiteBlindRand);
    ASSERT_TRUE(a != NULL && b != NULL);
    ASSERT_EQ(LiteSetCurve(a, id), CRYPT_SUCCESS);
    ASSERT_EQ(LiteSetCurve(b, id), CRYPT_SUCCESS);
    ASSERT_EQ(ECC_CofactorIsOne(NULL), 0);
    ASSERT_EQ(ECC_CofactorIsOne(a->para), 1);
    ASSERT_EQ(CRYPT_ECDH_SetPrvKey(a, &key), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDH_Ctrl(a, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(LiteTestReadPub(a, &publicKey), CRYPT_SUCCESS);
    ASSERT_COMPARE("public key", out, publicKey.len, pub->x, pub->len);
    ASSERT_EQ(CRYPT_ECDH_SetPubKey(b, &peerKey), CRYPT_SUCCESS);
    publicKey.len = sizeof(out);
    ASSERT_EQ(LiteTestReadPub(b, &publicKey), CRYPT_SUCCESS);
    ASSERT_COMPARE("peer round trip", out, publicKey.len, peer->x, peer->len);
    len = sizeof(out);
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(a, b, out, &len), CRYPT_SUCCESS);
    ASSERT_COMPARE("shared secret", out, len, secret->x, secret->len);
EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_ECDH_FreeCtx(a);
    CRYPT_ECDH_FreeCtx(b);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_KEYGEN_TC001
 * @brief Generate EAL key pairs using deterministic entropy.
 * @precon EAL, ECDH and the selected curve are enabled.
 * @expect Private and public keys match the vectors after generation and regeneration.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_KEYGEN_TC001(int id, Hex *prv, Hex *pub, int rejectFirst)
{
#if !defined(HITLS_CRYPTO_ECC_LITE) || !defined(HITLS_CRYPTO_EAL)
    (void)id;
    (void)prv;
    (void)pub;
    (void)rejectFirst;
    SKIP_TEST();
#else
    if (!LiteCurveEnabled(id)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    uint8_t out[65];
    g_litePrv = prv;
    g_liteRandMode = rejectFirst;
    g_liteCalls = 0;
    CRYPT_RandRegist(LiteTestRand);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, id), CRYPT_SUCCESS);
    for (uint32_t i = 0; i < 2; i++) {
        CRYPT_EccPrv privateKey = {out, sizeof(out)};
        CRYPT_EccPub publicKey = {out, sizeof(out)};
        ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
        uint32_t expectedCalls = i + (rejectFirst == 0 ? 1u : 2u);
        ASSERT_EQ(g_liteCalls, expectedCalls);
        ASSERT_EQ(LiteTestReadPrv(ctx->key, &privateKey), CRYPT_SUCCESS);
        ASSERT_COMPARE("EAL generated private key", out, privateKey.len, prv->x, prv->len);
        ASSERT_EQ(LiteTestReadPub(ctx->key, &publicKey), CRYPT_SUCCESS);
        ASSERT_COMPARE("EAL generated public key", out, publicKey.len, pub->x, pub->len);
    }
EXIT:
    CRYPT_RandRegist(NULL);
    g_litePrv = NULL;
    CRYPT_EAL_PkeyFreeCtx(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_EAL_VECTOR_TC001
 * @brief Check EAL key imports and shared secrets against independent vectors.
 * @precon EAL, ECDH and the selected curve are enabled.
 * @expect Both key import interfaces produce the exact fixed-width secret.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_EAL_VECTOR_TC001(int id, Hex *prv, Hex *pub, Hex *peer, Hex *secret)
{
#if !defined(HITLS_CRYPTO_ECC_LITE) || !defined(HITLS_CRYPTO_EAL)
    (void)id;
    (void)prv;
    (void)pub;
    (void)peer;
    (void)secret;
    SKIP_TEST();
#else
    if (!LiteCurveEnabled(id)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *a = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    CRYPT_EAL_PkeyCtx *b = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    CRYPT_EAL_PkeyPrv privateKey = {.id = CRYPT_PKEY_ECDH, .key.eccPrv = {prv->x, prv->len}};
    CRYPT_EAL_PkeyPub peerKey = {.id = CRYPT_PKEY_ECDH, .key.eccPub = {peer->x, peer->len}};
    BSL_Param privateParams[] = {{CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, prv->x, prv->len, 0}, BSL_PARAM_END};
    BSL_Param peerParams[] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, peer->x, peer->len, 0}, BSL_PARAM_END};
    uint8_t out[65];
    CRYPT_EccPub publicKey = {out, sizeof(out)};
    CRYPT_RandRegist(LiteBlindRand);
    ASSERT_TRUE(a != NULL && b != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(a, id), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(b, id), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(a, &privateKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(b, &peerKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(a, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0), CRYPT_SUCCESS);
    publicKey.len = sizeof(out);
    ASSERT_EQ(LiteTestReadPub(a->key, &publicKey), CRYPT_SUCCESS);
    ASSERT_COMPARE("EAL public key", out, publicKey.len, pub->x, pub->len);
    publicKey.len = sizeof(out);
    ASSERT_EQ(LiteTestReadPub(b->key, &publicKey), CRYPT_SUCCESS);
    ASSERT_COMPARE("EAL peer round trip", out, publicKey.len, peer->x, peer->len);
    uint32_t len = secret->len;
    memset(out, 0xa5, sizeof(out));
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, out, &len), CRYPT_SUCCESS);
    ASSERT_COMPARE("EAL shared secret", out, len, secret->x, secret->len);
    for (uint32_t j = len; j < sizeof(out); j++) {
        ASSERT_EQ(out[j], 0xa5);
    }

    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(a, privateParams), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(b, peerParams), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(a, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0), CRYPT_SUCCESS);
    publicKey.len = sizeof(out);
    ASSERT_EQ(LiteTestReadPub(a->key, &publicKey), CRYPT_SUCCESS);
    ASSERT_COMPARE("EAL public key", out, publicKey.len, pub->x, pub->len);
    publicKey.len = sizeof(out);
    ASSERT_EQ(LiteTestReadPub(b->key, &publicKey), CRYPT_SUCCESS);
    ASSERT_COMPARE("EAL peer round trip", out, publicKey.len, peer->x, peer->len);
    len = secret->len;
    memset(out, 0xa5, sizeof(out));
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, out, &len), CRYPT_SUCCESS);
    ASSERT_COMPARE("EAL shared secret", out, len, secret->x, secret->len);
    for (uint32_t j = len; j < sizeof(out); j++) {
        ASSERT_EQ(out[j], 0xa5);
    }
EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_EAL_PkeyFreeCtx(a);
    CRYPT_EAL_PkeyFreeCtx(b);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_KEYGEN_ERROR_TC001
 * @brief Exercise absent, failing and exhausted entropy callbacks.
 * @precon ECDH and the selected curve are enabled.
 * @expect Failure leaves no key.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_KEYGEN_ERROR_TC001(int id, int mode, int expected)
{
#ifndef HITLS_CRYPTO_ECC_LITE
    (void)id;
    (void)mode;
    (void)expected;
    SKIP_TEST();
#else
    if (!LiteCurveEnabled(id)) {
        SKIP_TEST();
    }
    CRYPT_ECDH_Ctx *ctx = CRYPT_ECDH_NewCtx();
    uint8_t out[65];
    CRYPT_EccPub pub = {out, sizeof(out)};
    CRYPT_EccPrv prv = {out, sizeof(out)};
    g_liteRandMode = mode;
    g_liteCalls = 0;
    CRYPT_RandRegist(mode == 0 ? NULL : LiteTestRand);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(LiteSetCurve(ctx, id), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDH_Gen(ctx), expected);
    ASSERT_EQ(LiteTestReadPub(ctx, &pub), CRYPT_ECC_PKEY_ERR_EMPTY_KEY);
    ASSERT_EQ(LiteTestReadPrv(ctx, &prv), CRYPT_ECC_PKEY_ERR_EMPTY_KEY);
EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_ECDH_FreeCtx(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_INVALID_TC001
 * @brief Reject malformed points, invalid private keys and short output buffers.
 * @precon ECDH and the selected curve are enabled.
 * @expect Invalid inputs fail; valid keys remain usable.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_INVALID_TC001(int id, Hex *order, Hex *validPub)
{
#ifndef HITLS_CRYPTO_ECC_LITE
    (void)id;
    (void)order;
    (void)validPub;
    SKIP_TEST();
#else
    if (!LiteCurveEnabled(id)) {
        SKIP_TEST();
    }
    CRYPT_ECDH_Ctx *ctx = CRYPT_ECDH_NewCtx();
    uint8_t out[65] = {0};
    CRYPT_EccPrv prv = {out, order->len};
    CRYPT_EccPub pub = {out, validPub->len};
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(LiteSetCurve(ctx, id), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDH_SetPrvKey(ctx, &prv), CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY);
    prv.data = order->x;
    ASSERT_EQ(CRYPT_ECDH_SetPrvKey(ctx, &prv), CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY);
    memcpy(out, validPub->x, validPub->len);
    out[validPub->len - 1] ^= 1;
    ASSERT_TRUE(CRYPT_ECDH_SetPubKey(ctx, &pub) != CRYPT_SUCCESS);
    memcpy(out, validPub->x, validPub->len);
    pub.len--;
    ASSERT_TRUE(CRYPT_ECDH_SetPubKey(ctx, &pub) != CRYPT_SUCCESS);
    pub.len++;
    memset(out + 1, 0xff, order->len);
    ASSERT_TRUE(CRYPT_ECDH_SetPubKey(ctx, &pub) != CRYPT_SUCCESS);
    pub.data = validPub->x;
    ASSERT_EQ(CRYPT_ECDH_SetPubKey(ctx, &pub), CRYPT_SUCCESS);
EXIT:
    CRYPT_ECDH_FreeCtx(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_MISMATCH_TC001
 * @brief Reject a peer on a different curve.
 * @precon P-192 and P-256 ECDH are enabled.
 * @expect Curve mismatch is reported.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_MISMATCH_TC001(int id, int peerId, Hex *peerPub)
{
#ifndef HITLS_CRYPTO_ECC_LITE
    (void)id;
    (void)peerId;
    (void)peerPub;
    SKIP_TEST();
#else
    if (!LiteCurveEnabled(id) || !LiteCurveEnabled(peerId)) {
        SKIP_TEST();
    }
    CRYPT_ECDH_Ctx *a = CRYPT_ECDH_NewCtx();
    CRYPT_ECDH_Ctx *b = CRYPT_ECDH_NewCtx();
    uint8_t one = 1;
    uint8_t out[32];
    uint32_t len = sizeof(out);
    CRYPT_EccPrv prv = {&one, 1};
    CRYPT_EccPub pub = {peerPub->x, peerPub->len};
    ASSERT_TRUE(a != NULL && b != NULL);
    ASSERT_EQ(LiteSetCurve(a, id), CRYPT_SUCCESS);
    ASSERT_EQ(LiteSetCurve(b, peerId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDH_SetPrvKey(a, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDH_SetPubKey(b, &pub), CRYPT_SUCCESS);
#ifdef HITLS_BSL_ERR
    BSL_ERR_ClearError();
#endif
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(a, b, out, &len), CRYPT_ECC_POINT_ERR_CURVE_ID);
#ifdef HITLS_BSL_ERR
    ASSERT_EQ(BSL_ERR_GetError(), CRYPT_ECC_POINT_ERR_CURVE_ID);
    ASSERT_EQ(BSL_ERR_GetError(), 0);
#endif
EXIT:
    CRYPT_ECDH_FreeCtx(a);
    CRYPT_ECDH_FreeCtx(b);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_ALLOC_TC001
 * @brief Fail each keygen allocation and retry.
 * @precon ECDH and the selected curve are enabled.
 * @expect No partial key survives; keygen succeeds after allocation recovers.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_ALLOC_TC001(int id, Hex *prv, int allocation)
{
#ifndef HITLS_CRYPTO_ECC_LITE
    (void)id;
    (void)prv;
    (void)allocation;
    SKIP_TEST();
#else
    if (!LiteCurveEnabled(id)) {
        SKIP_TEST();
    }
    CRYPT_ECDH_Ctx *ctx = CRYPT_ECDH_NewCtx();
    uint8_t out[65];
    CRYPT_EccPub pub = {out, sizeof(out)};
    CRYPT_EccPrv privateKey = {out, sizeof(out)};
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(LiteSetCurve(ctx, id), CRYPT_SUCCESS);
    g_litePrv = prv;
    g_liteCalls = 0;
    g_liteRandMode = 0;
    CRYPT_RandRegist(LiteTestRand);
    g_liteAllocCount = 0;
    g_liteFailAlloc = allocation;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, LiteTestMalloc), 0);
    ASSERT_EQ(CRYPT_ECDH_Gen(ctx), CRYPT_MEM_ALLOC_FAIL);
    ASSERT_EQ(LiteTestReadPub(ctx, &pub), CRYPT_ECC_PKEY_ERR_EMPTY_KEY);
    ASSERT_EQ(LiteTestReadPrv(ctx, &privateKey), CRYPT_ECC_PKEY_ERR_EMPTY_KEY);
    g_liteFailAlloc = 0;
    ASSERT_EQ(CRYPT_ECDH_Gen(ctx), CRYPT_SUCCESS);
EXIT:
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, NULL);
    CRYPT_RandRegist(NULL);
    CRYPT_ECDH_FreeCtx(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_INPUT_TC001
 * @brief Reject missing keys, null inputs and short shared-secret buffers.
 * @precon ECDH and the selected curve are enabled.
 * @expect Inputs are rejected without writing the output buffer.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_INPUT_TC001(int id, Hex *prv, Hex *peer)
{
#ifndef HITLS_CRYPTO_ECC_LITE
    (void)id;
    (void)prv;
    (void)peer;
    SKIP_TEST();
#else
    if (!LiteCurveEnabled(id)) {
        SKIP_TEST();
    }
    CRYPT_ECDH_Ctx *a = CRYPT_ECDH_NewCtx();
    CRYPT_ECDH_Ctx *b = CRYPT_ECDH_NewCtx();
    uint8_t out[32] = {0};
    uint32_t len = sizeof(out);
    CRYPT_EccPrv key = {prv->x, prv->len};
    CRYPT_EccPub pub = {peer->x, peer->len};
    memset(out, 0xa5, sizeof(out));
    CRYPT_RandRegist(LiteBlindRand);
    ASSERT_TRUE(a != NULL && b != NULL);
    ASSERT_EQ(CRYPT_ECDH_Gen(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_Gen(a), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_Ctrl(a, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(NULL, b, out, &len), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(a, NULL, out, &len), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(a, b, out, &len), CRYPT_ECDH_ERR_EMPTY_KEY);
    ASSERT_EQ(LiteSetCurve(a, id), CRYPT_SUCCESS);
    ASSERT_EQ(LiteSetCurve(b, id), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(a, b, out, &len), CRYPT_ECDH_ERR_EMPTY_KEY);
    ASSERT_EQ(CRYPT_ECDH_SetPrvKey(a, &key), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(a, b, out, &len), CRYPT_ECDH_ERR_EMPTY_KEY);
    ASSERT_EQ(CRYPT_ECDH_SetPubKey(b, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(b, b, out, &len), CRYPT_ECDH_ERR_EMPTY_KEY);
    ASSERT_EQ(CRYPT_ECDH_Ctrl(b, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(a, a, out, &len), CRYPT_ECDH_ERR_EMPTY_KEY);
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(a, b, NULL, &len), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(a, b, out, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(len, sizeof(out));
    len = 0;
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(a, b, out, &len), CRYPT_ECC_BUFF_LEN_NOT_ENOUGH);
    ASSERT_EQ(len, 0);
    len = prv->len - 1;
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(a, b, out, &len), CRYPT_ECC_BUFF_LEN_NOT_ENOUGH);
    ASSERT_EQ(len, prv->len - 1);
    for (uint32_t i = 0; i < sizeof(out); i++) {
        ASSERT_EQ(out[i], 0xa5);
    }
    len = sizeof(out);
    ASSERT_EQ(CRYPT_ECDH_ComputeShareKey(a, b, out, &len), CRYPT_SUCCESS);
    ASSERT_EQ(len, prv->len);
EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_ECDH_FreeCtx(a);
    CRYPT_ECDH_FreeCtx(b);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_EAL_INPUT_TC001
 * @brief Reject missing keys, null inputs and short buffers through EAL.
 * @precon EAL, ECDH and the selected curve are enabled.
 * @expect Failures preserve output; valid inputs produce the expected secret.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_EAL_INPUT_TC001(int id, Hex *prv, Hex *peer, Hex *secret)
{
#if !defined(HITLS_CRYPTO_ECC_LITE) || !defined(HITLS_CRYPTO_EAL)
    (void)id;
    (void)prv;
    (void)peer;
    (void)secret;
    SKIP_TEST();
#else
    if (!LiteCurveEnabled(id)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *a = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    CRYPT_EAL_PkeyCtx *b = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    CRYPT_EAL_PkeyPrv key = {.id = CRYPT_PKEY_ECDH, .key.eccPrv = {prv->x, prv->len}};
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_ECDH, .key.eccPub = {peer->x, peer->len}};
    uint8_t out[32] = {0};
    uint32_t len = sizeof(out);
    memset(out, 0xa5, sizeof(out));
    CRYPT_RandRegist(LiteBlindRand);
    ASSERT_TRUE(a != NULL && b != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(a), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(NULL, b, out, &len), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, NULL, out, &len), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, out, &len), CRYPT_ECDH_ERR_EMPTY_KEY);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(a, id), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(b, id), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, out, &len), CRYPT_ECDH_ERR_EMPTY_KEY);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(a, &key), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, out, &len), CRYPT_ECDH_ERR_EMPTY_KEY);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(b, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(b, b, out, &len), CRYPT_ECDH_ERR_EMPTY_KEY);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(b, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, a, out, &len), CRYPT_ECDH_ERR_EMPTY_KEY);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, NULL, &len), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, out, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(len, sizeof(out));
    len = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, out, &len), CRYPT_ECC_BUFF_LEN_NOT_ENOUGH);
    ASSERT_EQ(len, 0);
    len = secret->len - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, out, &len), CRYPT_ECC_BUFF_LEN_NOT_ENOUGH);
    ASSERT_EQ(len, secret->len - 1);
    for (uint32_t i = 0; i < sizeof(out); i++) {
        ASSERT_EQ(out[i], 0xa5);
    }
    len = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, out, &len), CRYPT_SUCCESS);
    ASSERT_COMPARE("EAL shared secret", out, len, secret->x, secret->len);
EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_EAL_PkeyFreeCtx(a);
    CRYPT_EAL_PkeyFreeCtx(b);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_NULL_INPUT_TC001
 * @brief Preserve null-input handling at ECC/ECDH entry points and cleanup paths.
 * @precon ECDH and the selected curve are enabled.
 * @expect Invalid inputs fail; existing parameters remain usable.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_NULL_INPUT_TC001(int id)
{
#ifndef HITLS_CRYPTO_ECC_LITE
    (void)id;
    SKIP_TEST();
#else
    if (!LiteCurveEnabled(id)) {
        SKIP_TEST();
    }
    CRYPT_ECDH_Ctx *ctx = CRYPT_ECDH_NewCtx();
    ECC_Point *point = NULL;
    uint8_t one = 1;
    CRYPT_EccPrv prv = {&one, 1};
    CRYPT_EccPub pub = {&one, 1};
    CRYPT_RandRegist(LiteBlindRand);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_ECDH_FreeCtx(NULL);
    CRYPT_ECDH_FreePara(NULL);
    ECC_FreePoint(NULL);
    EccLiteBnFree(NULL);
    ASSERT_EQ(CRYPT_ECDH_GetParaId(ctx), CRYPT_PKEY_PARAID_MAX);
    ASSERT_EQ(CRYPT_ECDH_GetSecBits(ctx), 0);
    ASSERT_EQ(CRYPT_ECDH_GetSecBits(NULL), 0);
    ASSERT_EQ(CRYPT_ECDH_Ctrl(NULL, CRYPT_CTRL_SET_PARA_BY_ID, &id, sizeof(id)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_SetPrvKey(NULL, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_SetPubKey(NULL, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_SetPrvKey(ctx, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_SetPubKey(ctx, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(LiteSetCurve(ctx, id), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDH_SetPrvKey(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_SetPubKey(ctx, NULL), CRYPT_NULL_INPUT);
    prv.data = NULL;
    pub.data = NULL;
    ASSERT_EQ(CRYPT_ECDH_SetPrvKey(ctx, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_SetPubKey(ctx, &pub), CRYPT_NULL_INPUT);
    prv.data = &one;
    pub.data = &one;
    prv.len = 0;
    pub.len = 0;
    ASSERT_EQ(CRYPT_ECDH_SetPrvKey(ctx, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_SetPubKey(ctx, &pub), CRYPT_NULL_INPUT);
    BSL_Param params[] = {BSL_PARAM_END};
    ASSERT_EQ(CRYPT_ECDH_SetPrvKeyEx(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_SetPubKeyEx(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_SetPrvKeyEx(ctx, params), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_ECDH_SetPubKeyEx(ctx, params), CRYPT_NULL_INPUT);
    ASSERT_NE(LiteSetCurve(ctx, CRYPT_PKEY_PARAID_MAX), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDH_GetParaId(ctx), id);
    g_liteAllocCount = 0;
    g_liteFailAlloc = 1;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, LiteTestMalloc), 0);
    ASSERT_NE(LiteSetCurve(ctx, id), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDH_GetParaId(ctx), id);
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, NULL), 0);
    prv.len = 1;
    ASSERT_EQ(CRYPT_ECDH_SetPrvKey(ctx, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDH_Ctrl(ctx, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0), CRYPT_SUCCESS);
#ifdef HITLS_BSL_ERR
    BSL_ERR_ClearError();
#endif
    point = ECC_NewPoint(NULL);
    ASSERT_TRUE(point == NULL);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));
    ASSERT_EQ(ECC_PointMul(NULL, ctx->pubkey, ctx->prvkey, NULL), CRYPT_NULL_INPUT);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));
    ASSERT_EQ(ECC_PointMul(ctx->para, NULL, ctx->prvkey, NULL), CRYPT_NULL_INPUT);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));
    ASSERT_EQ(ECC_PointMul(ctx->para, ctx->pubkey, NULL, NULL), CRYPT_NULL_INPUT);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));

    uint8_t encoded[1 + 2 * ECC_LITE_MAX_BYTES] = {4};
    CRYPT_Data x = {encoded + 1, ctx->para->bytes};
    CRYPT_Data y = {encoded + 1 + ctx->para->bytes, ctx->para->bytes};
    CRYPT_Data missing = {NULL, ctx->para->bytes};
    ASSERT_EQ(ECC_GetPoint(NULL, ctx->pubkey, &x, &y), CRYPT_NULL_INPUT);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));
    ASSERT_EQ(ECC_GetPoint(ctx->para, NULL, &x, &y), CRYPT_NULL_INPUT);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));
    ASSERT_EQ(ECC_GetPoint(ctx->para, ctx->pubkey, NULL, &y), CRYPT_NULL_INPUT);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));
    ASSERT_EQ(ECC_GetPoint(ctx->para, ctx->pubkey, &missing, &y), CRYPT_NULL_INPUT);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));
    ASSERT_EQ(ECC_GetPoint(ctx->para, ctx->pubkey, &x, &missing), CRYPT_NULL_INPUT);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));
    ASSERT_EQ(ECC_GetPoint(ctx->para, ctx->pubkey, &x, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(ECC_GetPoint(ctx->para, ctx->pubkey, &x, &y), CRYPT_SUCCESS);

    uint32_t encodedLen = 1 + 2 * ctx->para->bytes;
    ASSERT_EQ(ECC_DecodePoint(NULL, ctx->pubkey, encoded, encodedLen), CRYPT_NULL_INPUT);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));
    ASSERT_EQ(ECC_DecodePoint(ctx->para, NULL, encoded, encodedLen), CRYPT_NULL_INPUT);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));
    ASSERT_EQ(ECC_DecodePoint(ctx->para, ctx->pubkey, NULL, encodedLen), CRYPT_NULL_INPUT);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));
    ASSERT_EQ(ECC_DecodePoint(ctx->para, ctx->pubkey, NULL, 0), CRYPT_NULL_INPUT);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_NULL_INPUT));
    ASSERT_EQ(ECC_DecodePoint(ctx->para, ctx->pubkey, encoded, encodedLen), CRYPT_SUCCESS);
    ASSERT_TRUE(LiteErrorStackEquals(CRYPT_SUCCESS));
EXIT:
    ECC_FreePoint(point);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, NULL);
    g_liteFailAlloc = 0;
    CRYPT_RandRegist(NULL);
    CRYPT_ECDH_FreeCtx(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_CURVE_SELECT_TC001
 * @brief Select enabled curves and reject disabled curves.
 * @precon ECDH is enabled.
 * @expect Runtime curve availability matches the build configuration.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_CURVE_SELECT_TC001(int id)
{
#ifndef HITLS_CRYPTO_ECC_LITE
    (void)id;
    SKIP_TEST();
#else
    CRYPT_ECDH_Ctx *ctx = CRYPT_ECDH_NewCtx();
    ASSERT_TRUE(ctx != NULL);
    if (LiteCurveEnabled(id)) {
        ASSERT_EQ(LiteSetCurve(ctx, id), CRYPT_SUCCESS);
    } else {
        ASSERT_NE(LiteSetCurve(ctx, id), CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_ECDH_FreeCtx(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_ECDH_LITE_UNSUPPORTED_PKEY_TC001
 * @brief Check unsupported key operations through EAL.
 * @precon ECC lite and EAL are enabled.
 * @expect EAL forwards unsupported results.
 */
/* BEGIN_CASE */
void SDV_ECDH_LITE_UNSUPPORTED_PKEY_TC001(void)
{
#if !defined(HITLS_CRYPTO_ECC_LITE) || !defined(HITLS_CRYPTO_EAL)
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyCtx *eal = NULL;
    CRYPT_EAL_PkeyCtx *dup = NULL;
    CRYPT_EAL_PkeyPrv prv = {.id = CRYPT_PKEY_ECDH};
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_ECDH};
    BSL_Param params[] = {BSL_PARAM_END};
    int32_t bits = -1;
#ifdef HITLS_BSL_ERR
    BSL_ERR_ClearError();
#endif
    eal = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    ASSERT_TRUE(eal != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(eal, &prv), CRYPT_ECC_NOT_SUPPORT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(eal, &pub), CRYPT_ECC_NOT_SUPPORT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(eal, params), CRYPT_ECC_NOT_SUPPORT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(eal, params), CRYPT_ECC_NOT_SUPPORT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(eal, CRYPT_CTRL_GET_BITS, &bits, sizeof(bits)), CRYPT_SUCCESS);
    ASSERT_EQ(bits, 0);
    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyBits(eal), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyLen(eal), 0);
    dup = CRYPT_EAL_PkeyDupCtx(eal);
    ASSERT_TRUE(dup == NULL);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(dup);
    CRYPT_EAL_PkeyFreeCtx(eal);
#ifdef HITLS_BSL_ERR
    BSL_ERR_ClearError();
#endif
#endif
}
/* END_CASE */
