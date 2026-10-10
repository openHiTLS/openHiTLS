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

/* Simulation provider: registration, algorithm tables and engine lifecycle */

#include "sim_prov_internal.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_cipher.h"
#include "crypt_utils.h"
#include "crypt_modes_cbc.h"
#include "crypt_modes_gcm.h"
#include "crypt_modes_ccm.h"
#include "crypt_modes_chacha20poly1305.h"
#include "crypt_modes.h"

#ifdef HITLS_CRYPTO_PROVIDER

/* ---------------- KEYMGMT: delegate to built-in implementations ---------------- */

static void *SimKeyMgmtNewCtx(void *provCtx, int32_t algId)
{
    (void)provCtx;
    SimEngine *e = SimEngineGet();
    if (e == NULL) {
        return NULL;
    }
    /* A built-in context stands in for our key object; it is only ever used
     * through the delegate layer with a NULL libCtx (no recursion). */
    CRYPT_EAL_PkeyCtx *inner = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)algId);
    if (inner == NULL) {
        return NULL;
    }
    return inner;
}

static void SimKeyMgmtFreeCtx(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx((CRYPT_EAL_PkeyCtx *)ctx);
}

static void *SimKeyMgmtDupCtx(const void *ctx)
{
    return CRYPT_EAL_PkeyDupCtx((const CRYPT_EAL_PkeyCtx *)ctx);
}

static int32_t SimKeyMgmtSetParam(void *ctx, const BSL_Param *param)
{
    return CRYPT_EAL_PkeySetParaEx((CRYPT_EAL_PkeyCtx *)ctx, param);
}

static int32_t SimKeyMgmtGenKey(void *ctx)
{
    /* Key generation is a scenario-matchable crypto point (operaId KEYMGMT). GEN mutates the caller's key object, so the device layer
     * always executes it inline at the submit point - see SimDeviceSubmit. */
    SimOpCtx op = {0};
    op.kind = SIM_OP_KIND_GEN;
    op.operaId = CRYPT_EAL_OPERAID_KEYMGMT;
    op.pkey = (CRYPT_EAL_PkeyCtx *)ctx;
    return SimCryptoEntry(&op);
}

static int32_t SimKeyMgmtSetPrv(void *ctx, const BSL_Param *param)
{
    return CRYPT_EAL_PkeySetPrvEx((CRYPT_EAL_PkeyCtx *)ctx, param);
}

static int32_t SimKeyMgmtSetPub(void *ctx, const BSL_Param *param)
{
    return CRYPT_EAL_PkeySetPubEx((CRYPT_EAL_PkeyCtx *)ctx, param);
}

static int32_t SimKeyMgmtGetPrv(const void *ctx, BSL_Param *param)
{
    return CRYPT_EAL_PkeyGetPrvEx((const CRYPT_EAL_PkeyCtx *)ctx, param);
}

static int32_t SimKeyMgmtGetPub(const void *ctx, BSL_Param *param)
{
    return CRYPT_EAL_PkeyGetPubEx((const CRYPT_EAL_PkeyCtx *)ctx, param);
}

static int32_t SimKeyMgmtCheck(uint32_t checkType, const void *ctx1, const void *ctx2)
{
    (void)checkType;
    if (ctx2 == NULL) {
        return CRYPT_EAL_PkeyPrvCheck((CRYPT_EAL_PkeyCtx *)(uintptr_t)ctx1);
    }
    return CRYPT_EAL_PkeyPairCheck((CRYPT_EAL_PkeyCtx *)(uintptr_t)ctx1, (CRYPT_EAL_PkeyCtx *)(uintptr_t)ctx2);
}

static int32_t SimKeyMgmtCompare(const void *ctx1, const void *ctx2)
{
    return CRYPT_EAL_PkeyCmp((const CRYPT_EAL_PkeyCtx *)ctx1, (const CRYPT_EAL_PkeyCtx *)ctx2);
}

static int32_t SimKeyMgmtCtrl(void *ctx, int32_t cmd, void *val, uint32_t len)
{
    return CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)ctx, cmd, val, len);
}

/* The decode chain hands the parsed key material to the target provider
 * through IMPORT (lowkey2pkey -> ImportTargetPkey): curve first, then
 * private/public material. */
static int32_t SimKeyMgmtImport(void *ctx, const BSL_Param *param)
{
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)ctx;
    const BSL_Param *curve = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_EC_CURVE_ID);
    int32_t ret = CRYPT_SUCCESS;

    if (curve != NULL && curve->valueType == BSL_PARAM_TYPE_INT32 && curve->value != NULL) {
        ret = CRYPT_EAL_PkeySetParaById(pkey, *(CRYPT_PKEY_ParaId *)curve->value);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    if (BSL_PARAM_FindConstParam(param, CRYPT_PARAM_EC_PRVKEY) != NULL ||
        BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RSA_D) != NULL ||
        BSL_PARAM_FindConstParam(param, CRYPT_PARAM_CURVE25519_PRVKEY) != NULL) {
        ret = CRYPT_EAL_PkeySetPrvEx(pkey, param);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    if (BSL_PARAM_FindConstParam(param, CRYPT_PARAM_EC_PUBKEY) != NULL ||
        BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RSA_E) != NULL ||
        BSL_PARAM_FindConstParam(param, CRYPT_PARAM_CURVE25519_PUBKEY) != NULL) {
        ret = CRYPT_EAL_PkeySetPubEx(pkey, param);
    }
    return ret;
}

static const CRYPT_EAL_Func g_simKeyMgmtFuncs[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (void *)SimKeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (void *)SimKeyMgmtSetParam},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (void *)SimKeyMgmtGenKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (void *)SimKeyMgmtSetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (void *)SimKeyMgmtSetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (void *)SimKeyMgmtGetPrv},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (void *)SimKeyMgmtGetPub},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (void *)SimKeyMgmtDupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (void *)SimKeyMgmtCheck},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (void *)SimKeyMgmtCompare},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (void *)SimKeyMgmtCtrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (void *)SimKeyMgmtFreeCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_IMPORT, (void *)SimKeyMgmtImport},
    CRYPT_EAL_FUNC_END,
};

/* ---------------- SIGN ---------------- */

static int32_t SimProvSign(void *ctx, int32_t mdAlgId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                           uint32_t *signLen)
{
    SimOpCtx op = {0};
    op.kind = SIM_OP_KIND_SIGN;
    op.operaId = CRYPT_EAL_OPERAID_SIGN;
    op.pkey = (CRYPT_EAL_PkeyCtx *)ctx;
    op.mdId = mdAlgId;
    op.data = data;
    op.dataLen = dataLen;
    op.out = sign;
    op.outCap = sign == NULL ? 0 : *signLen;
    op.outLen = 0;
    int32_t ret = SimCryptoEntry(&op);
    if (ret == CRYPT_SUCCESS && signLen != NULL) {
        *signLen = op.outLen;
    }
    return ret;
}

static int32_t SimProvVerify(const void *ctx, int32_t mdAlgId, const uint8_t *data, uint32_t dataLen,
                             const uint8_t *sign, uint32_t signLen)
{
    SimOpCtx op = {0};
    op.kind = SIM_OP_KIND_VERIFY;
    op.operaId = CRYPT_EAL_OPERAID_SIGN;
    op.pkey = (CRYPT_EAL_PkeyCtx *)(uintptr_t)ctx;
    op.mdId = mdAlgId;
    op.data = data;
    op.dataLen = dataLen;
    op.out = (uint8_t *)(uintptr_t)sign; /* verify keeps sign as its input */
    op.outCap = signLen;
    op.outLen = signLen;
    return SimCryptoEntry(&op);
}

static const CRYPT_EAL_Func g_simSignFuncs[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (void *)SimProvSign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (void *)SimProvVerify},
    CRYPT_EAL_FUNC_END,
};

/* ---------------- KEYEXCH ---------------- */

static int32_t SimProvExch(const void *ctx, const void *pubCtx, uint8_t *out, uint32_t *outLen)
{
    SimOpCtx op = {0};
    op.kind = SIM_OP_KIND_EXCH;
    op.operaId = CRYPT_EAL_OPERAID_KEYEXCH;
    op.pkey = (CRYPT_EAL_PkeyCtx *)(uintptr_t)ctx;
    op.peer = (const CRYPT_EAL_PkeyCtx *)pubCtx;
    op.out = out;
    op.outCap = out == NULL ? 0 : *outLen;
    op.outLen = 0;
    int32_t ret = SimCryptoEntry(&op);
    if (ret == CRYPT_SUCCESS && outLen != NULL) {
        *outLen = op.outLen;
    }
    return ret;
}

static const CRYPT_EAL_Func g_simExchFuncs[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, (void *)SimProvExch},
    CRYPT_EAL_FUNC_END,
};

/* ---------------- KEM ----------------
 *
 * Encaps/decaps are scenario-matchable crypto points (operaId KEM): like SIGN and KEYEXCH they run through
 * SimCryptoEntry so they can
 * pause, resume and be counted. Encaps has two outputs (ciphertext and
 * shared secret) mapped onto out/out2. */

static int32_t SimProvKemEncaps(const void *ctx, uint8_t *cipher, uint32_t *cipherLen, uint8_t *out, uint32_t *outLen)
{
    SimOpCtx op = {0};
    op.kind = SIM_OP_KIND_KEM_ENC;
    op.operaId = CRYPT_EAL_OPERAID_KEM;
    op.pkey = (CRYPT_EAL_PkeyCtx *)(uintptr_t)ctx;
    op.out = cipher;
    op.outCap = cipher == NULL ? 0 : *cipherLen;
    op.outLen = 0;
    op.out2 = out;
    op.outCap2 = out == NULL ? 0 : *outLen;
    op.outLen2 = 0;
    int32_t ret = SimCryptoEntry(&op);
    if (ret == CRYPT_SUCCESS) {
        if (cipherLen != NULL) {
            *cipherLen = op.outLen;
        }
        if (outLen != NULL) {
            *outLen = op.outLen2;
        }
    }
    return ret;
}

static int32_t SimProvKemDecaps(const void *ctx, uint8_t *data, uint32_t dataLen, uint8_t *out, uint32_t *outLen)
{
    SimOpCtx op = {0};
    op.kind = SIM_OP_KIND_KEM_DEC;
    op.operaId = CRYPT_EAL_OPERAID_KEM;
    op.pkey = (CRYPT_EAL_PkeyCtx *)(uintptr_t)ctx;
    op.data = data;
    op.dataLen = dataLen;
    op.out = out;
    op.outCap = out == NULL ? 0 : *outLen;
    op.outLen = 0;
    int32_t ret = SimCryptoEntry(&op);
    if (ret == CRYPT_SUCCESS && outLen != NULL) {
        *outLen = op.outLen;
    }
    return ret;
}

static const CRYPT_EAL_Func g_simKemFuncs[] = {
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE, (void *)SimProvKemEncaps},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE, (void *)SimProvKemDecaps},
    CRYPT_EAL_FUNC_END,
};

/* ---------------- HASH ----------------
 *
 * The TLS record layer routes digests through the config attr as well, so the
 * simulation provider must also cover the hash algorithms the TLS suites use.
 * Delegation goes through the built-in (non-provider) MD API. */

static void *SimMdNewCtx(void *provCtx, int32_t algId)
{
    (void)provCtx;
    return CRYPT_EAL_MdNewCtx((CRYPT_MD_AlgId)algId);
}

static int32_t SimMdInitCtx(void *ctx, BSL_Param *param)
{
    (void)param;
    return CRYPT_EAL_MdInit((CRYPT_EAL_MdCtx *)ctx);
}

static int32_t SimMdUpdate(void *ctx, const uint8_t *input, uint32_t len)
{
    return CRYPT_EAL_MdUpdate((CRYPT_EAL_MdCtx *)ctx, input, len);
}

static int32_t SimMdFinal(void *ctx, uint8_t *out, uint32_t *outLen)
{
    return CRYPT_EAL_MdFinal((CRYPT_EAL_MdCtx *)ctx, out, outLen);
}

static void SimMdFreeCtx(void *ctx)
{
    CRYPT_EAL_MdFreeCtx((CRYPT_EAL_MdCtx *)ctx);
}

static void *SimMdDupCtx(const void *ctx)
{
    return CRYPT_EAL_MdDupCtx((const CRYPT_EAL_MdCtx *)ctx);
}

static int32_t SimMdDeinitCtx(void *ctx)
{
    return CRYPT_EAL_MdDeinit((CRYPT_EAL_MdCtx *)ctx);
}

/* The EAL MD provider path queries digest/block size through GETPARAM during
 * method resolution; the first argument is the libCtx (see EAL_ProviderMdFindMethod),
 * so the sizes must be static per algorithm. */
#define SIM_MD_DEFINE(name, digestSize, blockSize)                       \
    static int32_t SimMdGetParam##name(void *ctx, BSL_Param *param)      \
    {                                                                    \
        (void)ctx;                                                       \
        return CRYPT_MdCommonGetParam((digestSize), (blockSize), param); \
    }                                                                    \
    static const CRYPT_EAL_Func g_simMdFuncs##name[] = {                 \
        {CRYPT_EAL_IMPLMD_NEWCTX, (void *)SimMdNewCtx},                  \
        {CRYPT_EAL_IMPLMD_INITCTX, (void *)SimMdInitCtx},                \
        {CRYPT_EAL_IMPLMD_UPDATE, (void *)SimMdUpdate},                  \
        {CRYPT_EAL_IMPLMD_FINAL, (void *)SimMdFinal},                    \
        {CRYPT_EAL_IMPLMD_DEINITCTX, (void *)SimMdDeinitCtx},            \
        {CRYPT_EAL_IMPLMD_DUPCTX, (void *)SimMdDupCtx},                  \
        {CRYPT_EAL_IMPLMD_FREECTX, (void *)SimMdFreeCtx},                \
        {CRYPT_EAL_IMPLMD_GETPARAM, (void *)SimMdGetParam##name},        \
        CRYPT_EAL_FUNC_END,                                              \
    }

SIM_MD_DEFINE(Md5, 16, 64);
SIM_MD_DEFINE(Sha1, 20, 64);
SIM_MD_DEFINE(Sha224, 28, 64);
SIM_MD_DEFINE(Sha256, 32, 64);
SIM_MD_DEFINE(Sha384, 48, 128);
SIM_MD_DEFINE(Sha512, 64, 128);
SIM_MD_DEFINE(Sm3, 32, 64);

static const CRYPT_EAL_AlgInfo g_simMdAlgs[] = {
#ifdef HITLS_CRYPTO_MD5
    {CRYPT_MD_MD5, g_simMdFuncsMd5, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA1
    {CRYPT_MD_SHA1, g_simMdFuncsSha1, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA224
    {CRYPT_MD_SHA224, g_simMdFuncsSha224, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA256
    {CRYPT_MD_SHA256, g_simMdFuncsSha256, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA384
    {CRYPT_MD_SHA384, g_simMdFuncsSha384, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA512
    {CRYPT_MD_SHA512, g_simMdFuncsSha512, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_SM3
    {CRYPT_MD_SM3, g_simMdFuncsSm3, SIM_PROV_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END,
};

/* ---------------- MAC ---------------- */

static void *SimMacNewCtx(void *provCtx, int32_t algId)
{
    (void)provCtx;
    return CRYPT_EAL_MacNewCtx((CRYPT_MAC_AlgId)algId);
}

static int32_t SimMacInit(void *ctx, const uint8_t *key, uint32_t len, BSL_Param *param)
{
    (void)param;
    return CRYPT_EAL_MacInit((CRYPT_EAL_MacCtx *)ctx, key, len);
}

static int32_t SimMacUpdate(void *ctx, const uint8_t *input, uint32_t len)
{
    return CRYPT_EAL_MacUpdate((CRYPT_EAL_MacCtx *)ctx, input, len);
}

static int32_t SimMacFinal(void *ctx, uint8_t *out, uint32_t *outLen)
{
    return CRYPT_EAL_MacFinal((CRYPT_EAL_MacCtx *)ctx, out, outLen);
}

static void SimMacDeinitCtx(void *ctx)
{
    CRYPT_EAL_MacDeinit((CRYPT_EAL_MacCtx *)ctx);
}

static void SimMacFreeCtx(void *ctx)
{
    CRYPT_EAL_MacFreeCtx((CRYPT_EAL_MacCtx *)ctx);
}

/* The TLS layer feeds CRYPT_PARAM_MD_ATTR through SetParam (SetHmacMdAttr);
 * the inner built-in HMAC re-resolves its MD with a NULL libCtx (built-in
 * method table), which is exactly the delegation semantic. */
static int32_t SimMacSetParam(void *ctx, const BSL_Param *param)
{
    return CRYPT_EAL_MacSetParam((CRYPT_EAL_MacCtx *)ctx, param);
}

static const CRYPT_EAL_Func g_simMacFuncs[] = {
    {CRYPT_EAL_IMPLMAC_NEWCTX, (void *)SimMacNewCtx},       {CRYPT_EAL_IMPLMAC_INIT, (void *)SimMacInit},
    {CRYPT_EAL_IMPLMAC_UPDATE, (void *)SimMacUpdate},       {CRYPT_EAL_IMPLMAC_FINAL, (void *)SimMacFinal},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (void *)SimMacDeinitCtx}, {CRYPT_EAL_IMPLMAC_FREECTX, (void *)SimMacFreeCtx},
    {CRYPT_EAL_IMPLMAC_SETPARAM, (void *)SimMacSetParam},   CRYPT_EAL_FUNC_END,
};

static const CRYPT_EAL_AlgInfo g_simMacAlgs[] = {
#ifdef HITLS_CRYPTO_HMAC
    {CRYPT_MAC_HMAC_MD5, g_simMacFuncs, SIM_PROV_ATTR},
    {CRYPT_MAC_HMAC_SHA1, g_simMacFuncs, SIM_PROV_ATTR},
    {CRYPT_MAC_HMAC_SHA224, g_simMacFuncs, SIM_PROV_ATTR},
    {CRYPT_MAC_HMAC_SHA256, g_simMacFuncs, SIM_PROV_ATTR},
    {CRYPT_MAC_HMAC_SHA384, g_simMacFuncs, SIM_PROV_ATTR},
    {CRYPT_MAC_HMAC_SHA512, g_simMacFuncs, SIM_PROV_ATTR},
    {CRYPT_MAC_HMAC_SM3, g_simMacFuncs, SIM_PROV_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END,
};

/* ---------------- KDF ---------------- */

static void *SimKdfNewCtx(void *provCtx, int32_t algId)
{
    (void)provCtx;
    /* Built-in KDF context: its internal HMAC resolves through the built-in
     * method table (no attr recursion into this provider). */
    return CRYPT_EAL_KdfNewCtx((CRYPT_KDF_AlgId)algId);
}

static int32_t SimKdfSetParam(void *ctx, BSL_Param *param)
{
    return CRYPT_EAL_KdfSetParam((CRYPT_EAL_KdfCtx *)ctx, param);
}

static int32_t SimKdfDerive(void *ctx, uint8_t *key, uint32_t keyLen)
{
    return CRYPT_EAL_KdfDerive((CRYPT_EAL_KdfCtx *)ctx, key, keyLen);
}

static void SimKdfFreeCtx(void *ctx)
{
    CRYPT_EAL_KdfFreeCtx((CRYPT_EAL_KdfCtx *)ctx);
}

static const CRYPT_EAL_Func g_simKdfFuncs[] = {
    {CRYPT_EAL_IMPLKDF_NEWCTX, (void *)SimKdfNewCtx},
    {CRYPT_EAL_IMPLKDF_SETPARAM, (void *)SimKdfSetParam},
    {CRYPT_EAL_IMPLKDF_DERIVE, (void *)SimKdfDerive},
    {CRYPT_EAL_IMPLKDF_FREECTX, (void *)SimKdfFreeCtx},
    CRYPT_EAL_FUNC_END,
};

static const CRYPT_EAL_AlgInfo g_simKdfAlgs[] = {
#ifdef HITLS_CRYPTO_KDFTLS12
    {CRYPT_KDF_KDFTLS12, g_simKdfFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_HKDF
    {CRYPT_KDF_HKDF, g_simKdfFuncs, SIM_PROV_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END,
};

/* ---------------- SYMMCIPHER ----------------
 *
 * The record layer caches the cipher ctx per connection and re-arms it with
 * CRYPT_EAL_CipherReinit (which reaches the raw CRYPT_CTRL_REINIT_STATUS
 * command) for every record. Delegating through the public EAL wrapper would
 * duplicate the outer state machine and reject the re-init command, so - like
 * the default provider - the callbacks hand the low-level modes contexts
 * straight to the outer EAL layer. */

static void *SimCipherNewCtx(void *provCtx, int32_t algId)
{
    void *libCtx = provCtx;
    void *newCtxFunc = NULL;
    (void)libCtx;
    switch (algId) {
#if defined(HITLS_CRYPTO_CBC) && defined(HITLS_CRYPTO_AES)
        case CRYPT_CIPHER_AES128_CBC:
        case CRYPT_CIPHER_AES192_CBC:
        case CRYPT_CIPHER_AES256_CBC:
            newCtxFunc = (void *)MODES_CBC_NewCtxEx;
            break;
#endif
#if defined(HITLS_CRYPTO_CCM) && defined(HITLS_CRYPTO_AES)
        case CRYPT_CIPHER_AES128_CCM:
        case CRYPT_CIPHER_AES192_CCM:
        case CRYPT_CIPHER_AES256_CCM:
            newCtxFunc = (void *)MODES_CCM_NewCtxEx;
            break;
#endif
#if defined(HITLS_CRYPTO_GCM) && defined(HITLS_CRYPTO_AES)
        case CRYPT_CIPHER_AES128_GCM:
        case CRYPT_CIPHER_AES192_GCM:
        case CRYPT_CIPHER_AES256_GCM:
            newCtxFunc = (void *)MODES_GCM_NewCtxEx;
            break;
#endif
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)
        case CRYPT_CIPHER_CHACHA20_POLY1305:
            newCtxFunc = (void *)MODES_CHACHA20POLY1305_NewCtxEx;
            break;
#endif
#if defined(HITLS_CRYPTO_CBC) && defined(HITLS_CRYPTO_SM4)
        case CRYPT_CIPHER_SM4_CBC:
            newCtxFunc = (void *)MODES_CBC_NewCtxEx;
            break;
#endif
#if defined(HITLS_CRYPTO_GCM) && defined(HITLS_CRYPTO_SM4)
        case CRYPT_CIPHER_SM4_GCM:
            newCtxFunc = (void *)MODES_GCM_NewCtxEx;
            break;
#endif
#if defined(HITLS_CRYPTO_CCM) && defined(HITLS_CRYPTO_SM4)
        case CRYPT_CIPHER_SM4_CCM:
            newCtxFunc = (void *)MODES_CCM_NewCtxEx;
            break;
#endif
        default:
            return NULL;
    }
    if (newCtxFunc != NULL) {
        return ((void *(*)(void *, int32_t))newCtxFunc)(NULL, algId);
    }
    return NULL;
}

static const CRYPT_EAL_Func g_simCipherCbcFuncs[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (void *)SimCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (void *)MODES_CBC_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (void *)MODES_CBC_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (void *)MODES_CBC_FinalEx},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (void *)MODES_CBC_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (void *)MODES_CBC_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (void *)MODES_CBC_FreeCtx},
    {CRYPT_EAL_IMPLCIPHER_DUPCTX, (void *)MODES_CipherDupCtx},
    CRYPT_EAL_FUNC_END,
};

static const CRYPT_EAL_Func g_simCipherGcmFuncs[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (void *)SimCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (void *)MODES_GCM_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (void *)MODES_GCM_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (void *)MODES_GCM_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (void *)MODES_GCM_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (void *)MODES_GCM_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (void *)MODES_GCM_FreeCtx},
    {CRYPT_EAL_IMPLCIPHER_DUPCTX, (void *)MODES_CipherDupCtx},
    CRYPT_EAL_FUNC_END,
};

static const CRYPT_EAL_Func g_simCipherCcmFuncs[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (void *)SimCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (void *)MODES_CCM_InitCtx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (void *)MODES_CCM_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (void *)MODES_CCM_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (void *)MODES_CCM_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (void *)MODES_CCM_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (void *)MODES_CCM_FreeCtx},
    {CRYPT_EAL_IMPLCIPHER_DUPCTX, (void *)MODES_CCM_DupCtx},
    CRYPT_EAL_FUNC_END,
};

static const CRYPT_EAL_Func g_simCipherChachaFuncs[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (void *)SimCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (void *)MODES_CHACHA20POLY1305_InitCtx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (void *)MODES_CHACHA20POLY1305_Update},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (void *)MODES_CHACHA20POLY1305_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (void *)MODES_CHACHA20POLY1305_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (void *)MODES_CHACHA20POLY1305_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (void *)MODES_CHACHA20POLY1305_FreeCtx},
    {CRYPT_EAL_IMPLCIPHER_DUPCTX, (void *)MODES_CipherDupCtx},
    CRYPT_EAL_FUNC_END,
};

static const CRYPT_EAL_AlgInfo g_simCipherAlgs[] = {
#if defined(HITLS_CRYPTO_CBC) && defined(HITLS_CRYPTO_AES)
    {CRYPT_CIPHER_AES128_CBC, g_simCipherCbcFuncs, SIM_PROV_ATTR},
    {CRYPT_CIPHER_AES192_CBC, g_simCipherCbcFuncs, SIM_PROV_ATTR},
    {CRYPT_CIPHER_AES256_CBC, g_simCipherCbcFuncs, SIM_PROV_ATTR},
#endif
#if defined(HITLS_CRYPTO_GCM) && defined(HITLS_CRYPTO_AES)
    {CRYPT_CIPHER_AES128_GCM, g_simCipherGcmFuncs, SIM_PROV_ATTR},
    {CRYPT_CIPHER_AES192_GCM, g_simCipherGcmFuncs, SIM_PROV_ATTR},
    {CRYPT_CIPHER_AES256_GCM, g_simCipherGcmFuncs, SIM_PROV_ATTR},
#endif
#if defined(HITLS_CRYPTO_CCM) && defined(HITLS_CRYPTO_AES)
    {CRYPT_CIPHER_AES128_CCM, g_simCipherCcmFuncs, SIM_PROV_ATTR},
    {CRYPT_CIPHER_AES192_CCM, g_simCipherCcmFuncs, SIM_PROV_ATTR},
    {CRYPT_CIPHER_AES256_CCM, g_simCipherCcmFuncs, SIM_PROV_ATTR},
#endif
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)
    {CRYPT_CIPHER_CHACHA20_POLY1305, g_simCipherChachaFuncs, SIM_PROV_ATTR},
#endif
#if defined(HITLS_CRYPTO_CBC) && defined(HITLS_CRYPTO_SM4)
    {CRYPT_CIPHER_SM4_CBC, g_simCipherCbcFuncs, SIM_PROV_ATTR},
#endif
#if defined(HITLS_CRYPTO_GCM) && defined(HITLS_CRYPTO_SM4)
    {CRYPT_CIPHER_SM4_GCM, g_simCipherGcmFuncs, SIM_PROV_ATTR},
#endif
#if defined(HITLS_CRYPTO_CCM) && defined(HITLS_CRYPTO_SM4)
    {CRYPT_CIPHER_SM4_CCM, g_simCipherCcmFuncs, SIM_PROV_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END,
};

/* ---------------- algorithm tables ----------------
 *
 * The KEYMGMT/SIGN/KEYEXCH registration must cover every algorithm the TLS
 * config layer probes with our attr string: ConfigLoadGroupInfo probes each
 * default group (ECDH/DH/X25519/SM2/hybrid KEM) and
 * ConfigLoadSignatureSchemeInfo probes each cert key type
 * (RSA/RSA_PSS/ECDSA/ED25519/SM2/ML_DSA) with
 * CRYPT_EAL_ProviderPkeyNewCtx(attr). A missing entry makes the whole config
 * creation fail, so the tables are exhaustive rather than P0-only; the
 * delegated implementation is generic (built-in ctx by algId). */

static const CRYPT_EAL_AlgInfo g_simKeyMgmtAlgs[] = {
#ifdef HITLS_CRYPTO_ECDH
    {CRYPT_PKEY_ECDH, g_simKeyMgmtFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_PKEY_ECDSA, g_simKeyMgmtFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_RSA
    {CRYPT_PKEY_RSA, g_simKeyMgmtFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_DSA
    {CRYPT_PKEY_DSA, g_simKeyMgmtFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_DH
    {CRYPT_PKEY_DH, g_simKeyMgmtFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_X25519
    {CRYPT_PKEY_X25519, g_simKeyMgmtFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_PKEY_ED25519, g_simKeyMgmtFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_SM2
    {CRYPT_PKEY_SM2, g_simKeyMgmtFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_MLKEM
    {CRYPT_PKEY_ML_KEM, g_simKeyMgmtFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
    {CRYPT_PKEY_HYBRID_KEM, g_simKeyMgmtFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_MLDSA
    {CRYPT_PKEY_ML_DSA, g_simKeyMgmtFuncs, SIM_PROV_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END,
};

static const CRYPT_EAL_AlgInfo g_simSignAlgs[] = {
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_PKEY_ECDSA, g_simSignFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_RSA
    {CRYPT_PKEY_RSA, g_simSignFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_DSA
    {CRYPT_PKEY_DSA, g_simSignFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_PKEY_ED25519, g_simSignFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_SM2
    {CRYPT_PKEY_SM2, g_simSignFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_MLDSA
    {CRYPT_PKEY_ML_DSA, g_simSignFuncs, SIM_PROV_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END,
};

static const CRYPT_EAL_AlgInfo g_simExchAlgs[] = {
#ifdef HITLS_CRYPTO_ECDH
    {CRYPT_PKEY_ECDH, g_simExchFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_DH
    {CRYPT_PKEY_DH, g_simExchFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_X25519
    {CRYPT_PKEY_X25519, g_simExchFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_SM2
    {CRYPT_PKEY_SM2, g_simExchFuncs, SIM_PROV_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END,
};

static const CRYPT_EAL_AlgInfo g_simKemAlgs[] = {
#ifdef HITLS_CRYPTO_MLKEM
    {CRYPT_PKEY_ML_KEM, g_simKemFuncs, SIM_PROV_ATTR},
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
    {CRYPT_PKEY_HYBRID_KEM, g_simKemFuncs, SIM_PROV_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END,
};

int32_t SimProvQuery(void *provCtx, int32_t operaId, CRYPT_EAL_AlgInfo **algInfos)
{
    (void)provCtx;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = (CRYPT_EAL_AlgInfo *)g_simKeyMgmtAlgs;
            return CRYPT_SUCCESS;
        case CRYPT_EAL_OPERAID_SIGN:
            *algInfos = (CRYPT_EAL_AlgInfo *)g_simSignAlgs;
            return CRYPT_SUCCESS;
        case CRYPT_EAL_OPERAID_KEYEXCH:
            *algInfos = (CRYPT_EAL_AlgInfo *)g_simExchAlgs;
            return CRYPT_SUCCESS;
        case CRYPT_EAL_OPERAID_KEM:
            *algInfos = (CRYPT_EAL_AlgInfo *)g_simKemAlgs;
            return CRYPT_SUCCESS;
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = (CRYPT_EAL_AlgInfo *)g_simMdAlgs;
            return CRYPT_SUCCESS;
        case CRYPT_EAL_OPERAID_MAC:
            *algInfos = (CRYPT_EAL_AlgInfo *)g_simMacAlgs;
            return CRYPT_SUCCESS;
        case CRYPT_EAL_OPERAID_KDF:
            *algInfos = (CRYPT_EAL_AlgInfo *)g_simKdfAlgs;
            return CRYPT_SUCCESS;
        case CRYPT_EAL_OPERAID_SYMMCIPHER:
            *algInfos = (CRYPT_EAL_AlgInfo *)g_simCipherAlgs;
            return CRYPT_SUCCESS;
        case CRYPT_EAL_OPERAID_DECODER:
            *algInfos = (CRYPT_EAL_AlgInfo *)g_simDecoderAlgs;
            return CRYPT_SUCCESS;
        default:
            return CRYPT_NOT_SUPPORT;
    }
}

/* ---------------- provider lifecycle ---------------- */

int32_t SimProvCtrl(void *provCtx, int32_t cmd, void *val, uint32_t valLen);

void SimProvFree(void *provCtx);

int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param, CRYPT_EAL_Func *capFuncs,
                               CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    (void)mgrCtx;
    (void)param;
    (void)capFuncs;
    static CRYPT_EAL_Func funcs[] = {
        {CRYPT_EAL_PROVCB_QUERY, SimProvQuery},
        {CRYPT_EAL_PROVCB_CTRL, SimProvCtrl},
        {CRYPT_EAL_PROVCB_FREE, SimProvFree},
        CRYPT_EAL_FUNC_END,
    };
    if (outFuncs == NULL || provCtx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    *outFuncs = funcs;
    *provCtx = NULL; /* the engine singleton is created lazily */
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_PROVIDER */
