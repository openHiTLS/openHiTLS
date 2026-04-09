#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECDSA
#ifdef HITLS_CRYPTO_HMAC

#include <stdbool.h>
#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_bn.h"
#include "crypt_algid.h"
#include "crypt_utils.h"
#include "crypt_ecc_pkey.h"
#include "crypt_ecc.h"
#include "ecdsa_internal.h"
#include "crypt_hmac.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

typedef struct {
    const uint8_t *data;
    uint32_t len;
} Rfc6979Chunk;

/* qlenBits: RFC 6979 subgroup order bit length, derived from order n. */
static BN_BigNum *Bits2Int(const BN_BigNum *paraN, uint32_t qlenBits, const uint8_t *data, uint32_t dataLen)
{
    uint32_t nBits = qlenBits;
    uint32_t orderBits = BN_Bits(paraN);
    if (orderBits > nBits) {
        nBits = orderBits;
    }
    BN_BigNum *bn = BN_Create(nBits);
    if (bn == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    if (data == NULL || dataLen == 0) {
        return bn;
    }

    uint32_t truncBits = qlenBits;
    uint32_t useLen = dataLen;
    const uint8_t *ptr = data;
    bool needShift = (BN_BYTES_TO_BITS(useLen) > truncBits);
    if (needShift) {
        useLen = BN_BITS_TO_BYTES(truncBits);
    }
    int32_t ret = BN_Bin2Bn(bn, ptr, useLen);
    if (ret != CRYPT_SUCCESS) {
        BN_Destroy(bn);
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    if (needShift && ((truncBits & 7) != 0)) {
        ret = BN_Rshift(bn, bn, (8 - (truncBits & 7)));
        if (ret != CRYPT_SUCCESS) {
            BN_Destroy(bn);
            BSL_ERR_PUSH_ERROR(ret);
            return NULL;
        }
    }
    return bn;
}

static int32_t MdIdToHmacId(CRYPT_MD_AlgId mdId, CRYPT_MAC_AlgId *macId)
{
    if (macId == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (mdId) {
        case CRYPT_MD_MD5:
            *macId = CRYPT_MAC_HMAC_MD5;
            return CRYPT_SUCCESS;
        case CRYPT_MD_SHA1:
            *macId = CRYPT_MAC_HMAC_SHA1;
            return CRYPT_SUCCESS;
        case CRYPT_MD_SHA224:
            *macId = CRYPT_MAC_HMAC_SHA224;
            return CRYPT_SUCCESS;
        case CRYPT_MD_SHA256:
            *macId = CRYPT_MAC_HMAC_SHA256;
            return CRYPT_SUCCESS;
        case CRYPT_MD_SHA384:
            *macId = CRYPT_MAC_HMAC_SHA384;
            return CRYPT_SUCCESS;
        case CRYPT_MD_SHA512:
            *macId = CRYPT_MAC_HMAC_SHA512;
            return CRYPT_SUCCESS;
        case CRYPT_MD_SHA3_224:
            *macId = CRYPT_MAC_HMAC_SHA3_224;
            return CRYPT_SUCCESS;
        case CRYPT_MD_SHA3_256:
            *macId = CRYPT_MAC_HMAC_SHA3_256;
            return CRYPT_SUCCESS;
        case CRYPT_MD_SHA3_384:
            *macId = CRYPT_MAC_HMAC_SHA3_384;
            return CRYPT_SUCCESS;
        case CRYPT_MD_SHA3_512:
            *macId = CRYPT_MAC_HMAC_SHA3_512;
            return CRYPT_SUCCESS;
        case CRYPT_MD_SM3:
            *macId = CRYPT_MAC_HMAC_SM3;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
            return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
}

static int32_t BnToOctets(const BN_BigNum *bn, uint8_t *out, uint32_t outLen)
{
    if (bn == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t bnLen = BN_Bytes(bn);
    if (bnLen > outLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    (void)memset(out, 0, outLen);
    if (bnLen == 0) {
        return CRYPT_SUCCESS;
    }
    uint32_t useLen = bnLen;
    int32_t ret = BN_Bn2Bin(bn, out + outLen - bnLen, &useLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t Bits2Octets(const BN_BigNum *paraN, uint32_t qlenBits, const uint8_t *hash, uint32_t hashLen, uint8_t *out,
    uint32_t outLen)
{
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    BN_BigNum *tmp = Bits2Int(paraN, qlenBits, hash, hashLen);
    BN_Optimizer *opt = NULL;
    if (tmp == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    opt = BN_OptimizerCreate();
    if (opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_Mod(tmp, tmp, paraN, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BnToOctets(tmp, out, outLen);
EXIT:
    if (opt != NULL) {
        OptimizerEnd(opt);
        BN_OptimizerDestroy(opt);
    }
    BN_Destroy(tmp);
    return ret;
}

static int32_t NewHmacCtx(const CRYPT_ECDSA_Ctx *ctx, CRYPT_MAC_AlgId macId, CRYPT_HMAC_Ctx **hmacCtx)
{
    if (ctx == NULL || hmacCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_HMAC_Ctx *tmp = CRYPT_HMAC_NewCtxEx(ctx->libCtx, macId);
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
#ifdef HITLS_CRYPTO_PROVIDER
    if (ctx->mdAttr != NULL) {
        BSL_Param params[2] = {{0}, BSL_PARAM_END};
        (void)BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_MD_ATTR, BSL_PARAM_TYPE_UTF8_STR,
            ctx->mdAttr, (uint32_t)strlen(ctx->mdAttr) + 1);
        int32_t ret = CRYPT_HMAC_SetParam(tmp, params);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_HMAC_FreeCtx(tmp);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
#endif
    *hmacCtx = tmp;
    return CRYPT_SUCCESS;
}

static int32_t HmacOnce(const CRYPT_ECDSA_Ctx *ctx, CRYPT_MAC_AlgId macId, const uint8_t *key, uint32_t keyLen,
    const Rfc6979Chunk *chunks, uint32_t chunkNum, uint8_t *out, uint32_t outLen)
{
    if (ctx == NULL || out == NULL || (key == NULL && keyLen != 0) || (chunks == NULL && chunkNum != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    uint32_t useLen = outLen;
    CRYPT_HMAC_Ctx *hmacCtx = NULL;
    ret = NewHmacCtx(ctx, macId, &hmacCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_HMAC_Init(hmacCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    for (uint32_t i = 0; i < chunkNum; i++) {
        if (chunks[i].len == 0) {
            continue;
        }
        if (chunks[i].data == NULL) {
            ret = CRYPT_NULL_INPUT;
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        ret = CRYPT_HMAC_Update(hmacCtx, chunks[i].data, chunks[i].len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
    }
    ret = CRYPT_HMAC_Final(hmacCtx, out, &useLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    CRYPT_HMAC_FreeCtx(hmacCtx);
    return ret;
}

static int32_t UpdateV(const CRYPT_ECDSA_Ctx *ctx, CRYPT_MAC_AlgId macId, const uint8_t *key, uint32_t keyLen,
    uint8_t *v, uint32_t vLen)
{
    const Rfc6979Chunk chunk = {v, vLen};
    return HmacOnce(ctx, macId, key, keyLen, &chunk, 1, v, vLen);
}

/* int2octets(priv), bits2octets(hash), DRBG V, DRBG K, and candidate T — one allocation, one cleanse+free. */

void ECDSA_Rfc6979Free(ECDSA_Rfc6979State *st)
{
    if (st == NULL) {
        return;
    }
    if (st->blob != NULL) {
        uint32_t total = st->qLen * 2u + st->hLen * 2u + st->tcap;
        BSL_SAL_CleanseData(st->blob, total);
        BSL_SAL_Free(st->blob);
        st->blob = NULL;
        st->bx = NULL;
        st->bh = NULL;
        st->v = NULL;
        st->key = NULL;
        st->t = NULL;
    }
    BN_Destroy(st->tmpK);
    st->tmpK = NULL;
    (void)memset(st, 0, sizeof(ECDSA_Rfc6979State));
}

static int32_t Rfc6979DrbgRetryAfterReject(ECDSA_Rfc6979State *st)
{
    uint8_t zero = 0x00;
    Rfc6979Chunk retryChunk[2] = {
        {st->v, st->hLen},
        {&zero, sizeof(zero)}
    };
    int32_t ret = HmacOnce(st->ctx, st->macId, st->key, st->hLen, retryChunk, 2, st->key, st->hLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = UpdateV(st->ctx, st->macId, st->key, st->hLen, st->v, st->hLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t ECDSA_Rfc6979Init(ECDSA_Rfc6979State *st, const CRYPT_ECDSA_Ctx *ctx, const BN_BigNum *paraN,
    CRYPT_MD_AlgId mdId, const uint8_t *hash, uint32_t hashLen)
{
    if (st == NULL || ctx == NULL || ctx->para == NULL || ctx->prvkey == NULL || paraN == NULL ||
        (hash == NULL && hashLen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)memset(st, 0, sizeof(ECDSA_Rfc6979State));

    uint32_t hLen = CRYPT_GetMdSizeById(mdId);
    if (hLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    CRYPT_MAC_AlgId macId = 0;
    int32_t ret = MdIdToHmacId(mdId, &macId);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t qlenBits = BN_Bits(paraN);
    if (qlenBits == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t qLen = BN_BITS_TO_BYTES(qlenBits);
    uint32_t hlenBits = hLen * 8;
    uint32_t tcap = ((qlenBits + hlenBits - 1) / hlenBits) * hLen;

    st->qLen = qLen;
    st->hLen = hLen;
    st->tcap = tcap;
    st->qlenBits = qlenBits;
    st->hlenBits = hlenBits;
    st->ctx = ctx;
    st->paraN = paraN;
    st->macId = macId;

    uint32_t blobLen = qLen * 2u + hLen * 2u + tcap;
    st->blob = BSL_SAL_Calloc(1, blobLen);
    if (st->blob == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    st->bx = st->blob;
    st->bh = st->blob + qLen;
    st->v = st->blob + qLen * 2u;
    st->key = st->blob + qLen * 2u + hLen;
    st->t = st->blob + qLen * 2u + hLen * 2u;

    uint32_t orderBits = BN_Bits(paraN);
    uint32_t tmpBits = qlenBits > orderBits ? qlenBits : orderBits;
    st->tmpK = BN_Create(tmpBits);
    if (st->tmpK == NULL) {
        ECDSA_Rfc6979Free(st);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memset(st->v, 0x01, hLen);
    ret = BnToOctets(ctx->prvkey, st->bx, qLen);
    if (ret != CRYPT_SUCCESS) {
        ECDSA_Rfc6979Free(st);
        return ret;
    }
    ret = Bits2Octets(paraN, qlenBits, hash, hashLen, st->bh, qLen);
    if (ret != CRYPT_SUCCESS) {
        ECDSA_Rfc6979Free(st);
        return ret;
    }

    uint8_t zero = 0x00;
    uint8_t one = 0x01;
    Rfc6979Chunk chunks[4] = {
        {st->v, hLen},
        {&zero, sizeof(zero)},
        {st->bx, qLen},
        {st->bh, qLen}
    };
    ret = HmacOnce(ctx, macId, st->key, hLen, chunks, 4, st->key, hLen);
    if (ret != CRYPT_SUCCESS) {
        ECDSA_Rfc6979Free(st);
        return ret;
    }
    ret = UpdateV(ctx, macId, st->key, hLen, st->v, hLen);
    if (ret != CRYPT_SUCCESS) {
        ECDSA_Rfc6979Free(st);
        return ret;
    }
    chunks[1].data = &one;
    ret = HmacOnce(ctx, macId, st->key, hLen, chunks, 4, st->key, hLen);
    if (ret != CRYPT_SUCCESS) {
        ECDSA_Rfc6979Free(st);
        return ret;
    }
    ret = UpdateV(ctx, macId, st->key, hLen, st->v, hLen);
    if (ret != CRYPT_SUCCESS) {
        ECDSA_Rfc6979Free(st);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t ECDSA_Rfc6979Next(ECDSA_Rfc6979State *st, BN_BigNum *k)
{
    if (st == NULL || st->blob == NULL || st->tmpK == NULL || k == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    const CRYPT_ECDSA_Ctx *ctx = st->ctx;
    const BN_BigNum *paraN = st->paraN;
    uint32_t qlenBits = st->qlenBits;
    uint32_t hLen = st->hLen;
    uint32_t hlenBits = st->hlenBits;
    uint32_t tcap = st->tcap;
    int32_t ret;

    for (int32_t attempt = 0; attempt < CRYPT_ECC_TRY_MAX_CNT; attempt++) {
        uint32_t tlenBits = 0;
        uint32_t generated = 0;
        while (tlenBits < qlenBits) {
            ret = UpdateV(ctx, st->macId, st->key, hLen, st->v, hLen);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            if (generated > tcap || hLen > tcap - generated) {
                ret = CRYPT_SECUREC_FAIL;
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            (void)memcpy(st->t + generated, st->v, hLen);
            generated += hLen;
            tlenBits += hlenBits;
        }
        ret = BN_Zeroize(st->tmpK);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        BN_BigNum *candidate = Bits2Int(paraN, qlenBits, st->t, generated);
        if (candidate == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ret = BN_Copy(st->tmpK, candidate);
        BN_Destroy(candidate);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (!BN_IsZero(st->tmpK) && BN_Cmp(st->tmpK, paraN) < 0) {
            ret = BN_Copy(k, st->tmpK);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            ret = Rfc6979DrbgRetryAfterReject(st);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            return CRYPT_SUCCESS;
        }

        ret = Rfc6979DrbgRetryAfterReject(st);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    BSL_ERR_PUSH_ERROR(CRYPT_ECDSA_ERR_TRY_CNT);
    return CRYPT_ECDSA_ERR_TRY_CNT;
}

#endif /* HITLS_CRYPTO_HMAC */

#endif /* HITLS_CRYPTO_ECDSA */
