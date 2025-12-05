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
#ifdef HITLS_CRYPTO_RSA

#include "crypt_utils.h"
#include "crypt_rsa.h"
#include "rsa_local.h"
#include "crypt_errno.h"
#include "securec.h"
#include "eal_md_local.h"

// rsa-decrypt Calculation used by Chinese Remainder Theorem(CRT). intermediate variables:
typedef struct {
    BN_BigNum *cP;
    BN_BigNum *cQ;
    BN_BigNum *mP;
    BN_BigNum *mQ;
    BN_Mont *montP;
    BN_Mont *montQ;
} RsaDecProcedurePara;

static int32_t InputRangeCheck(const BN_BigNum *input, const BN_BigNum *n, uint32_t bits)
{
    // The value range defined in RFC is [0, n - 1]. Because the operation result of 0, 1, n - 1 is relatively fixed,
    // it is considered invalid here. The actual valid value range is [2, n - 2].
    int32_t ret;
    BN_BigNum *nMinusOne = NULL;
    if (BN_IsZero(input) == true || BN_IsOne(input) == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    /* Allocate 8 extra bits to prevent calculation errors due to the feature of BigNum calculation. */
    nMinusOne = BN_Create(bits);
    if (nMinusOne == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = BN_SubLimb(nMinusOne, n, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BN_Destroy(nMinusOne);
        return ret;
    }
    if (BN_Cmp(input, nMinusOne) >= 0) {
        ret = CRYPT_RSA_ERR_INPUT_VALUE;
        BSL_ERR_PUSH_ERROR(ret);
    }
    BN_Destroy(nMinusOne);
    return ret;
}

static int32_t AddZero(uint32_t bits, uint8_t *out, uint32_t *outLen)
{
    uint32_t i;
    uint32_t zeros = 0;
    uint32_t needBytes = BN_BITS_TO_BYTES(bits);
    /* Divide bits by 8 to obtain the byte length. If it is smaller than the key length, pad it with 0. */
    if ((*outLen) < needBytes) {
        /* Divide bits by 8 to obtain the byte length. If it is smaller than the key length, pad it with 0. */
        zeros = needBytes - (*outLen);
        if (memmove_s(out + zeros, needBytes - zeros, out, (*outLen)) != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }
        for (i = 0; i < zeros; i++) {
            out[i] = 0x0;
        }
    }
    *outLen = needBytes;
    return CRYPT_SUCCESS;
}

static int32_t ResultToOut(uint32_t bits, const BN_BigNum *result, uint8_t *out, uint32_t *outLen)
{
    int32_t ret = BN_Bn2Bin(result, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return AddZero(bits, out, outLen);
}

static int32_t AllocResultAndInputBN(uint32_t bits, BN_BigNum **result, BN_BigNum **inputBN,
    const uint8_t *input, uint32_t inputLen)
{
    if (inputLen > BN_BITS_TO_BYTES(bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    *result = BN_Create(bits + 1);
    *inputBN = BN_Create(bits);
    if (*result == NULL || *inputBN == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return BN_Bin2Bn(*inputBN, input, inputLen);
}

static int32_t CalcMontExp(CRYPT_RSA_PrvKey *prvKey,
    BN_BigNum *result, const BN_BigNum *input, BN_Optimizer *opt, bool consttime)
{
    int32_t ret;
    BN_Mont *mont = NULL;
    if (BN_IsZero(prvKey->n) || BN_IsZero(prvKey->d)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    mont = BN_MontCreate(prvKey->n);
    if (mont == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (consttime) {
        ret = BN_MontExpConsttime(result, input, prvKey->d, mont, opt);
    } else {
        ret = BN_MontExp(result, input, prvKey->d, mont, opt);
    }

    BN_MontDestroy(mont);
    return ret;
}

#if defined(HITLS_CRYPTO_RSA_ENCRYPT) || defined(HITLS_CRYPTO_RSA_VERIFY) || defined(HITLS_CRYPTO_RSA_SIGN)
int32_t  CRYPT_RSA_PubEnc(const CRYPT_RSA_Ctx *ctx, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    BN_BigNum *inputBN = NULL;
    BN_BigNum *result = NULL;
    if (ctx == NULL || input == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_RSA_PubKey *pubKey = ctx->pubKey;
    if (pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    if ((*outLen) < BN_BITS_TO_BYTES(bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
    }
    BN_Optimizer *optimizer = BN_OptimizerCreate();
    if (optimizer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF_EX(AllocResultAndInputBN(bits, &result, &inputBN, input, inputLen), ret);
    GOTO_ERR_IF_EX(InputRangeCheck(inputBN, pubKey->n, bits), ret);

    // pubKey->mont: Ensure that this value is not empty when the public key is set or generated.
    GOTO_ERR_IF(BN_MontExp(result, inputBN, pubKey->e, pubKey->mont, optimizer), ret);
    ret = ResultToOut(bits, result, out, outLen);
ERR:
    BN_Destroy(result);
    BN_Destroy(inputBN);
    BN_OptimizerDestroy(optimizer);
    return ret;
}
#endif

/* Release intermediate variables. */
static void RsaDecProcedureFree(RsaDecProcedurePara *para)
{
    if (para == NULL) {
        return;
    }
    BN_Destroy(para->cP);
    BN_Destroy(para->cQ);
    BN_Destroy(para->mP);
    BN_Destroy(para->mQ);
    BN_MontDestroy(para->montP);
    BN_MontDestroy(para->montQ);
}

/* Apply for intermediate variables. */
static int32_t RsaDecProcedureAlloc(RsaDecProcedurePara *para, uint32_t bits, const CRYPT_RSA_PrvKey *priKey)
{
    para->cP = BN_Create(bits);
    para->cQ = BN_Create(bits);
    para->mP = BN_Create(bits);
    para->mQ = BN_Create(bits);
    para->montP = BN_MontCreate(priKey->p);
    para->montQ = BN_MontCreate(priKey->q);
    bool allocFail = para->cP == NULL || para->cQ == NULL ||
                     para->mP == NULL || para->mQ == NULL || para->montP == NULL || para->montQ == NULL;
    if (allocFail == true) {
        RsaDecProcedureFree(para);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

/* rsa decryption calculation by CRT. Message is the BigNum converted from the original input ciphertext. */
static int32_t NormalDecProcedure(const CRYPT_RSA_Ctx *ctx, const BN_BigNum *message, BN_BigNum *result,
    BN_Optimizer *opt)
{
    CRYPT_RSA_PrvKey *priKey = ctx->prvKey;
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    RsaDecProcedurePara procedure = {0}; // Temporary variable
    /* Apply for temporary variable */
    int32_t ret = RsaDecProcedureAlloc(&procedure, bits, priKey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    /* cP = M mod P where inp = M = Message */
    ret = BN_Mod(procedure.cP, message, priKey->p, opt);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    /* cQ = M mod Q where inp = M = Message */
    ret = BN_Mod(procedure.cQ, message, priKey->q, opt);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    /* mP = cP^dP mod p */
    ret = BN_MontExpConsttime(procedure.mP, procedure.cP, priKey->dP, procedure.montP, opt);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    /* mQ = cQ^dQ mod q */
    ret = BN_MontExpConsttime(procedure.mQ, procedure.cQ, priKey->dQ, procedure.montQ, opt);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    /* result = (mP - mQ) mod p */
    ret = BN_ModSub(result, procedure.mP, procedure.mQ, priKey->p, opt);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    /* result = result * qInv mod p */
    ret = MontMulCore(result, result, priKey->qInv, procedure.montP, opt);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    /* result = result * q */
    ret = BN_Mul(result, result, priKey->q, opt);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    /* result = result + mQ */
    ret = BN_Add(result, result, procedure.mQ);
EXIT:
    RsaDecProcedureFree(&procedure);
    return ret;
}

#ifdef HITLS_CRYPTO_RSA_BLINDING
static int32_t RSA_GetSub(const BN_BigNum *p, const BN_BigNum *q, BN_BigNum *r1, BN_BigNum *r2)
{
    int32_t ret = BN_SubLimb(r1, p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_SubLimb(r2, q, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t RSA_GetL(BN_BigNum *l, BN_BigNum *u, BN_BigNum *r1, BN_BigNum *r2, BN_Optimizer *opt)
{
    int32_t ret = BN_Mul(l, r1, r2, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BN_Gcd(u, r1, r2, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BN_Div(l, NULL, l, u, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static BN_BigNum *RSA_GetPublicExp(const BN_BigNum *d, const BN_BigNum *p,
    const BN_BigNum *q, uint32_t bits, BN_Optimizer *opt)
{
    int32_t ret;
    /* Apply for the temporary space of the BN object */
    BN_BigNum *l = BN_Create(bits);
    BN_BigNum *r1 = BN_Create(bits >> 1);
    BN_BigNum *r2 = BN_Create(bits >> 1);
    BN_BigNum *u = BN_Create(bits + 1);
    BN_BigNum *e = BN_Create(bits);

    if (l == NULL || r1 == NULL || r2 == NULL || u == NULL || e == NULL) {
        ret = CRYPT_NULL_INPUT;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = RSA_GetSub(p, q, r1, r2);
    // The push error in GetSub can be used to locate the fault. Therefore, it is not added here.
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = RSA_GetL(l, u, r1, r2, opt);
    // The push error in GetL can be used to locate the fault. Therefore, it is not added here.
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = BN_ModInv(e, d, l, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    BN_Destroy(r1);
    BN_Destroy(r2);
    BN_Destroy(l);
    BN_Destroy(u);
    if (ret != CRYPT_SUCCESS) {
        BN_Destroy(e);
        e = NULL;
    }
    return e;
}

static int32_t RSA_InitBlind(CRYPT_RSA_Ctx *ctx, BN_Optimizer *opt)
{
    uint32_t bits = BN_Bits(ctx->prvKey->n);
    bool needDestoryE = false;
    BN_BigNum *e = ctx->prvKey->e;
    if (e == NULL || BN_IsZero(e)) {
        e = RSA_GetPublicExp(ctx->prvKey->d, ctx->prvKey->p, ctx->prvKey->q, bits, opt);
        if (e == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_E_VALUE);
            return CRYPT_RSA_ERR_E_VALUE;
        }
        needDestoryE = true;
    }

    ctx->scBlind = RSA_BlindNewCtx();

    int32_t ret = RSA_BlindCreateParam(LIBCTX_FROM_RSA_CTX(ctx), ctx->scBlind, e, ctx->prvKey->n, bits, opt);
    if (needDestoryE) {
        BN_Destroy(e);
    }
    return ret;
}

static int32_t RSA_BlindProcess(CRYPT_RSA_Ctx *ctx, BN_BigNum *message, BN_Optimizer *opt)
{
    int32_t ret;
    if (ctx->scBlind == NULL) {
        ret = RSA_InitBlind(ctx, opt);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    return RSA_BlindCovert(ctx->scBlind, message, ctx->prvKey->n, opt);
}
#endif

static int32_t RSA_AllocAndCheck(const CRYPT_RSA_Ctx *ctx, const uint8_t *input, uint32_t inputLen,
    BN_BigNum **result, BN_BigNum **message)
{
    int32_t ret;
    if (ctx->prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }

    uint32_t bits = CRYPT_RSA_GetBits(ctx);

    ret = AllocResultAndInputBN(bits, result, message, input, inputLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = InputRangeCheck(*message, ctx->prvKey->n, bits);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    return ret;
ERR:
    BN_Destroy(*result);
    BN_Destroy(*message);
    return ret;
}

static int32_t RSA_PrvProcess(const CRYPT_RSA_Ctx *ctx, BN_BigNum *message, BN_BigNum *result, BN_Optimizer *opt)
{
#ifndef HITLS_CRYPTO_RSA_BLINDING
    (void)opt;
#endif
    int32_t ret;
#ifdef HITLS_CRYPTO_RSA_BLINDING
    // blinding
    if ((ctx->flags & CRYPT_RSA_BLINDING) != 0) {
        ret = RSA_BlindProcess((CRYPT_RSA_Ctx *)(uintptr_t)ctx, message, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
#endif
    /* If ctx->prvKey->p is set to 0, the standard mode is used for RSA decryption.
       Otherwise, the CRT mode is used for RSA decryption. */
    if (BN_IsZero(ctx->prvKey->p)) {
        ret = CalcMontExp(ctx->prvKey, result, message, opt, true);
    } else {
        ret = NormalDecProcedure(ctx, message, result, opt);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

#ifdef HITLS_CRYPTO_RSA_BLINDING
    // unblinding
    if ((ctx->flags & CRYPT_RSA_BLINDING) != 0) {
        ret = RSA_BlindInvert(ctx->scBlind, result, ctx->prvKey->n, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
    }
#endif
    return ret;
}

int32_t CRYPT_RSA_PrvDec(const CRYPT_RSA_Ctx *ctx, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    uint32_t bits;
    BN_BigNum *result = NULL;
    BN_BigNum *message = NULL;
    BN_Optimizer *opt = NULL;

    if (ctx == NULL || input == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }

    bits = CRYPT_RSA_GetBits(ctx);
    if ((*outLen) < BN_BITS_TO_BYTES(bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
    }
    opt = BN_OptimizerCreate();
    if (opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = RSA_AllocAndCheck(ctx, input, inputLen, &result, &message);
    if (ret != CRYPT_SUCCESS) {
        BN_OptimizerDestroy(opt);
        return ret;
    }

    (void)OptimizerStart(opt);
    ret = RSA_PrvProcess(ctx, message, result, opt);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = ResultToOut(bits, result, out, outLen);
EXIT:
    OptimizerEnd(opt);
    BN_OptimizerDestroy(opt);
    BN_Destroy(result);
    BN_Destroy(message);
    return ret;
}

#if defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY)
static uint32_t GetHashLen(const CRYPT_RSA_Ctx *ctx)
{
    if (ctx->pad.type == EMSA_PKCSV15) {
        return CRYPT_GetMdSizeById(ctx->pad.para.pkcsv15.mdId);
    }

    return (uint32_t)(ctx->pad.para.pss.mdMeth.mdSize);
}

static int32_t CheckHashLen(uint32_t inputLen)
{
    if (inputLen > 64) {  // 64 is the maximum of the hash length.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_ALGID);
        return CRYPT_RSA_ERR_ALGID;
    }
    // Inconsistent length
    BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_ALGID);
    return CRYPT_RSA_ERR_ALGID;
}
#endif

#if defined(HITLS_CRYPTO_RSA_EMSA_PSS) && defined(HITLS_CRYPTO_RSA_SIGN)
static int32_t PssPad(CRYPT_RSA_Ctx *ctx, const uint8_t *input, uint32_t inputLen, uint8_t *out, uint32_t outLen)
{
    uint32_t saltLen = 0;
    bool kat = false; // mark
    if (ctx->pad.salt.data != NULL) {
        // If the salt contains data, that is the kat test.
        kat = true;
    }
    if (kat) {
        saltLen = ctx->pad.salt.len;
    } else if (ctx->pad.para.pss.saltLen != 0) {
        saltLen = ctx->pad.para.pss.saltLen;
    }
    int32_t ret = CRYPT_RSA_SetPss(ctx, &ctx->pad.para.pss.mdMeth, &ctx->pad.para.pss.mgfMeth,
        saltLen, input, inputLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif

#ifdef HITLS_CRYPTO_RSA_BSSA

static int32_t BlindInputCheck(const CRYPT_RSA_Ctx *ctx, const uint8_t *input, uint32_t inputLen,
    const uint8_t *out, const uint32_t *outLen)
{
    if (ctx == NULL || input == NULL || inputLen == 0 || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pubKey == NULL) {
        // Check whether the private key information exists.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_NO_PUBKEY_INFO);
        return CRYPT_RSA_ERR_NO_PUBKEY_INFO;
    }
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    if ((*outLen) < BN_BITS_TO_BYTES(bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
    }
    if (ctx->pad.type != EMSA_PSS) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_PADDING_NOT_SUPPORTED);
        return CRYPT_RSA_PADDING_NOT_SUPPORTED;
    }
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_RSA_SIGN
static RSA_BlindParam *BssaParamNew(void)
{
    RSA_BlindParam *param = BSL_SAL_Calloc(1u, sizeof(RSA_BlindParam));
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    param->para.bssa = RSA_BlindNewCtx();
    if (param->para.bssa == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(param);
        return NULL;
    }
    param->type = RSABSSA;
    return param;
}

static int32_t BssaBlind(CRYPT_RSA_Ctx *ctx, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    uint32_t padLen = BN_BITS_TO_BYTES(bits);
    RSA_BlindParam *param = NULL;
    BN_BigNum *e = ctx->pubKey->e;
    BN_BigNum *n = ctx->pubKey->n;
    RSA_Blind *blind = NULL;
    uint8_t *pad = BSL_SAL_Malloc(padLen);
    BN_Optimizer *opt = BN_OptimizerCreate();
    BN_BigNum *enMsg = BN_Create(bits);
    BN_BigNum *gcd = BN_Create(bits);
    if (pad == NULL || opt == NULL || enMsg == NULL || gcd == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
   // encoded_msg = EMSA-PSS-ENCODE(msg, bit_len(n))
    GOTO_ERR_IF(PssPad(ctx, input, inputLen, pad, padLen), ret);
    GOTO_ERR_IF(BN_Bin2Bn(enMsg, pad, padLen), ret);

    // Check if bigNumOut and n are coprime using GCD
    GOTO_ERR_IF(BN_Gcd(gcd, enMsg, n, opt), ret);

    // Check if gcd is 1
    if (!BN_IsOne(gcd)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        ret = CRYPT_INVALID_ARG;
        goto ERR;
    }

    param = ctx->blindParam;
    if (param == NULL) {
        param = BssaParamNew();
        if (param == NULL) {
            ret = CRYPT_MEM_ALLOC_FAIL;
            goto ERR;
        }
        GOTO_ERR_IF(RSA_BlindCreateParam(LIBCTX_FROM_RSA_CTX(ctx), param->para.bssa, e, n, bits, opt), ret);
    }
    blind = param->para.bssa;
    GOTO_ERR_IF(BN_ModMul(enMsg, enMsg, blind->r, n, opt), ret);
    GOTO_ERR_IF(ResultToOut(bits, enMsg, out, outLen), ret);
    ctx->blindParam = param;
ERR:
    if (ret != CRYPT_SUCCESS && ctx->blindParam == NULL && param != NULL) {
        RSA_BlindFreeCtx(param->para.bssa);
        BSL_SAL_Free(param);
    }
    BN_Destroy(enMsg);
    BN_Destroy(gcd);
    BSL_SAL_FREE(pad);
    BN_OptimizerDestroy(opt);
    return ret;
}

static int32_t BlindSign(CRYPT_RSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    int32_t ret;
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    uint32_t sLen = BN_BITS_TO_BYTES(bits);
    uint32_t mLen = BN_BITS_TO_BYTES(bits);
    uint8_t *s = BSL_SAL_Malloc(sLen);
    uint8_t *m = BSL_SAL_Malloc(mLen);
    if (s == NULL || m == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }

    /* Step 1: Compute blind signature using RSA private key operation */
    ret = CRYPT_RSA_PrvDec(ctx, data, dataLen, s, &sLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    /* Step 2: Verify the signature by applying the public key operation
     * This step ensures the signature is valid under the RSA key pair */
    ret = CRYPT_RSA_PubEnc(ctx, s, sLen, m, &mLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    /* Step 3: Verify that the result matches the input blinded message
     * This ensures the signature operation was performed correctly */
    if (dataLen != mLen || memcmp(data, m, mLen) != 0) {
        ret = CRYPT_RSA_NOR_VERIFY_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    /* Copy the blind signature to output buffer */
    (void)memcpy_s(sign, *signLen, s, sLen);
    *signLen = sLen;
EXIT:
    BSL_SAL_FREE(m);
    BSL_SAL_FREE(s);
    return ret;
}

int32_t CRYPT_RSA_Blind(CRYPT_RSA_Ctx *ctx, int32_t algId, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen)
{
    int32_t ret = BlindInputCheck(ctx, input, inputLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if ((int32_t)ctx->pad.para.pss.mdId != algId) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_MD_ALGID);
        return CRYPT_RSA_ERR_MD_ALGID;
    }
    uint8_t hash[64]; // 64 is max hash len
    uint32_t hashLen = sizeof(hash);
    void *libCtx = LIBCTX_FROM_RSA_CTX(ctx);
    ret = EAL_Md(algId, libCtx, MDATTR_FROM_RSA_CTX(ctx), input, inputLen, hash, &hashLen, false, libCtx != NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if ((ctx->flags & CRYPT_RSA_BSSA) != 0) {
        ret = BssaBlind(ctx, hash, hashLen, out, outLen);
    } else {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_BLIND_TYPE);
        ret = CRYPT_RSA_ERR_BLIND_TYPE;
    }
    return ret;
}
#endif // HITLS_CRYPTO_RSA_SIGN

#ifdef HITLS_CRYPTO_RSA_VERIFY
static int32_t BssaUnBlind(const CRYPT_RSA_Ctx *ctx, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen)
{
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    uint32_t sigLen = BN_BITS_TO_BYTES(bits);
    if (inputLen != sigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret;
    RSA_Blind *blind = NULL;
    BN_BigNum *n = ctx->pubKey->n;
    BN_Optimizer *opt = BN_OptimizerCreate();
    BN_BigNum *z = BN_Create(bits);
    BN_BigNum *s = BN_Create(bits);
    if (opt == NULL || z == NULL || s == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    if (ctx->blindParam == NULL || ctx->blindParam->para.bssa == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_NO_BLIND_INFO);
        ret = CRYPT_RSA_ERR_NO_BLIND_INFO;
        goto ERR;
    }
    if (ctx->blindParam->type != RSABSSA) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_BLIND_TYPE);
        ret = CRYPT_RSA_ERR_BLIND_TYPE;
        goto ERR;
    }
    blind = ctx->blindParam->para.bssa;
    GOTO_ERR_IF(BN_Bin2Bn(z, input, inputLen), ret);
    GOTO_ERR_IF(BN_ModMul(s, z, blind->rInv, n, opt), ret);
    GOTO_ERR_IF(ResultToOut(bits, s, out, outLen), ret);
ERR:
    BN_Destroy(z);
    BN_Destroy(s);
    BN_OptimizerDestroy(opt);
    return ret;
}

int32_t CRYPT_RSA_UnBlind(const CRYPT_RSA_Ctx *ctx, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen)
{
    int32_t ret = BlindInputCheck(ctx, input, inputLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if ((ctx->flags & CRYPT_RSA_BSSA) != 0) {
        ret = BssaUnBlind(ctx, input, inputLen, out, outLen);
    } else {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_BLIND_TYPE);
        ret = CRYPT_RSA_ERR_BLIND_TYPE;
    }
    return ret;
}
#endif // HITLS_CRYPTO_RSA_VERIFY
#endif // HITLS_CRYPTO_RSA_BSSA

#ifdef HITLS_CRYPTO_RSA_SIGN
static int32_t SignInputCheck(const CRYPT_RSA_Ctx *ctx, const uint8_t *input, uint32_t inputLen,
    const uint8_t *out, const uint32_t *outLen)
{
    if (ctx == NULL || input == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->prvKey == NULL) {
        // Check whether the private key information exists.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    // Check whether the length of the out is sufficient to place the signature information.
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    if ((*outLen) < BN_BITS_TO_BYTES(bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
    }
    if (ctx->pad.type != EMSA_PKCSV15 && ctx->pad.type != EMSA_PSS) {
        // No padding type is set.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_PAD_NO_SET_ERROR);
        return CRYPT_RSA_PAD_NO_SET_ERROR;
    }
#ifdef HITLS_CRYPTO_RSA_BSSA
    if ((ctx->flags & CRYPT_RSA_BSSA) != 0) {
        if (BN_BITS_TO_BYTES(bits) != inputLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
            return CRYPT_RSA_ERR_INPUT_VALUE;
        }
        return CRYPT_SUCCESS;
    }
#endif
    if (GetHashLen(ctx) != inputLen) {
        return CheckHashLen(inputLen);
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_SignData(CRYPT_RSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    int32_t ret = SignInputCheck(ctx, data, dataLen, sign, signLen);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
#ifdef HITLS_CRYPTO_RSA_BSSA
    if ((ctx->flags & CRYPT_RSA_BSSA) != 0) {
        return BlindSign(ctx, data, dataLen, sign, signLen);
    }
#endif
    uint32_t padLen = BN_BITS_TO_BYTES(CRYPT_RSA_GetBits(ctx));
    uint8_t *pad = BSL_SAL_Malloc(padLen);
    RETURN_RET_IF(pad == NULL, CRYPT_MEM_ALLOC_FAIL);
    switch (ctx->pad.type) {
#ifdef HITLS_CRYPTO_RSA_EMSA_PKCSV15
        case EMSA_PKCSV15:
            ret = CRYPT_RSA_SetPkcsV15Type1(ctx->pad.para.pkcsv15.mdId, data, dataLen, pad, padLen);
            break;
#endif
#ifdef HITLS_CRYPTO_RSA_EMSA_PSS
        case EMSA_PSS:
            ret = PssPad(ctx, data, dataLen, pad, padLen);
            break;
#endif
        default: // This branch cannot be entered because it's been verified before.
            ret = CRYPT_RSA_PAD_NO_SET_ERROR;
            break;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = CRYPT_RSA_PrvDec(ctx, pad, padLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    (void)memset_s(pad, padLen, 0, padLen);
    BSL_SAL_FREE(pad);
    return ret;
}

int32_t CRYPT_RSA_Sign(CRYPT_RSA_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    uint8_t hash[64]; // 64 is max hash len
    uint32_t hashLen = sizeof(hash) / sizeof(hash[0]);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    void *tmpLibCtx = LIBCTX_FROM_RSA_CTX(ctx);
    int32_t ret = EAL_Md(algId, tmpLibCtx, MDATTR_FROM_RSA_CTX(ctx), data, dataLen, hash, &hashLen, true,
        tmpLibCtx != NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_RSA_SignData(ctx, hash, hashLen, sign, signLen);
}
#endif // HITLS_CRYPTO_RSA_SIGN

#ifdef HITLS_CRYPTO_RSA_VERIFY
static int32_t VerifyInputCheck(const CRYPT_RSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign)
{
    if (ctx == NULL || data == NULL || sign == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pubKey == NULL) {
        // Check whether the private key information exists.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    if (ctx->pad.type != EMSA_PKCSV15 && ctx->pad.type != EMSA_PSS) {
        // No padding type is set.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_PAD_NO_SET_ERROR);
        return CRYPT_RSA_PAD_NO_SET_ERROR;
    }
    if (GetHashLen(ctx) != dataLen) {
        return CheckHashLen(dataLen);
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_VerifyData(CRYPT_RSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
#ifdef HITLS_CRYPTO_RSA_EMSA_PSS
    uint32_t saltLen = 0;
#endif
    int32_t ret = VerifyInputCheck(ctx, data, dataLen, sign);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    uint32_t padLen = BN_BITS_TO_BYTES(bits);
    uint8_t *pad = BSL_SAL_Malloc(padLen);
    if (pad == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = CRYPT_RSA_PubEnc(ctx, sign, signLen, pad, &padLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    switch (ctx->pad.type) {
#ifdef HITLS_CRYPTO_RSA_EMSA_PKCSV15
        case EMSA_PKCSV15:
            ret = CRYPT_RSA_VerifyPkcsV15Type1(ctx->pad.para.pkcsv15.mdId, pad, padLen,
                data, dataLen);
            break;
#endif
#ifdef HITLS_CRYPTO_RSA_EMSA_PSS
        case EMSA_PSS:
            saltLen = (uint32_t)ctx->pad.para.pss.saltLen;
            if (ctx->pad.para.pss.mdMeth.id == 0) {
                ret = CRYPT_NULL_INPUT;
                goto EXIT;
            }
            ret = CRYPT_RSA_VerifyPss(ctx, &ctx->pad.para.pss.mdMeth, &ctx->pad.para.pss.mgfMeth,
                saltLen, data, dataLen, pad, padLen);
            break;
#endif
        default: // This branch cannot be entered because it's been verified before.
            ret = CRYPT_RSA_PAD_NO_SET_ERROR;
            BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    (void)memset_s(pad, padLen, 0, padLen);
    BSL_SAL_FREE(pad);
    return ret;
}

int32_t CRYPT_RSA_Verify(CRYPT_RSA_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
    uint8_t hash[64]; // 64 is max hash len
    uint32_t hashLen = sizeof(hash) / sizeof(hash[0]);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    void *libCtx = LIBCTX_FROM_RSA_CTX(ctx);
    int32_t ret = EAL_Md(algId, libCtx, MDATTR_FROM_RSA_CTX(ctx), data, dataLen, hash, &hashLen, true, libCtx != NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_RSA_VerifyData(ctx, hash, hashLen, sign, signLen);
}
#endif // HITLS_CRYPTO_RSA_VERIFY

#if defined(HITLS_CRYPTO_RSA_ENCRYPT) || defined(HITLS_CRYPTO_RSA_RECOVER)
static int32_t EncryptInputCheck(const CRYPT_RSA_Ctx *ctx, const uint8_t *input, uint32_t inputLen,
    const uint8_t *out, const uint32_t *outLen)
{
    if (ctx == NULL || (input == NULL && inputLen != 0) || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pubKey == NULL) {
        // Check whether the public key information exists.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    // Check whether the length of the out is sufficient to place the encryption information.
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    if ((*outLen) < BN_BITS_TO_BYTES(bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
    }
    if (inputLen > BN_BITS_TO_BYTES(bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_ENC_BITS);
        return CRYPT_RSA_ERR_ENC_BITS;
    }
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_RSA_ENCRYPT
int32_t CRYPT_RSA_Encrypt(CRYPT_RSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen)
{
    uint32_t bits, padLen;
    uint8_t *pad = NULL;
    int32_t ret = EncryptInputCheck(ctx, data, dataLen, out, outLen);
    // The static function has pushed an error. The push error is not repeated here.
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    bits = CRYPT_RSA_GetBits(ctx);
    padLen = BN_BITS_TO_BYTES(bits);
    pad = BSL_SAL_Malloc(padLen);
    if (pad == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    switch (ctx->pad.type) {
#if defined(HITLS_CRYPTO_RSAES_PKCSV15_TLS) || defined(HITLS_CRYPTO_RSAES_PKCSV15)
        case RSAES_PKCSV15_TLS:
        case RSAES_PKCSV15:
            ret = CRYPT_RSA_SetPkcsV15Type2(LIBCTX_FROM_RSA_CTX(ctx), data, dataLen, pad, padLen);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                goto EXIT;
            }
            break;
#endif
#ifdef HITLS_CRYPTO_RSAES_OAEP
        case RSAES_OAEP:
            ret = CRYPT_RSA_SetPkcs1Oaep(ctx, data, dataLen, pad, padLen);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                goto EXIT;
            }
            break;
#endif
#ifdef HITLS_CRYPTO_RSA_NO_PAD
        case RSA_NO_PAD:
            if (dataLen != padLen) {
                ret = CRYPT_RSA_ERR_ENC_INPUT_NOT_ENOUGH;
                BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_ENC_INPUT_NOT_ENOUGH);
                goto EXIT;
            }
            (void)memcpy_s(pad, padLen, data, dataLen);
            break;
#endif
        default:
            ret = CRYPT_RSA_PAD_NO_SET_ERROR;
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
    }

    ret = CRYPT_RSA_PubEnc(ctx, pad, padLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    (void)memset_s(pad, padLen, 0, padLen);
    BSL_SAL_FREE(pad);
    return ret;
}
#endif // HITLS_CRYPTO_RSA_ENCRYPT

#ifdef HITLS_CRYPTO_RSA_DECRYPT
static int32_t DecryptInputCheck(const CRYPT_RSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    const uint8_t *out, const uint32_t *outLen)
{
    if (ctx == NULL || data == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->prvKey == NULL) {
        // Check whether the private key information exists.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }

    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    if (dataLen != BN_BITS_TO_BYTES(bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_DEC_BITS);
        return CRYPT_RSA_ERR_DEC_BITS;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_Decrypt(CRYPT_RSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out, uint32_t *outLen)
{
    uint8_t *pad = NULL;
    int32_t ret = DecryptInputCheck(ctx, data, dataLen, out, outLen);
    // The static function has pushed an error. The push error is not repeated here.
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    uint32_t padLen = BN_BITS_TO_BYTES(bits);
    pad = BSL_SAL_Malloc(padLen);
    if (pad == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = CRYPT_RSA_PrvDec(ctx, data, dataLen, pad, &padLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    switch (ctx->pad.type) {
#ifdef HITLS_CRYPTO_RSAES_OAEP
        case RSAES_OAEP:
            ret = CRYPT_RSA_VerifyPkcs1Oaep(&ctx->pad.para.oaep, pad, padLen, ctx->label.data, ctx->label.len,
                out, outLen);
            break;
#endif
#ifdef HITLS_CRYPTO_RSAES_PKCSV15
        case RSAES_PKCSV15:
            ret = CRYPT_RSA_VerifyPkcsV15Type2(pad, padLen, out, outLen);
            break;
#endif
#ifdef HITLS_CRYPTO_RSAES_PKCSV15_TLS
        case RSAES_PKCSV15_TLS:
            ret = CRYPT_RSA_VerifyPkcsV15Type2TLS(pad, padLen, out, outLen);
            break;
#endif
#ifdef HITLS_CRYPTO_RSA_NO_PAD
        case RSA_NO_PAD:
            if (memcpy_s(out, *outLen, pad, padLen) != EOK) {
                ret = CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
                BSL_ERR_PUSH_ERROR(CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
                goto EXIT;
            }
            *outLen = padLen;
            break;
#endif
        default:
            ret = CRYPT_RSA_PAD_NO_SET_ERROR;
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
    }
EXIT:
    BSL_SAL_CleanseData(pad, padLen);
    BSL_SAL_FREE(pad);
    return ret;
}
#endif // HITLS_CRYPTO_RSA_DECRYPT

#ifdef HITLS_CRYPTO_RSA_RECOVER
int32_t CRYPT_RSA_Recover(CRYPT_RSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out, uint32_t *outLen)
{
    int32_t ret = EncryptInputCheck(ctx, data, dataLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    RETURN_RET_IF(data == NULL, CRYPT_NULL_INPUT);
    uint32_t emLen = BN_BITS_TO_BYTES(CRYPT_RSA_GetBits(ctx));
    uint8_t *emMsg = BSL_SAL_Malloc(emLen);
    if (emMsg == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_RSA_PubEnc(ctx, data, dataLen, emMsg, &emLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    switch (ctx->pad.type) { // Remove padding based on the padding type to obtain the plaintext.
#ifdef HITLS_CRYPTO_RSA_EMSA_PKCSV15
        case RSAES_PKCSV15:
            ret = CRYPT_RSA_UnPackPkcsV15Type1(emMsg, emLen, out, outLen);
            break;
#endif
#ifdef HITLS_CRYPTO_RSA_NO_PAD
        case RSA_NO_PAD:
            if (memcpy_s(out, *outLen, emMsg, emLen) != EOK) {
                BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
                ret = CRYPT_SECUREC_FAIL;
                goto ERR;
            }
            *outLen = emLen;
            break;
#endif
        default:
            ret = CRYPT_RSA_PAD_NO_SET_ERROR;
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
    }
ERR:
    (void)memset_s(emMsg, emLen, 0, emLen);
    BSL_SAL_FREE(emMsg);
    return ret;
}
#endif // HITLS_CRYPTO_RSA_RECOVER

#endif /* HITLS_CRYPTO_RSA */