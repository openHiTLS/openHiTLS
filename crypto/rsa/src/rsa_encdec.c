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
#include "bsl_sal.h"
#include "securec.h"
#include "bsl_err_internal.h"


// rsa-decrypt Calculation used by Chinese Remainder Theorem(CRT). intermediate variables:
typedef struct {
    BN_Optimizer *optimizer;
    BN_BigNum *cP;
    BN_BigNum *cQ;
    BN_BigNum *mP;
    BN_BigNum *mQ;
    BN_Mont *montP;
    BN_Mont *montQ;
} RsaDecProcedurePara;

static int32_t InputRangeCheck(const BN_BigNum *input, const BN_BigNum *n)
{
    // The value range defined in RFC is [0, n - 1]. Because the operation result of 0, 1, n - 1 is relatively fixed,
    // it is considered invalid here. The actual valid value range is [2, n - 2].
    int32_t ret;
    BN_BigNum *nMinusOne = NULL;
    if (BN_IsLimb(input, 0) == true || BN_IsLimb(input, 1) == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    /* Allocate 8 extra bits to prevent calculation errors due to the feature of BigNum calculation. */
    nMinusOne = BN_Create(BN_Bits(n) + 8);
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
    int32_t ret;
    uint32_t i;
    uint32_t zeros = 0;
    /* Divide bits by 8 to obtain the byte length. If it is smaller than the key length, pad it with 0. */
    if ((*outLen) < BN_BITS_TO_BYTES(bits)) {
        /* Divide bits by 8 to obtain the byte length. If it is smaller than the key length, pad it with 0. */
        zeros = BN_BITS_TO_BYTES(bits) - (*outLen);
        ret = memmove_s(out + zeros, BN_BITS_TO_BYTES(bits) - zeros, out, (*outLen));
        if (ret != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }
        for (i = 0; i < zeros; i++) {
            out[i] = 0x0;
        }
    }
    *outLen = BN_BITS_TO_BYTES(bits);
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

static int32_t CalcMontExp(const BN_BigNum *n, const BN_BigNum *eOrd,
    BN_BigNum *result, const BN_BigNum *input, bool consttime)
{
    int32_t ret;
    BN_Optimizer *optimizer = NULL;
    BN_Mont *mont = NULL;
    if (BN_IsZero(n) || BN_IsZero(eOrd)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    optimizer = BN_OptimizerCreate();
    mont = BN_MontCreate(n);
    if (optimizer == NULL || mont == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    if (consttime) {
        ret = BN_MontExpConsttime(result, input, eOrd, mont, optimizer);
    } else {
        ret = BN_MontExp(result, input, eOrd, mont, optimizer);
    }
ERR:
    BN_OptimizerDestroy(optimizer);
    BN_MontDestroy(mont);
    return ret;
}

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
    GOTO_ERR_IF_EX(InputRangeCheck(inputBN, pubKey->n), ret);

    // pubKey->mont: Ensure that this value is not empty when the public key is set or generated.
    GOTO_ERR_IF(BN_MontExp(result, inputBN, pubKey->e, pubKey->mont, optimizer), ret);
    ret = ResultToOut(bits, result, out, outLen);
ERR:
    BN_Destroy(result);
    BN_Destroy(inputBN);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

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
    BN_OptimizerDestroy(para->optimizer);
    BN_MontDestroy(para->montP);
    BN_MontDestroy(para->montQ);
    return;
}

/* Apply for intermediate variables. */
static int32_t RsaDecProcedureAlloc(RsaDecProcedurePara *para, uint32_t bits, const CRYPT_RSA_PrvKey *priKey)
{
    para->optimizer = BN_OptimizerCreate();
    para->cP = BN_Create(bits);
    para->cQ = BN_Create(bits);
    para->mP = BN_Create(bits);
    para->mQ = BN_Create(bits);
    para->montP = BN_MontCreate(priKey->p);
    para->montQ = BN_MontCreate(priKey->q);
    bool creatFailed = (para->optimizer == NULL || para->cP == NULL || para->cQ == NULL ||
        para->mP == NULL || para->mQ == NULL || para->montP == NULL || para->montQ == NULL);
    if (creatFailed) {
        RsaDecProcedureFree(para);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

/* rsa decryption calculation by CRT. Message is the BigNum converted from the original input ciphertext. */
static int32_t NormalDecProcedure(
    const CRYPT_RSA_Ctx *ctx, const BN_BigNum *message, BN_BigNum *result)
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
    ret = BN_Mod(procedure.cP, message, priKey->p, procedure.optimizer);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    /* cQ = M mod Q where inp = M = Message */
    ret = BN_Mod(procedure.cQ, message, priKey->q, procedure.optimizer);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    /* mP = cP^dP mod p */
    ret = BN_MontExpConsttime(procedure.mP, procedure.cP, priKey->dP, procedure.montP, procedure.optimizer);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    /* mQ = cQ^dQ mod q */
    ret = BN_MontExpConsttime(procedure.mQ, procedure.cQ, priKey->dQ, procedure.montQ, procedure.optimizer);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    /* result = (mP - mQ) mod p */
    ret = BN_ModSub(result, procedure.mP, procedure.mQ, priKey->p, procedure.optimizer);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    /* result = result * qInv mod p */
    ret = BN_ModMul(result, result, priKey->qInv, priKey->p, procedure.optimizer);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    /* result = result * q */
    ret = BN_Mul(result, result, priKey->q, procedure.optimizer);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    /* result = result + mQ */
    ret = BN_Add(result, result, procedure.mQ);
ERR:
    RsaDecProcedureFree(&procedure);
    return ret;
}

static int32_t RSA_GetSub(
    const BN_BigNum *p, const BN_BigNum *q, BN_BigNum *r1, BN_BigNum *r2)
{
    int32_t ret;

    ret = BN_SubLimb(r1, p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_SubLimb(r2, q, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

static int32_t RSA_GetL(
    BN_BigNum *l, BN_BigNum *u, BN_BigNum *r1, BN_BigNum *r2, BN_Optimizer *opt)
{
    int32_t ret;
    ret = BN_Mul(l, r1, r2, opt);
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
        return ret;
    }
    return ret;
}

static BN_BigNum *RSA_GetPublicExp(const BN_BigNum *d, const BN_BigNum *p,
    const BN_BigNum *q, uint32_t bits, BN_Optimizer *opt)
{
    int32_t ret;
    /* Apply for the temporary space of the BN object */
    BN_BigNum *l = BN_Create(BN_Bits(p) + BN_Bits(q));
    BN_BigNum *r1 = BN_Create(BN_Bits(p));
    BN_BigNum *r2 = BN_Create(BN_Bits(q));
    BN_BigNum *u = BN_Create(bits + 1);
    BN_BigNum *e = BN_Create(bits);

    if (l == NULL || r1 == NULL || r2 == NULL || u == NULL || e == NULL) {
        ret = CRYPT_NULL_INPUT;
        BSL_ERR_PUSH_ERROR(ret);
        goto END;
    }

    ret = RSA_GetSub(p, q, r1, r2);
    // The push error in GetSub can be used to locate the fault. Therefore, it is not added here.
    if (ret != CRYPT_SUCCESS) {
        goto END;
    }

    ret = RSA_GetL(l, u, r1, r2, opt);
    // The push error in GetL can be used to locate the fault. Therefore, it is not added here.
    if (ret != CRYPT_SUCCESS) {
        goto END;
    }

    ret = BN_ModInv(e, d, l, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto END;
    }
END:
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

    ctx->blind = RSA_BlindNewCtx();

    int32_t ret = RSA_BlindCreateParam(ctx->blind, e, ctx->prvKey->n, opt);
    if (needDestoryE) {
        BN_Destroy(e);
    }
    return ret;
}

static int32_t RSA_BlindProcess(CRYPT_RSA_Ctx *ctx, BN_BigNum *message, BN_Optimizer *opt)
{
    int32_t ret;
    if (ctx->blind == NULL) {
        ret = RSA_InitBlind(ctx, opt);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    ret = RSA_BlindCovert(ctx->blind, message, ctx->prvKey->n, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return ret;
}

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
    ret = InputRangeCheck(*message, ctx->prvKey->n);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    return ret;
ERR:
    BN_Destroy(*result);
    BN_Destroy(*message);
    return ret;
}

static int32_t RSA_PrvProcess(
    const CRYPT_RSA_Ctx *ctx, BN_BigNum *message, BN_BigNum *result, BN_Optimizer *opt)
{
    int32_t ret;
    // blinding
    if ((ctx->flags & CRYPT_RSA_BLINDING) != 0) {
        ret = RSA_BlindProcess((CRYPT_RSA_Ctx *)(uintptr_t)ctx, message, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    /* If ctx->prvKey->p is set to 0, the standard mode is used for RSA decryption.
       Otherwise, the CRT mode is used for RSA decryption. */
    if (BN_IsZero(ctx->prvKey->p)) {
        ret = CalcMontExp(ctx->prvKey->n, ctx->prvKey->d, result, message, true);
    } else {
        ret = NormalDecProcedure(ctx, message, result);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // unblinding
    if ((ctx->flags & CRYPT_RSA_BLINDING) != 0) {
        ret = RSA_BlindInvert(ctx->blind, result, ctx->prvKey->n, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
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

    ret = RSA_PrvProcess(ctx, message, result, opt);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }

    ret = ResultToOut(bits, result, out, outLen);
ERR:
    BN_OptimizerDestroy(opt);
    BN_Destroy(result);
    BN_Destroy(message);
    return ret;
}

static uint32_t GetHashLen(const CRYPT_RSA_Ctx *ctx)
{
    if (ctx->pad.type == EMSA_PKCSV15) {
        return CRYPT_MD_GetSizeById(ctx->pad.para.pkcsv15.mdId);
    }

    return (uint32_t)(ctx->pad.para.pss.mdMeth->mdSize);
}

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
    if (GetHashLen(ctx) != inputLen) {
        // Inconsistent length
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_ALGID);
        return CRYPT_RSA_ERR_ALGID;
    }
    return CRYPT_SUCCESS;
}

static int32_t PssPad(CRYPT_RSA_Ctx *ctx, const uint8_t *input, uint32_t inputLen, uint8_t *out, uint32_t outLen)
{
    CRYPT_Data salt = { 0 };
    bool kat = false;
    if (ctx->pad.salt.data != NULL) {
        // If the salt contains data, that is the kat test.
        kat = true;
    }
    if (kat) {
        salt.data = ctx->pad.salt.data;
        salt.len = ctx->pad.salt.len;
        ctx->pad.salt.data = NULL;
        ctx->pad.salt.len = 0;
    } else if (ctx->pad.para.pss.saltLen != 0) {
        // Generate a salt information to the salt.
        int32_t ret = GenPssSalt(&salt, ctx->pad.para.pss.mdMeth, ctx->pad.para.pss.saltLen, outLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_GEN_SALT);
            return CRYPT_RSA_ERR_GEN_SALT;
        }
    }
    int32_t ret = CRYPT_RSA_SetPss(ctx->pad.para.pss.mdMeth, ctx->pad.para.pss.mgfMeth, CRYPT_RSA_GetBits(ctx),
        salt.data, salt.len, input, inputLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    if (!kat && (ctx->pad.para.pss.saltLen != 0)) {
        // The generated salt needs to be released.
        BSL_SAL_CleanseData(salt.data, salt.len);
        BSL_SAL_FREE(salt.data);
    }
    return ret;
}

int32_t CRYPT_RSA_Sign(CRYPT_RSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    int32_t ret = SignInputCheck(ctx, data, dataLen, sign, signLen);
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
    switch (ctx->pad.type) {
        case EMSA_PKCSV15:
            ret = CRYPT_RSA_SetPkcsV15Type1(ctx->pad.para.pkcsv15.mdId, data,
                dataLen, pad, padLen);
            break;
        case EMSA_PSS:
            ret = PssPad(ctx, data, dataLen, pad, padLen);
            break;
        default: // This branch cannot be entered because it's been verified before.
            ret = CRYPT_RSA_PAD_NO_SET_ERROR;
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = CRYPT_RSA_PrvDec(ctx, pad, padLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    (void)memset_s(pad, padLen, 0, padLen);
    BSL_SAL_FREE(pad);
    return ret;
}

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
        // Inconsistent length
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_ALGID);
        return CRYPT_RSA_ERR_ALGID;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_Verify(CRYPT_RSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
    uint8_t *pad = NULL;
    uint32_t saltLen = 0;
    int32_t ret = VerifyInputCheck(ctx, data, dataLen, sign);
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

    ret = CRYPT_RSA_PubEnc(ctx, sign, signLen, pad, &padLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    saltLen = (uint32_t)ctx->pad.para.pss.saltLen;
    switch (ctx->pad.type) {
        case EMSA_PKCSV15:
            ret = CRYPT_RSA_VerifyPkcsV15Type1(ctx->pad.para.pkcsv15.mdId, pad, padLen,
                data, dataLen);
            break;
        case EMSA_PSS:
            if (ctx->pad.para.pss.saltLen == SALTLEN_PSS_HASHLEN_TYPE) { // saltLen is -1
                saltLen = (uint32_t)ctx->pad.para.pss.mdMeth->mdSize;
            } else if (ctx->pad.para.pss.saltLen == SALTLEN_PSS_MAXLEN_TYPE) { // saltLen is -2
                saltLen = (uint32_t)(padLen - ctx->pad.para.pss.mdMeth->mdSize - 2); // salt, obtains DRBG
            }
            ret = CRYPT_RSA_VerifyPss(ctx->pad.para.pss.mdMeth, ctx->pad.para.pss.mgfMeth,
                bits, saltLen, data, dataLen, pad, padLen);
            break;
        default: // This branch cannot be entered because it's been verified before.
            ret = CRYPT_RSA_PAD_NO_SET_ERROR;
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
    }
ERR:
    (void)memset_s(pad, padLen, 0, padLen);
    BSL_SAL_FREE(pad);
    return ret;
}

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
        case RSAES_PKCSV15:
            ret = CRYPT_RSA_SetPkcsV15Type2(data, dataLen, pad, padLen);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                goto ERR;
            }
            break;
        case RSAES_OAEP:
            ret = CRYPT_RSA_SetPkcs1Oaep(ctx->pad.para.oaep.mdMeth,
                ctx->pad.para.oaep.mgfMeth, data, dataLen, ctx->label.data, ctx->label.len, pad, padLen);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                goto ERR;
            }
            break;
        case RSA_NO_PAD:
            if (dataLen != padLen) {
                ret = CRYPT_RSA_ERR_ENC_INPUT_NOT_ENOUGH;
                BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_ENC_INPUT_NOT_ENOUGH);
                goto ERR;
            }
            (void)memcpy_s(pad, padLen, data, dataLen);
            break;
        default:
            ret = CRYPT_RSA_PAD_NO_SET_ERROR;
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
    }

    ret = CRYPT_RSA_PubEnc(ctx, pad, padLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    (void)memset_s(pad, padLen, 0, padLen);
    BSL_SAL_FREE(pad);
    return ret;
}

static int32_t DecryptInputCheck(const CRYPT_RSA_Ctx *ctx, const uint8_t *data, const uint32_t dataLen,
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

int32_t CRYPT_RSA_Decrypt(CRYPT_RSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen)
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
        goto ERR;
    }

    switch (ctx->pad.type) {
        case RSAES_OAEP:
            ret = CRYPT_RSA_VerifyPkcs1Oaep(ctx->pad.para.oaep.mdMeth,
                ctx->pad.para.oaep.mgfMeth, pad, padLen, ctx->label.data, ctx->label.len, out, outLen);
            break;
        case RSAES_PKCSV15:
            ret = CRYPT_RSA_VerifyPkcsV15Type2(pad, padLen, out, outLen);
            break;
        case RSA_NO_PAD:
            if (memcpy_s(out, *outLen, pad, padLen) != EOK) {
                ret = CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
                BSL_ERR_PUSH_ERROR(CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
                goto ERR;
            }
            *outLen = padLen;
            break;
        default:
            ret = CRYPT_RSA_PAD_NO_SET_ERROR;
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
    }
ERR:
    BSL_SAL_CleanseData(pad, padLen);
    BSL_SAL_FREE(pad);
    return ret;
}

static int32_t SetEmsaPkcsV15(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(CRYPT_RSA_PkcsV15Para)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_SET_EMS_PKCSV15_LEN_ERROR);
        return CRYPT_RSA_SET_EMS_PKCSV15_LEN_ERROR;
    }
    static const uint32_t SIGN_MD_ID_LIST[] = { CRYPT_MD_SHA224, CRYPT_MD_SHA256,
        CRYPT_MD_SHA384, CRYPT_MD_SHA512, CRYPT_MD_SM3, CRYPT_MD_SHA1, CRYPT_MD_MD5
    };

    CRYPT_RSA_PkcsV15Para *pad = val;
    if (ParamIdIsValid(pad->mdId, SIGN_MD_ID_LIST, sizeof(SIGN_MD_ID_LIST) / sizeof(SIGN_MD_ID_LIST[0])) == false) {
        // This hash algorithm is not supported.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_MD_ALGID);
        return CRYPT_RSA_ERR_MD_ALGID;
    }
    (void)memset_s(&(ctx->pad), sizeof(RSAPad), 0, sizeof(RSAPad));
    (void)memcpy_s(&(ctx->pad.para.pkcsv15), sizeof(CRYPT_RSA_PkcsV15Para), val, sizeof(CRYPT_RSA_PkcsV15Para));
    ctx->pad.type = EMSA_PKCSV15;
    ctx->pad.para.pkcsv15.mdId = pad->mdId;
    return CRYPT_SUCCESS;
}

static int32_t SetEmsaPss(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(RSA_PadingPara)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_SET_EMS_PSS_LEN_ERROR);
        return CRYPT_RSA_SET_EMS_PSS_LEN_ERROR;
    }

    RSA_PadingPara *pad = val;
    if (pad->mdMeth == NULL || pad->mgfMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    if (bits == 0) {
        // The valid key information does not exist.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    if (pad->saltLen < SALTLEN_PSS_AUTOLEN_TYPE) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_SALT_LEN);
        return  CRYPT_RSA_ERR_SALT_LEN;
    }
    uint32_t saltLen = (uint32_t)pad->saltLen;
    if (pad->saltLen == SALTLEN_PSS_HASHLEN_TYPE) {
        saltLen = pad->mdMeth->mdSize;
    }
    uint32_t bytes = BN_BITS_TO_BYTES(bits);
    // The minimum specification supported by RSA is 1K,
    // and the maximum hash length supported by the hash algorithm is 64 bytes.
    // Therefore, specifying the salt length as the maximum available length is satisfied.
    if (pad->saltLen != SALTLEN_PSS_MAXLEN_TYPE && pad->saltLen != SALTLEN_PSS_AUTOLEN_TYPE &&
        saltLen > bytes - pad->mdMeth->mdSize - 2) { // maximum length of the salt is padLen-mdMethod->GetDigestSize-2
        // The configured salt length does not meet the specification.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_PSS_SALT_LEN);
        return CRYPT_RSA_ERR_PSS_SALT_LEN;
    }
    (void)memset_s(&(ctx->pad), sizeof(RSAPad), 0, sizeof(RSAPad));
    (void)memcpy_s(&(ctx->pad.para.pss), sizeof(RSA_PadingPara), val, sizeof(RSA_PadingPara));
    ctx->pad.type = EMSA_PSS;
    ctx->pad.para.pss.mdId = pad->mdId;
    ctx->pad.para.pss.mgfId = pad->mgfId;
    return CRYPT_SUCCESS;
}

static int32_t SetOaep(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(RSA_PadingPara)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_SET_RSAES_OAEP_LEN_ERROR);
        return CRYPT_RSA_SET_RSAES_OAEP_LEN_ERROR;
    }

    (void)memset_s(&(ctx->pad), sizeof(RSAPad), 0, sizeof(RSAPad));
    (void)memcpy_s(&(ctx->pad.para.oaep), sizeof(RSA_PadingPara), val, sizeof(RSA_PadingPara));
    ctx->pad.type = RSAES_OAEP;
    return CRYPT_SUCCESS;
}

static int32_t SetOaepLabel(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    uint8_t *data = NULL;
    // val can be NULL
    if ((val == NULL && len != 0) || (len == 0 && val != NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len == 0 && val == NULL) {
        BSL_SAL_FREE(ctx->label.data);
        ctx->label.data = NULL;
        ctx->label.len = 0;
        return CRYPT_SUCCESS;
    }
    data = (uint8_t *)BSL_SAL_Malloc(len);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BSL_SAL_FREE(ctx->label.data);
    ctx->label.data = data;
    ctx->label.len = len;
    (void)memcpy_s(ctx->label.data, ctx->label.len, val, len);
    return CRYPT_SUCCESS;
}
static int32_t SetRsaesPkcsV15(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(CRYPT_RSA_PkcsV15Para)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_SET_EMS_PKCSV15_LEN_ERROR);
        return CRYPT_RSA_SET_EMS_PKCSV15_LEN_ERROR;
    }

    (void)memset_s(&(ctx->pad), sizeof(RSAPad), 0, sizeof(RSAPad));
    (void)memcpy_s(&(ctx->pad.para.pkcsv15), sizeof(CRYPT_RSA_PkcsV15Para), val, sizeof(CRYPT_RSA_PkcsV15Para));
    ctx->pad.type = RSAES_PKCSV15;
    return CRYPT_SUCCESS;
}
static int32_t SetSalt(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    if (ctx->pad.type != EMSA_PSS) {
        // In non-PSS mode, salt information cannot be set.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_SET_SALT_NOT_PSS_ERROR);
        return CRYPT_RSA_SET_SALT_NOT_PSS_ERROR;
    }
    RSA_PadingPara *pad = &(ctx->pad.para.pss);
    uint32_t bytes = BN_BITS_TO_BYTES(CRYPT_RSA_GetBits(ctx));
    // The maximum salt length is padLen - mdMethod->GetDigestSize - 2
    if (len > bytes - pad->mdMeth->mdSize - 2) {
        // The configured salt length does not meet the specification.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_SALT_LEN);
        return CRYPT_RSA_ERR_SALT_LEN;
    }
    ctx->pad.salt.data = val;
    ctx->pad.salt.len = len;
    return CRYPT_SUCCESS;
}

static int32_t GetSaltLen(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    (void)len;
    int32_t *valTmp = val;
    if (valTmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pad.type != EMSA_PSS) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_ALGID);
        return CRYPT_RSA_ERR_ALGID;
    }
    *valTmp = ctx->pad.para.pss.saltLen;
    return CRYPT_SUCCESS;
}

static int32_t GetPadding(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    RSA_PadType *valTmp = val;
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_SET_FLAG_LEN_ERROR);
        return CRYPT_RSA_SET_FLAG_LEN_ERROR;
    }
    *valTmp = ctx->pad.type;
    return CRYPT_SUCCESS;
}

static int32_t GetMd(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    (void)len;
    CRYPT_MD_AlgId *valTmp = val;
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->pad.type == EMSA_PKCSV15) {
        *valTmp = ctx->pad.para.pkcsv15.mdId;
        return CRYPT_SUCCESS;
    }
    *valTmp = ctx->pad.para.pss.mdId;

    return CRYPT_SUCCESS;
}

static int32_t GetMgf(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    (void)len;
    CRYPT_MD_AlgId *valTmp = val;
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pad.type == EMSA_PKCSV15) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_ALGID);
        return CRYPT_RSA_ERR_ALGID;
    }
    *valTmp = ctx->pad.para.pss.mgfId;
    return CRYPT_SUCCESS;
}

static int32_t SetFlag(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL || ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t flag = *(const uint32_t *)val;
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_SET_FLAG_LEN_ERROR);
        return CRYPT_RSA_SET_FLAG_LEN_ERROR;
    }
    if (flag == 0 || flag >= CRYPT_RSA_MAXFLAG) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_FLAG_NOT_SUPPORT_ERROR);
        return CRYPT_RSA_FLAG_NOT_SUPPORT_ERROR;
    }
    ctx->flags |= flag;
    return CRYPT_SUCCESS;
}

static int32_t ClearFlag(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL || ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_SET_FLAG_LEN_ERROR);
        return CRYPT_RSA_SET_FLAG_LEN_ERROR;
    }
    uint32_t flag = *(const uint32_t *)val;

    if (flag == 0 || flag >= CRYPT_RSA_MAXFLAG) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_FLAG_NOT_SUPPORT_ERROR);
        return CRYPT_RSA_FLAG_NOT_SUPPORT_ERROR;
    }
    ctx->flags &= ~flag;
    return CRYPT_SUCCESS;
}

static int32_t RsaUpReferences(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    if (val != NULL && len == (uint32_t)sizeof(int)) {
        return BSL_SAL_AtomicUpReferences(&(ctx->references), (int *)val);
    }
    BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
    return CRYPT_NULL_INPUT;
}

static int32_t SetRsaPad(CRYPT_RSA_Ctx *ctx, const void *val, const uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_SET_FLAG_LEN_ERROR);
        return CRYPT_RSA_SET_FLAG_LEN_ERROR;
    }

    int32_t pad = *(int32_t *)val;
    if (pad < EMSA_PKCSV15 || pad > RSA_NO_PAD) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    ctx->pad.type = pad;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_Ctrl(CRYPT_RSA_Ctx *ctx, CRYPT_PkeyCtrl opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_SET_RSA_EMSA_PKCSV15:
            return SetEmsaPkcsV15(ctx, val, len);
        case CRYPT_CTRL_SET_RSA_EMSA_PSS:
            return SetEmsaPss(ctx, val, len);
        case CRYPT_CTRL_SET_RSA_SALT:
            return SetSalt(ctx, val, len);
        case CRYPT_CTRL_GET_RSA_SALT:
            return GetSaltLen(ctx, val, len);
        case CRYPT_CTRL_GET_RSA_PADDING:
            return GetPadding(ctx, val, len);
        case CRYPT_CTRL_GET_RSA_MD:
            return GetMd(ctx, val, len);
        case CRYPT_CTRL_GET_RSA_MGF:
            return GetMgf(ctx, val, len);

        case CRYPT_CTRL_SET_RSA_RSAES_OAEP:
            return SetOaep(ctx, val, len);
        case CRYPT_CTRL_SET_RSA_OAEP_LABEL:
            return SetOaepLabel(ctx, val, len);
        case CRYPT_CTRL_SET_RSA_RSAES_PKCSV15:
            return SetRsaesPkcsV15(ctx, val, len);
        case CRYPT_CTRL_SET_RSA_FLAG:
            return SetFlag(ctx, val, len);
        case CRYPT_CTRL_CLR_RSA_FLAG:
            return ClearFlag(ctx, val, len);
        case CRYPT_CTRL_SET_RSA_PADDING:
            return SetRsaPad(ctx, val, len);
        case CRYPT_CTRL_UP_REFERENCES:
            return RsaUpReferences(ctx, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_RSA_CTRL_NOT_SUPPORT_ERROR);
            return CRYPT_RSA_CTRL_NOT_SUPPORT_ERROR;
    }
}
#endif // HITLS_CRYPTO_RSA
